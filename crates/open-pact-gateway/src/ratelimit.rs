use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Counts events per source address in fixed windows: failed enrolments, issued nonces. IPv6
/// counts per /64, because one host usually holds the whole /64. Behind an ingress every request
/// has the ingress address, so the limit then applies to all clients together.
pub struct Limiter {
    max_events: u32,
    window: Duration,
    capacity: usize,
    seen: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6([s[0], s[1], s[2], s[3], 0, 0, 0, 0].into())
            }
        },
    }
}

impl Limiter {
    pub fn new(max_events: u32, window: Duration, capacity: usize) -> Self {
        Self {
            max_events,
            window,
            capacity,
            seen: Mutex::new(HashMap::new()),
        }
    }

    pub fn blocked(&self, ip: IpAddr, now: Instant) -> bool {
        let mut seen = self.seen.lock().expect("limiter lock");
        match seen.get(&bucket(ip)) {
            Some((start, count)) if now.duration_since(*start) < self.window => {
                *count >= self.max_events
            }
            _ => {
                if seen.len() >= self.capacity {
                    seen.retain(|_, (start, _)| now.duration_since(*start) < self.window);
                }
                // Fails closed: while too many addresses are counted at once, new addresses wait.
                seen.len() >= self.capacity
            }
        }
    }

    pub fn record(&self, ip: IpAddr, now: Instant) {
        let mut seen = self.seen.lock().expect("limiter lock");
        let entry = seen.entry(bucket(ip)).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn blocks_after_max_events_until_the_window_ends() {
        let l = Limiter::new(3, MIN, 100);
        let (ip, t0) = ("192.0.2.1".parse().unwrap(), Instant::now());
        for _ in 0..3 {
            assert!(!l.blocked(ip, t0));
            l.record(ip, t0);
        }
        assert!(l.blocked(ip, t0 + Duration::from_secs(59)));
        assert!(!l.blocked("192.0.2.2".parse().unwrap(), t0));
        assert!(!l.blocked(ip, t0 + MIN));
    }

    #[test]
    fn ipv6_addresses_in_one_64_share_a_count() {
        let l = Limiter::new(1, MIN, 100);
        let t0 = Instant::now();
        l.record("2001:db8:1:2::1".parse().unwrap(), t0);
        assert!(l.blocked("2001:db8:1:2:ffff::9".parse().unwrap(), t0));
        assert!(!l.blocked("2001:db8:1:3::1".parse().unwrap(), t0));
    }

    #[test]
    fn a_full_table_drops_expired_entries_and_otherwise_fails_closed() {
        let l = Limiter::new(5, MIN, 2);
        let t0 = Instant::now();
        l.record("192.0.2.1".parse().unwrap(), t0);
        l.record("192.0.2.2".parse().unwrap(), t0);
        assert!(l.blocked("192.0.2.3".parse().unwrap(), t0));
        assert!(!l.blocked("192.0.2.3".parse().unwrap(), t0 + MIN));
    }
}
