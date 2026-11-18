use time::{Duration, OffsetDateTime};

use crate::{Place, Schedule, Span, timestamp};

/// How long a VPN certificate lives: the shortest of
///
/// - twice the send interval of the VPN, or of the flat 0.7 form (a device that misses one send
///   still holds a valid certificate, and one that misses two does not),
/// - the manifest's `claim_max_age`,
/// - 24 hours,
/// - the time until the nearest grace deadline of a failing control, so that a certificate never
///   outlives the moment the gateway would deny the device.
///
/// Without a schedule only the second and third bound apply. A deadline that has passed gives a
/// lease of zero, never a negative one.
pub fn vpn_lease(
    schedule: Option<&Schedule>,
    claim_max_age: &Span,
    nearest_grace_deadline: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Duration {
    let mut lease = Duration::hours(24);
    if let Some(max_age) = claim_max_age.min_duration() {
        lease = lease.min(max_age);
    }
    let sends_every = schedule
        .and_then(|schedule| schedule.period(Place::Vpn))
        .and_then(|interval| timestamp::seconds(interval.as_secs()));
    if let Some(every) = sends_every {
        lease = lease.min(every * 2);
    }
    if let Some(deadline) = nearest_grace_deadline {
        lease = lease.min(deadline - now);
    }
    lease.max(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(table: &str) -> Schedule {
        toml::from_str(table).unwrap()
    }

    fn span(text: &str) -> Span {
        Span::try_from(text.to_string()).unwrap()
    }

    fn now() -> OffsetDateTime {
        timestamp::parse_rfc3339("2026-11-17T09:00:00Z").unwrap()
    }

    const VPN_1H: &str = "[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"1h\"\n";

    #[test]
    fn without_a_schedule_the_lease_is_claim_max_age_up_to_a_day() {
        assert_eq!(
            vpn_lease(None, &span("4h"), None, now()),
            Duration::hours(4)
        );
        assert_eq!(
            vpn_lease(None, &span("24h"), None, now()),
            Duration::hours(24)
        );
        assert_eq!(
            vpn_lease(None, &span("3d"), None, now()),
            Duration::hours(24)
        );
        assert_eq!(
            vpn_lease(None, &span("1mo"), None, now()),
            Duration::hours(24)
        );
    }

    #[test]
    fn the_lease_is_twice_the_vpn_send_interval() {
        let vpn = schedule(VPN_1H);
        assert_eq!(
            vpn_lease(Some(&vpn), &span("24h"), None, now()),
            Duration::hours(2)
        );
        let five_minutes = schedule("[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"5m\"\n");
        assert_eq!(
            vpn_lease(Some(&five_minutes), &span("24h"), None, now()),
            Duration::minutes(10)
        );
    }

    #[test]
    fn the_flat_form_uses_its_interval_for_either_mode() {
        let vpn = schedule("mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"55m\"");
        let always = schedule("mode = \"always\"\ninterval = \"90m\"");
        assert_eq!(
            vpn_lease(Some(&vpn), &span("24h"), None, now()),
            Duration::minutes(110)
        );
        assert_eq!(
            vpn_lease(Some(&always), &span("24h"), None, now()),
            Duration::hours(3)
        );
    }

    #[test]
    fn a_schedule_for_any_network_alone_bounds_the_lease_by_its_interval() {
        let always = schedule("[always]\ninterval = \"2h\"\n");
        assert_eq!(
            vpn_lease(Some(&always), &span("24h"), None, now()),
            Duration::hours(4)
        );
    }

    #[test]
    fn the_shorter_interval_of_two_parts_bounds_the_lease_on_the_vpn() {
        let both = schedule(&format!("{VPN_1H}[always]\ninterval = \"30m\"\n"));
        assert_eq!(
            vpn_lease(Some(&both), &span("24h"), None, now()),
            Duration::hours(1)
        );
        let long_vpn = schedule(
            "[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"24h\"\n[always]\ninterval = \"1h\"\n",
        );
        assert_eq!(
            vpn_lease(Some(&long_vpn), &span("24h"), None, now()),
            Duration::hours(2)
        );
    }

    #[test]
    fn a_long_interval_never_lifts_the_lease_above_a_day() {
        let daily = schedule("[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"24h\"\n");
        assert_eq!(
            vpn_lease(Some(&daily), &span("7d"), None, now()),
            Duration::hours(24)
        );
    }

    #[test]
    fn claim_max_age_bounds_the_lease_under_a_schedule() {
        let vpn = schedule(VPN_1H);
        assert_eq!(
            vpn_lease(Some(&vpn), &span("1h"), None, now()),
            Duration::hours(1)
        );
    }

    #[test]
    fn the_nearest_grace_deadline_bounds_the_lease() {
        let vpn = schedule(VPN_1H);
        let deadline = now() + Duration::minutes(25);
        assert_eq!(
            vpn_lease(Some(&vpn), &span("24h"), Some(deadline), now()),
            Duration::minutes(25)
        );
        assert_eq!(
            vpn_lease(None, &span("24h"), Some(deadline), now()),
            Duration::minutes(25)
        );
    }

    #[test]
    fn a_distant_grace_deadline_changes_nothing() {
        let vpn = schedule(VPN_1H);
        let deadline = now() + Duration::days(14);
        assert_eq!(
            vpn_lease(Some(&vpn), &span("24h"), Some(deadline), now()),
            Duration::hours(2)
        );
    }

    #[test]
    fn a_deadline_that_has_passed_gives_no_lease() {
        let deadline = now() - Duration::minutes(1);
        assert_eq!(
            vpn_lease(None, &span("24h"), Some(deadline), now()),
            Duration::ZERO
        );
        assert_eq!(
            vpn_lease(None, &span("24h"), Some(now()), now()),
            Duration::ZERO
        );
    }
}
