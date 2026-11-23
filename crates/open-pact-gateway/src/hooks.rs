//! Test pause points. A normal build has none: `hit` returns at once.

#[cfg(test)]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};

#[derive(Default)]
pub struct Hooks {
    #[cfg(test)]
    points: Mutex<std::collections::HashMap<&'static str, Arc<Point>>>,
}

/// One named pause. While armed, a code path that reaches it signals `reached` and waits for
/// `release`. Both signals keep one permit, so the test may release before the path arrives.
#[cfg(test)]
#[derive(Default)]
pub struct Point {
    /// 0 off, 1 pause the next hit only, 2 pause every hit.
    armed: AtomicU8,
    hits: AtomicUsize,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
impl Point {
    pub async fn reached(&self) {
        self.reached.notified().await;
    }

    pub fn release(&self) {
        self.release.notify_one();
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn disarm(&self) {
        self.armed.store(0, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

#[cfg(test)]
impl Hooks {
    /// Pauses the next path that reaches `name`; later ones pass.
    pub fn arm(&self, name: &'static str) -> Arc<Point> {
        self.set(name, 1)
    }

    /// Pauses every path that reaches `name` until `disarm`.
    pub fn arm_always(&self, name: &'static str) -> Arc<Point> {
        self.set(name, 2)
    }

    fn set(&self, name: &'static str, mode: u8) -> Arc<Point> {
        let point = self
            .points
            .lock()
            .expect("hooks")
            .entry(name)
            .or_default()
            .clone();
        point.armed.store(mode, Ordering::SeqCst);
        point
    }

    pub async fn hit(&self, name: &'static str) {
        let point = self.points.lock().expect("hooks").get(name).cloned();
        if let Some(point) = point {
            let mode = point.armed.load(Ordering::SeqCst);
            if mode == 0
                || (mode == 1
                    && point
                        .armed
                        .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
                        .is_err())
            {
                return;
            }
            point.hits.fetch_add(1, Ordering::SeqCst);
            point.reached.notify_one();
            point.release.notified().await;
        }
    }
}

#[cfg(not(test))]
impl Hooks {
    #[inline]
    pub async fn hit(&self, _name: &'static str) {}
}
