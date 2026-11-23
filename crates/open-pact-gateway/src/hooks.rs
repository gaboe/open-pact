//! Test pause points. A normal build has none: `hit` returns at once.

#[cfg(test)]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
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
    armed: AtomicBool,
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
        self.armed.store(false, Ordering::SeqCst);
        self.release.notify_one();
    }
}

#[cfg(test)]
impl Hooks {
    pub fn arm(&self, name: &'static str) -> Arc<Point> {
        let point = self
            .points
            .lock()
            .expect("hooks")
            .entry(name)
            .or_default()
            .clone();
        point.armed.store(true, Ordering::SeqCst);
        point
    }

    pub async fn hit(&self, name: &'static str) {
        let point = self.points.lock().expect("hooks").get(name).cloned();
        if let Some(point) = point
            && point.armed.load(Ordering::SeqCst)
        {
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
