//! Test pause points. A normal build has none: `hit` returns at once.

#[cfg(test)]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};

pub struct Hooks {
    #[cfg(test)]
    points: Mutex<std::collections::HashMap<&'static str, Arc<Point>>>,
    #[cfg(test)]
    counts: Mutex<std::collections::HashMap<&'static str, usize>>,
    #[cfg(test)]
    blocks: Mutex<std::collections::HashMap<&'static str, Arc<BlockPoint>>>,
    /// Database steps of a claim fail once this many stored-line reads happened (usize::MAX: never).
    #[cfg(test)]
    fault_after_reads: AtomicUsize,
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

/// A pause for code that runs on a blocking thread: it waits on a std channel, never on an await,
/// and never longer than `HOLD_LIMIT`, so a test that fails cannot hang the process.
#[cfg(test)]
pub struct BlockPoint {
    armed: AtomicU8,
    hits: AtomicUsize,
    holding: AtomicBool,
    reached: tokio::sync::Notify,
    release_tx: std::sync::mpsc::Sender<()>,
    release_rx: Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
pub const HOLD_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
impl BlockPoint {
    pub async fn reached(&self) {
        self.reached.notified().await;
    }

    pub fn release(&self) {
        let _ = self.release_tx.send(());
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// True while a thread waits at this point.
    pub fn holding(&self) -> bool {
        self.holding.load(Ordering::SeqCst)
    }
}

impl Default for Hooks {
    fn default() -> Self {
        Hooks {
            #[cfg(test)]
            points: Mutex::default(),
            #[cfg(test)]
            counts: Mutex::default(),
            #[cfg(test)]
            blocks: Mutex::default(),
            #[cfg(test)]
            fault_after_reads: AtomicUsize::new(usize::MAX),
        }
    }
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

    /// The next thread that reaches `name` through `block` waits for `release`.
    pub fn arm_block(&self, name: &'static str) -> Arc<BlockPoint> {
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let point = Arc::new(BlockPoint {
            armed: AtomicU8::new(1),
            hits: AtomicUsize::new(0),
            holding: AtomicBool::new(false),
            reached: tokio::sync::Notify::new(),
            release_tx,
            release_rx: Mutex::new(release_rx),
        });
        self.blocks
            .lock()
            .expect("hooks")
            .insert(name, point.clone());
        point
    }

    /// A std blocking pause for a blocking-pool thread; not an await.
    pub fn block(&self, name: &'static str) {
        let point = self.blocks.lock().expect("hooks").get(name).cloned();
        let Some(point) = point else { return };
        if point
            .armed
            .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        point.hits.fetch_add(1, Ordering::SeqCst);
        point.holding.store(true, Ordering::SeqCst);
        point.reached.notify_one();
        let _ = point
            .release_rx
            .lock()
            .expect("hooks")
            .recv_timeout(HOLD_LIMIT);
        point.holding.store(false, Ordering::SeqCst);
    }

    /// Counts a pass through `name` from a path that cannot await.
    pub fn bump(&self, name: &'static str) {
        *self.counts.lock().expect("hooks").entry(name).or_default() += 1;
    }

    /// How often a path reached `name`, armed or not.
    pub fn count(&self, name: &'static str) -> usize {
        self.counts
            .lock()
            .expect("hooks")
            .get(name)
            .copied()
            .unwrap_or(0)
    }

    /// From now on every claim database step fails once `reads` more stored-line reads ran.
    pub fn fail_after_reads(&self, reads: usize) {
        self.fault_after_reads
            .store(self.count("stored_lines_read") + reads, Ordering::SeqCst);
    }

    pub fn clear_fault(&self) {
        self.fault_after_reads.store(usize::MAX, Ordering::SeqCst);
    }

    /// True when a database step that follows the latest stored-line read must fail.
    pub fn fault_after_read(&self) -> bool {
        self.count("stored_lines_read") >= self.fault_after_reads.load(Ordering::SeqCst)
    }

    /// True when the stored-line read that just counted itself must fail.
    pub fn fault_in_read(&self) -> bool {
        self.count("stored_lines_read") > self.fault_after_reads.load(Ordering::SeqCst)
    }

    pub async fn hit(&self, name: &'static str) {
        *self.counts.lock().expect("hooks").entry(name).or_default() += 1;
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
    pub fn block(&self, _name: &'static str) {}

    #[inline]
    pub fn bump(&self, _name: &'static str) {}

    #[inline]
    pub async fn hit(&self, _name: &'static str) {}
}
