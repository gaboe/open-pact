//! The diagnostic lines of the request paths. A request never writes to stderr itself: a log
//! collector that stops draining its pipe would hold the request past its deadline and lose its
//! 503. A request queues the line with `try_send` and drops it when 256 lines already wait; one
//! thread writes the queue. The queue is process wide, so the error helper, the slow-request log
//! and the witness owners all share it.

use std::io::Write;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use prometheus_client::metrics::counter::Counter;

/// How many lines wait for the writer.
const CAPACITY: usize = 256;

/// How long a graceful shutdown waits for the writer to drain its queue.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(2);

type Sink = Arc<dyn Fn(&str) + Send + Sync>;

struct Diag {
    /// None once `shutdown` closed the queue.
    lines: Mutex<Option<SyncSender<String>>>,
    /// Signals when the writer thread has written its last line.
    done: Mutex<Option<Receiver<()>>>,
    dropped: Counter,
    /// Where the writer puts a line. Stderr, unless a test holds it.
    #[cfg(test)]
    sink: Arc<Mutex<Sink>>,
}

fn stderr() -> Sink {
    // A closed stderr must not stop the writer: ignore the error instead of panicking.
    Arc::new(|line| {
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    })
}

impl Diag {
    fn start(sink: Sink) -> Diag {
        let (lines, queue) = sync_channel::<String>(CAPACITY);
        let (finished, done) = std::sync::mpsc::channel::<()>();
        let sink = Arc::new(Mutex::new(sink));
        let writer = sink.clone();
        let spawned = std::thread::Builder::new()
            .name("diag-log".into())
            .spawn(move || {
                for line in queue {
                    let put = writer.lock().expect("diagnostic sink").clone();
                    put(&line);
                }
                let _ = finished.send(());
            });
        if let Err(error) = spawned {
            let _ = writeln!(
                std::io::stderr(),
                "the diagnostic log thread did not start: {error}"
            );
        }
        Diag {
            lines: Mutex::new(Some(lines)),
            done: Mutex::new(Some(done)),
            dropped: Counter::default(),
            #[cfg(test)]
            sink,
        }
    }

    /// Queues `line` and never waits. A full or closed queue drops the line and counts it.
    fn line(&self, line: String) {
        let queued = match self.lines.lock().expect("diagnostic queue").as_ref() {
            Some(lines) => lines.try_send(line).is_ok(),
            None => false,
        };
        if !queued {
            self.dropped.inc();
        }
    }

    /// Closes the queue and waits up to `cap` for the writer to write what is queued. Returns
    /// whether it did. A writer stuck on a blocked stderr never holds the process past `cap`.
    fn shutdown(&self, cap: Duration) -> bool {
        drop(self.lines.lock().expect("diagnostic queue").take());
        let done = self.done.lock().expect("diagnostic writer").take();
        done.is_some_and(|done| done.recv_timeout(cap).is_ok())
    }
}

static PROCESS: LazyLock<Diag> = LazyLock::new(|| Diag::start(stderr()));

/// Queues a diagnostic line from a request path. It never waits and never writes stderr.
pub fn line(line: String) {
    PROCESS.line(line);
}

/// The lines dropped because the queue was full; the metrics registry exposes it.
pub fn dropped() -> Counter {
    PROCESS.dropped.clone()
}

/// Writes the queued lines before the process exits, for at most `cap`.
pub fn shutdown(cap: Duration) -> bool {
    PROCESS.shutdown(cap)
}

/// Test only: one test at a time holds the process writer; the guard puts stderr back.
#[cfg(test)]
pub struct Held {
    _only: tokio::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
static HOLDERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Test only: the process writer puts every later line through `sink` until the guard drops. A
/// sink that blocks must unblock when its test ends, or the writer stays stuck for the next test.
#[cfg(test)]
pub async fn hold(sink: impl Fn(&str) + Send + Sync + 'static) -> Held {
    let only = HOLDERS.lock().await;
    *PROCESS.sink.lock().expect("diagnostic sink") = Arc::new(sink);
    Held { _only: only }
}

#[cfg(test)]
impl Drop for Held {
    fn drop(&mut self) {
        *PROCESS.sink.lock().expect("diagnostic sink") = stderr();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn collecting(pause: Duration) -> (Diag, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let put = seen.clone();
        let diag = Diag::start(Arc::new(move |line| {
            std::thread::sleep(pause);
            put.lock().unwrap().push(line.to_string());
        }));
        (diag, seen)
    }

    #[test]
    fn a_graceful_shutdown_writes_every_queued_line_first() {
        let (diag, seen) = collecting(Duration::from_millis(5));
        for n in 0..50 {
            diag.line(format!("line {n}"));
        }
        assert!(diag.shutdown(Duration::from_secs(2)));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 50, "lines were lost at shutdown");
        assert_eq!(seen[49], "line 49");
        assert_eq!(diag.dropped.get(), 0);
    }

    #[test]
    fn a_blocked_writer_never_holds_the_shutdown_past_its_cap() {
        let (release, held) = std::sync::mpsc::channel::<()>();
        let held = Mutex::new(held);
        let diag = Diag::start(Arc::new(move |_| {
            let _ = held.lock().unwrap().recv_timeout(Duration::from_secs(10));
        }));
        diag.line("held".into());
        diag.line("queued".into());
        let started = std::time::Instant::now();
        assert!(!diag.shutdown(Duration::from_millis(200)));
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(2),
            "shutdown waited {waited:?}"
        );
        drop(release);
    }

    #[test]
    fn a_line_after_shutdown_is_counted_as_dropped() {
        let (diag, seen) = collecting(Duration::ZERO);
        assert!(diag.shutdown(Duration::from_secs(2)));
        diag.line("late".into());
        assert_eq!(diag.dropped.get(), 1);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn a_full_queue_drops_and_counts_without_waiting() {
        let (release, held) = std::sync::mpsc::channel::<()>();
        let held = Mutex::new(held);
        let written = Arc::new(AtomicUsize::new(0));
        let count = written.clone();
        let diag = Diag::start(Arc::new(move |_| {
            let _ = held.lock().unwrap().recv_timeout(Duration::from_secs(10));
            count.fetch_add(1, Ordering::SeqCst);
        }));
        let started = std::time::Instant::now();
        for n in 0..1000 {
            diag.line(format!("line {n}"));
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        // One line sits in the held writer, 256 wait in the queue; the rest are dropped.
        assert!(diag.dropped.get() >= 1000 - 1 - CAPACITY as u64);
        assert!(diag.dropped.get() < 1000);
        drop(release);
    }
}
