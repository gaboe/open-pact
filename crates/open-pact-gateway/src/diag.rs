//! The diagnostic lines of the request paths. A request never writes to stderr itself: a log
//! collector that stops draining its pipe would hold the request past its deadline and lose its
//! 503. A request queues the line with `try_send` and drops it when 256 lines already wait; one
//! thread writes the queue.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

use crate::metrics::Observation;

/// How many lines wait for the writer.
const CAPACITY: usize = 256;

type Sink = Arc<dyn Fn(&str) + Send + Sync>;

pub struct Diag {
    lines: SyncSender<String>,
    dropped: AtomicU64,
    observe: Option<Arc<Observation>>,
    /// Where the writer puts a line. Stderr, unless a test holds it.
    #[cfg(test)]
    sink: Arc<Mutex<Sink>>,
}

impl Diag {
    pub fn start(observe: Option<Arc<Observation>>) -> Diag {
        let (lines, queue) = sync_channel::<String>(CAPACITY);
        let stderr: Sink = Arc::new(|line| eprintln!("{line}"));
        let sink = Arc::new(Mutex::new(stderr));
        let writer = sink.clone();
        let spawned = std::thread::Builder::new()
            .name("diag-log".into())
            .spawn(move || {
                for line in queue {
                    let put = writer.lock().expect("diagnostic sink").clone();
                    put(&line);
                }
            });
        if let Err(error) = spawned {
            eprintln!("the diagnostic log thread did not start: {error}");
        }
        Diag {
            lines,
            dropped: AtomicU64::new(0),
            observe,
            #[cfg(test)]
            sink,
        }
    }

    /// Queues `line` and never waits. A full queue drops the line and counts it.
    pub fn line(&self, line: String) {
        match self.lines.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                if let Some(metrics) = self.observe.as_ref().and_then(|o| o.metrics()) {
                    metrics.log_line_dropped();
                }
            }
        }
    }

    #[cfg(test)]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Test only: the writer puts every later line through `sink`.
    #[cfg(test)]
    pub fn set_sink(&self, sink: impl Fn(&str) + Send + Sync + 'static) {
        *self.sink.lock().expect("diagnostic sink") = Arc::new(sink);
    }
}
