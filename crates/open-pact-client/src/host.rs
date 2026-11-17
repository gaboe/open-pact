//! What the program that runs the library provides: its standard input, whether a person sits at
//! a terminal, and a way to interrupt a long wait. The CLI provides the real ones. An app provides
//! none: nothing is read, nobody is asked, and only its own cancel future interrupts. So no library
//! path reads a terminal, installs a signal handler or ends the process.

use std::future::Future;
use std::io::BufRead;
use std::pin::Pin;
use std::sync::Arc;

/// A future that completes at the next interrupt, such as Ctrl-C.
pub type InterruptFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Starts a reader of a program's standard input. The reader stays on the thread that asked for
/// it, so it may hold a lock, as the lock of the standard input does.
pub type InputSource = Arc<dyn Fn() -> Box<dyn BufRead> + Send + Sync>;

/// The way a command ends when its caller interrupted it. The caller decides what that means: the
/// CLI exits with 130.
#[derive(Debug)]
pub struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("interrupted")
    }
}

impl std::error::Error for Interrupted {}

/// What the caller provides. See the module text.
pub struct Host {
    input: InputSource,
    interactive: bool,
    interrupt: Box<dyn Fn() -> InterruptFuture + Send + Sync>,
}

impl Host {
    /// A host with the given input, terminal state and interrupt source. `interrupt` is called
    /// each time a command starts to wait, and its future completes at the next interrupt.
    pub fn new(
        input: impl Fn() -> Box<dyn BufRead> + Send + Sync + 'static,
        interactive: bool,
        interrupt: impl Fn() -> InterruptFuture + Send + Sync + 'static,
    ) -> Host {
        Host {
            input: Arc::new(input),
            interactive,
            interrupt: Box::new(interrupt),
        }
    }

    /// No input, no terminal and no interrupt: what an app gets without a host.
    pub fn closed() -> Host {
        Host::new(
            || Box::new(std::io::empty()),
            false,
            || Box::pin(std::future::pending()),
        )
    }
}

tokio::task_local! {
    static HOST: Arc<Host>;
}

/// Runs `future` with `host` as the one that provides input, terminal state and interrupts.
pub async fn with_host<F: Future>(host: Host, future: F) -> F::Output {
    HOST.scope(Arc::new(host), future).await
}

/// How to start a reader of the standard input; the reader is empty without a host. Call the
/// source on the thread that reads.
pub(crate) fn input() -> InputSource {
    HOST.try_with(|host| host.input.clone())
        .unwrap_or_else(|_| Arc::new(|| Box::new(std::io::empty())))
}

/// Whether a person sits at a terminal and can be asked.
pub(crate) fn interactive() -> bool {
    HOST.try_with(|host| host.interactive).unwrap_or(false)
}

/// Completes at the next interrupt. Never completes without a host.
pub(crate) async fn interrupted() {
    match HOST.try_with(|host| (host.interrupt)()) {
        Ok(future) => future.await,
        Err(_) => std::future::pending().await,
    }
}

/// Whether `error` is an interrupt.
pub(crate) fn is_interrupt(error: &anyhow::Error) -> bool {
    error.is::<Interrupted>()
}
