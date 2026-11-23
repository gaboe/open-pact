//! Built-in observation: a Prometheus text endpoint on its own listener and a slow-request log.
//!
//! Both are off unless the operator sets them. With neither set there is no registry, no timing
//! layer and no listener: every probe in the gateway is one `Option` check.
//!
//! Labels come from bounded sets only: the router's route template (or `unmatched`), four
//! method names, five status classes. No path, address, pseudonym, nonce or hash reaches a label or
//! the slow-request log.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{MethodFilter, on},
};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use prometheus_client::registry::{Registry, Unit};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Bucket bounds in seconds: from a fast read to a request that waited for the whole timeout.
const BUCKETS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// A scrape token shorter than this refuses startup.
const MIN_TOKEN_BYTES: usize = 32;

/// How long a client may take to finish the TLS handshake, and to send the request headers.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a new connection waits for a free slot. Ten seconds outlasts a stalled connection's
/// handshake or header timeout, so a scrape waits for one instead of failing.
const SLOT_WAIT: Duration = Duration::from_secs(10);
/// Connections at once. A connection serves one scrape and then closes.
const CONNECTIONS_AT_ONCE: usize = 16;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct HttpLabels {
    route: String,
    method: &'static str,
    status: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct AbortedLabels {
    route: String,
    method: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResultLabel {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct StateLabel {
    state: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SiteLabel {
    site: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct StageLabel {
    stage: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ServedLabels {
    caller: &'static str,
    result: &'static str,
}

/// Where a connection is taken from the pool. Queries on `&app.db` acquire without a timer.
#[derive(Clone, Copy)]
pub enum Site {
    Conn,
    ClaimTx,
    NonceTx,
    OtherTx,
}

impl Site {
    fn label(self) -> &'static str {
        match self {
            Site::Conn => "conn",
            Site::ClaimTx => "claim_tx",
            Site::NonceTx => "nonce_tx",
            Site::OtherTx => "other_tx",
        }
    }
}

#[derive(Clone, Copy)]
pub enum Stage {
    Verify,
    Nonce,
    Tree,
    Begin,
    Lock,
    Evaluate,
    Certificate,
    Store,
    Commit,
    Siem,
    Checkpoint,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Stage::Verify => "verify",
            Stage::Nonce => "nonce",
            Stage::Tree => "tree",
            Stage::Begin => "begin",
            Stage::Lock => "lock",
            Stage::Evaluate => "evaluate",
            Stage::Certificate => "certificate",
            Stage::Store => "store",
            Stage::Commit => "commit",
            Stage::Siem => "siem",
            Stage::Checkpoint => "checkpoint",
        }
    }
}

#[derive(Clone, Copy)]
pub enum NonceResult {
    Issued,
    RateLimited,
    CapReached,
}

#[derive(Clone, Copy)]
pub enum Push {
    Cosigned,
    Conflict,
    Refused,
    /// The witness answered 200 without a cosignature from a manifest witness key.
    Invalid,
    Error,
    Timeout,
}

impl Push {
    fn label(self) -> &'static str {
        match self {
            Push::Cosigned => "cosigned",
            Push::Conflict => "conflict",
            Push::Refused => "refused",
            Push::Invalid => "invalid",
            Push::Error => "error",
            Push::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy)]
pub enum Caller {
    Checkpoint,
    Mine,
    Enroll,
    Claim,
}

/// What a checkpoint answer held. `NotYet` means the note had fewer witness cosignatures than
/// the manifest's quorum.
#[derive(Clone, Copy)]
pub enum Served {
    Witnessed,
    NotYet,
    LogSigned,
}

pub struct Metrics {
    registry: Registry,
    http: Family<HttpLabels, Histogram>,
    aborted: Family<AbortedLabels, Counter>,
    nonce_lock_wait: Histogram,
    nonce_issue: Family<ResultLabel, Counter>,
    pool_connections: Family<StateLabel, Gauge>,
    pool_max: Gauge,
    db_acquire: Family<SiteLabel, Histogram>,
    claim_stage: Family<StageLabel, Histogram>,
    witness_push: Family<ResultLabel, Histogram>,
    checkpoint_served: Family<ServedLabels, Counter>,
    /// NaN until the first read of the log.
    log_size: Gauge<f64, AtomicU64>,
}

fn histogram() -> Histogram {
    Histogram::new(BUCKETS)
}

impl Metrics {
    pub fn new() -> Metrics {
        let mut registry = Registry::default();
        let http = Family::<HttpLabels, Histogram>::new_with_constructor(histogram);
        registry.register_with_unit(
            "openpact_http_request_duration",
            "Time a handler of the gateway took, by route template, method and status class",
            Unit::Seconds,
            http.clone(),
        );
        let aborted = Family::<AbortedLabels, Counter>::default();
        registry.register(
            "openpact_http_requests_aborted",
            "Requests whose handler stopped before it answered, for example because the client left",
            aborted.clone(),
        );
        let nonce_lock_wait = histogram();
        registry.register_with_unit(
            "openpact_nonce_lock_wait",
            "Time a nonce issuer waited for the advisory lock",
            Unit::Seconds,
            nonce_lock_wait.clone(),
        );
        let nonce_issue = Family::<ResultLabel, Counter>::default();
        registry.register(
            "openpact_nonce_issue",
            "Nonce requests by result: issued, rate_limited or cap_reached",
            nonce_issue.clone(),
        );
        let pool_connections = Family::<StateLabel, Gauge>::default();
        registry.register(
            "openpact_db_pool_connections",
            "Database pool connections at scrape time, used or idle",
            pool_connections.clone(),
        );
        let pool_max = Gauge::default();
        registry.register(
            "openpact_db_pool_max",
            "Largest size of the database pool",
            pool_max.clone(),
        );
        let db_acquire = Family::<SiteLabel, Histogram>::new_with_constructor(histogram);
        registry.register_with_unit(
            "openpact_db_acquire",
            "Time to take a pool connection at the sites that time it. At a transaction site it also covers BEGIN. Queries on the pool itself acquire without a timer",
            Unit::Seconds,
            db_acquire.clone(),
        );
        let claim_stage = Family::<StageLabel, Histogram>::new_with_constructor(histogram);
        registry.register_with_unit(
            "openpact_claim_stage",
            "Time a claim spent in each stage of its handler",
            Unit::Seconds,
            claim_stage.clone(),
        );
        let witness_push = Family::<ResultLabel, Histogram>::new_with_constructor(histogram);
        registry.register_with_unit(
            "openpact_witness_push",
            "Time of one add-checkpoint call to a witness, by result",
            Unit::Seconds,
            witness_push.clone(),
        );
        let checkpoint_served = Family::<ServedLabels, Counter>::default();
        registry.register(
            "openpact_checkpoint_served",
            "Checkpoints handed out, by caller and by whether the witness quorum was met",
            checkpoint_served.clone(),
        );
        let log_size = Gauge::<f64, AtomicU64>::default();
        log_size.set(f64::NAN);
        registry.register(
            "openpact_log_size",
            "Entries in the transparency log as of the last read; NaN until the first read",
            log_size.clone(),
        );
        Metrics {
            registry,
            http,
            aborted,
            nonce_lock_wait,
            nonce_issue,
            pool_connections,
            pool_max,
            db_acquire,
            claim_stage,
            witness_push,
            checkpoint_served,
            log_size,
        }
    }

    fn request(&self, route: &str, method: &'static str, status: &'static str, secs: f64) {
        self.http
            .get_or_create(&HttpLabels {
                route: route.to_owned(),
                method,
                status,
            })
            .observe(secs);
    }

    fn abort(&self, route: &str, method: &'static str) {
        self.aborted
            .get_or_create(&AbortedLabels {
                route: route.to_owned(),
                method,
            })
            .inc();
    }

    pub fn nonce_lock_wait(&self, secs: f64) {
        self.nonce_lock_wait.observe(secs);
    }

    pub fn nonce_issue(&self, result: NonceResult) {
        let result = match result {
            NonceResult::Issued => "issued",
            NonceResult::RateLimited => "rate_limited",
            NonceResult::CapReached => "cap_reached",
        };
        self.nonce_issue
            .get_or_create(&ResultLabel { result })
            .inc();
    }

    pub fn db_acquire(&self, site: Site, secs: f64) {
        self.db_acquire
            .get_or_create(&SiteLabel { site: site.label() })
            .observe(secs);
    }

    pub fn claim_stage(&self, stage: Stage, secs: f64) {
        self.claim_stage
            .get_or_create(&StageLabel {
                stage: stage.label(),
            })
            .observe(secs);
    }

    pub fn witness_push(&self, result: Push, secs: f64) {
        self.witness_push
            .get_or_create(&ResultLabel {
                result: result.label(),
            })
            .observe(secs);
    }

    pub fn checkpoint_served(&self, caller: Caller, served: Served) {
        let caller = match caller {
            Caller::Checkpoint => "checkpoint",
            Caller::Mine => "mine",
            Caller::Enroll => "enroll",
            Caller::Claim => "claim",
        };
        let result = match served {
            Served::Witnessed => "witnessed",
            Served::NotYet => "not_yet",
            Served::LogSigned => "log_signed",
        };
        self.checkpoint_served
            .get_or_create(&ServedLabels { caller, result })
            .inc();
    }

    pub fn log_size(&self, size: u64) {
        self.log_size.set(size as f64);
    }

    /// The text of a scrape. The pool gauges are read now.
    pub fn scrape(&self, pool: &PgPool) -> String {
        let size = i64::from(pool.size());
        let idle = i64::try_from(pool.num_idle()).unwrap_or(i64::MAX);
        self.pool_connections
            .get_or_create(&StateLabel { state: "used" })
            .set((size - idle).max(0));
        self.pool_connections
            .get_or_create(&StateLabel { state: "idle" })
            .set(idle);
        self.pool_max
            .set(i64::from(pool.options().get_max_connections()));
        let mut text = String::new();
        encode(&mut text, &self.registry).expect("encode into a String cannot fail");
        text
    }
}

/// The clock an observation point reads. Only points that run with observation on call it, so a
/// test can count the reads and show that the off path makes none.
pub fn now() -> Instant {
    #[cfg(test)]
    CLOCK_READS.with(|reads| reads.set(reads.get() + 1));
    Instant::now()
}

#[cfg(test)]
thread_local! {
    static CLOCK_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The clock reads that observation points made on this thread.
#[cfg(test)]
pub(crate) fn clock_reads() -> u64 {
    CLOCK_READS.with(std::cell::Cell::get)
}

/// Times a future into a metric when metrics are on. Off, it only awaits the future.
pub async fn timed<T>(
    metrics: Option<&Metrics>,
    record: impl FnOnce(&Metrics, f64),
    future: impl Future<Output = T>,
) -> T {
    let Some(metrics) = metrics else {
        return future.await;
    };
    let start = now();
    let output = future.await;
    record(metrics, start.elapsed().as_secs_f64());
    output
}

/// Records the time since the previous mark as one claim stage. Off, it reads no clock and a mark
/// does nothing.
pub struct StageClock<'a> {
    metrics: Option<&'a Metrics>,
    last: Option<Instant>,
}

impl<'a> StageClock<'a> {
    pub fn new(metrics: Option<&'a Metrics>) -> StageClock<'a> {
        StageClock {
            metrics,
            last: metrics.map(|_| now()),
        }
    }

    pub fn mark(&mut self, stage: Stage) {
        if let (Some(metrics), Some(last)) = (self.metrics, self.last) {
            let at = now();
            metrics.claim_stage(stage, (at - last).as_secs_f64());
            self.last = Some(at);
        }
    }
}

/// At most one slow-request line a window (one second by default); the next line says how many
/// were left out.
pub struct SlowLog {
    threshold: Duration,
    window: Duration,
    state: Mutex<SlowState>,
}

struct SlowState {
    /// When the last line finished writing.
    last: Option<Instant>,
    suppressed: u64,
    out: Box<dyn Write + Send>,
}

impl SlowLog {
    fn new(threshold_ms: u64) -> SlowLog {
        SlowLog::with_output(
            Duration::from_millis(threshold_ms),
            Duration::from_secs(1),
            Box::new(std::io::stderr()),
        )
    }

    fn with_output(threshold: Duration, window: Duration, out: Box<dyn Write + Send>) -> SlowLog {
        SlowLog {
            threshold,
            window,
            state: Mutex::new(SlowState {
                last: None,
                suppressed: 0,
                out,
            }),
        }
    }

    /// Writes the line for a request when one is due: the request was slow and no line finished
    /// writing less than a window ago. The clock is read under the lock, so a request that waited
    /// for a slow write compares against the end of that write. The lock stays held while the line
    /// is written, so lines leave in the order their decisions were made.
    fn emit(&self, route: &str, method: &str, status: &str, elapsed: Duration) -> Option<String> {
        if elapsed < self.threshold {
            return None;
        }
        let mut state = self.state.lock().expect("slow log state");
        if state
            .last
            .is_some_and(|last| Instant::now().saturating_duration_since(last) < self.window)
        {
            state.suppressed += 1;
            return None;
        }
        let mut line = format!(
            "slow_request route={route} method={method} status={status} ms={}",
            elapsed.as_millis()
        );
        if state.suppressed > 0 {
            line.push_str(&format!(" suppressed={}", state.suppressed));
        }
        let written = format!("{line}\n");
        if state
            .out
            .write_all(written.as_bytes())
            .and_then(|()| state.out.flush())
            .is_err()
        {
            return None;
        }
        state.last = Some(Instant::now());
        state.suppressed = 0;
        Some(line)
    }
}

/// What the timing layer feeds: the registry, the slow-request log, or both.
pub struct Observation {
    metrics: Option<Arc<Metrics>>,
    slow: Option<SlowLog>,
}

impl Observation {
    /// None when both are off.
    pub fn new(metrics: Option<Arc<Metrics>>, slow_ms: Option<u64>) -> Option<Arc<Observation>> {
        if metrics.is_none() && slow_ms.is_none() {
            return None;
        }
        Some(Arc::new(Observation {
            metrics,
            slow: slow_ms.map(SlowLog::new),
        }))
    }

    pub fn metrics(&self) -> Option<&Metrics> {
        self.metrics.as_deref()
    }
}

/// Puts the timing layer on `router`. Call it only with an observation that exists.
pub fn layer(router: Router, observation: Arc<Observation>) -> Router {
    router.layer(axum::middleware::from_fn_with_state(observation, observe))
}

fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::HEAD => "HEAD",
        _ => "other",
    }
}

fn status_label(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

/// Counts a handler that stopped before it answered: the guard is dropped without `answered`.
struct InFlight<'a> {
    observation: &'a Observation,
    route: &'a str,
    method: &'static str,
    answered: bool,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if !self.answered
            && let Some(metrics) = self.observation.metrics()
        {
            metrics.abort(self.route, self.method);
        }
    }
}

async fn observe(
    State(observation): State<Arc<Observation>>,
    request: Request,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let method = method_label(request.method());
    let start = now();
    let mut guard = InFlight {
        observation: &observation,
        route: &route,
        method,
        answered: false,
    };
    let response = next.run(request).await;
    guard.answered = true;
    let elapsed = start.elapsed();
    let status = status_label(response.status());
    if let Some(metrics) = observation.metrics() {
        metrics.request(&route, method, status, elapsed.as_secs_f64());
    }
    if let Some(slow) = &observation.slow {
        slow.emit(&route, method, status, elapsed);
    }
    response
}

/// The observation settings from the environment, checked before anything starts.
pub struct Settings {
    pub listener: Option<ListenerSettings>,
    /// None: no slow-request log.
    pub slow_ms: Option<u64>,
}

pub struct ListenerSettings {
    pub addr: SocketAddr,
    token: String,
    tls: Option<(PathBuf, PathBuf)>,
}

impl Settings {
    pub fn from_env() -> anyhow::Result<Settings> {
        Settings::parse(|name| std::env::var(name).ok())
    }

    fn parse(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Settings> {
        let slow_ms = match get("SLOW_REQUEST_MS").filter(|v| !v.is_empty()) {
            None => None,
            Some(v) => {
                let ms: u64 = v
                    .parse()
                    .map_err(|_| anyhow::anyhow!("SLOW_REQUEST_MS must be a number, got {v:?}"))?;
                (ms > 0).then_some(ms)
            }
        };
        let Some(addr) = get("METRICS_ADDR").filter(|v| !v.trim().is_empty()) else {
            return Ok(Settings {
                listener: None,
                slow_ms,
            });
        };
        let addr: SocketAddr = addr.parse().map_err(|_| {
            anyhow::anyhow!("METRICS_ADDR must be an IP address and a port, got {addr:?}")
        })?;
        let token = get("METRICS_TOKEN").unwrap_or_default();
        anyhow::ensure!(
            token.len() >= MIN_TOKEN_BYTES && token.bytes().all(|byte| byte.is_ascii_graphic()),
            "METRICS_ADDR needs METRICS_TOKEN: at least {MIN_TOKEN_BYTES} visible ASCII characters without spaces, for example the output of openssl rand -hex 32"
        );
        let path = |name: &str| {
            get(name)
                .filter(|v| !v.trim().is_empty())
                .map(PathBuf::from)
        };
        let tls = match (path("METRICS_TLS_CERT"), path("METRICS_TLS_KEY")) {
            (Some(cert), Some(key)) => Some((cert, key)),
            (None, None) if addr.ip().is_loopback() => None,
            (None, None) => anyhow::bail!(
                "METRICS_ADDR {addr} is not a loopback address, so it needs METRICS_TLS_CERT and METRICS_TLS_KEY"
            ),
            _ => anyhow::bail!("METRICS_TLS_CERT and METRICS_TLS_KEY go together"),
        };
        Ok(Settings {
            listener: Some(ListenerSettings { addr, token, tls }),
            slow_ms,
        })
    }
}

fn tls_config(cert: &PathBuf, key: &PathBuf) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let certs = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("read METRICS_TLS_CERT {}", cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse METRICS_TLS_CERT {}", cert.display()))?;
    anyhow::ensure!(
        !certs.is_empty(),
        "METRICS_TLS_CERT {} holds no certificate",
        cert.display()
    );
    let key = PrivateKeyDer::from_pem_file(key)
        .with_context(|| format!("read METRICS_TLS_KEY {}", key.display()))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("METRICS_TLS_CERT and METRICS_TLS_KEY do not fit together")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Accepts connections and serves each one in its own task. Each connection holds one of
/// `CONNECTIONS_AT_ONCE` slots from accept until it closes. A connection that finds no free slot
/// waits `SLOT_WAIT` for one, and the listener drops it when none comes.
async fn accept_connections(
    tcp: tokio::net::TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    router: Router,
) {
    let slots = Arc::new(Semaphore::new(CONNECTIONS_AT_ONCE));
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    loop {
        let Ok((stream, _peer)) = tcp.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(Ok(slot)) = tokio::time::timeout(SLOT_WAIT, slots.clone().acquire_owned()).await
        else {
            continue;
        };
        tokio::spawn(serve_connection(
            stream,
            acceptor.clone(),
            router.clone(),
            slot,
        ));
    }
}

/// Serves one connection: the TLS handshake under its own timeout when TLS is on, then one
/// request. The connection closes after its answer, which frees the slot. HTTP/1 only.
async fn serve_connection(
    stream: TcpStream,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    router: Router,
    _slot: OwnedSemaphorePermit,
) {
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .keep_alive(false);
    let service = TowerToHyperService::new(router);
    match acceptor {
        None => {
            let _ = http.serve_connection(TokioIo::new(stream), service).await;
        }
        Some(acceptor) => {
            let shaken = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
            if let Ok(Ok(tls)) = shaken {
                let _ = http.serve_connection(TokioIo::new(tls), service).await;
            }
        }
    }
}

#[derive(Clone)]
struct Scrape {
    metrics: Arc<Metrics>,
    pool: PgPool,
    /// SHA-256 of the token: the comparison then takes the same time for every guess.
    token: [u8; 32],
}

/// Whether the request carries the token. The scheme name is case-insensitive (RFC 9110, 11.1).
fn authorized(expected: &[u8; 32], headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some((scheme, token)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    digest.ct_eq(expected).into()
}

/// A HEAD request gets no scrape. Axum would otherwise run the GET handler and drop the body.
async fn head_refused() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

async fn scrape(State(state): State<Scrape>, headers: HeaderMap) -> Response {
    if !authorized(&state.token, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    }
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        state.metrics.scrape(&state.pool),
    )
        .into_response()
}

/// Binds the metrics listener and serves `GET /metrics` on it in a task. Returns the bound address.
/// A bad certificate or a taken port fails here, so the gateway refuses to start.
pub async fn start(
    settings: ListenerSettings,
    metrics: Arc<Metrics>,
    pool: PgPool,
) -> anyhow::Result<SocketAddr> {
    let router = Router::new()
        .route(
            "/metrics",
            on(MethodFilter::GET, scrape).on(MethodFilter::HEAD, head_refused),
        )
        .with_state(Scrape {
            metrics,
            pool,
            token: Sha256::digest(settings.token.as_bytes()).into(),
        });
    let tls = settings
        .tls
        .as_ref()
        .map(|(cert, key)| tls_config(cert, key))
        .transpose()?;
    let tcp = tokio::net::TcpListener::bind(settings.addr)
        .await
        .with_context(|| format!("bind METRICS_ADDR {}", settings.addr))?;
    let local = tcp.local_addr()?;
    tokio::spawn(accept_connections(tcp, tls, router));
    Ok(local)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::body::Body;
    use axum::routing::get;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use sqlx::postgres::PgPoolOptions;
    use tokio::io::AsyncReadExt;
    use tower::ServiceExt;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    fn settings(env: &[(&str, &str)]) -> anyhow::Result<Settings> {
        let env: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Settings::parse(|name| env.get(name).cloned())
    }

    fn refusal(env: &[(&str, &str)]) -> String {
        match settings(env) {
            Ok(_) => panic!("started with {env:?}"),
            Err(error) => error.to_string(),
        }
    }

    fn lazy_pool() -> PgPool {
        PgPoolOptions::new()
            .max_connections(7)
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .unwrap()
    }

    #[test]
    fn everything_is_off_unless_it_is_set() {
        let off = settings(&[]).unwrap();
        assert!(off.listener.is_none() && off.slow_ms.is_none());
        assert!(Observation::new(None, off.slow_ms).is_none());
        let blank = settings(&[("METRICS_ADDR", " "), ("SLOW_REQUEST_MS", "")]).unwrap();
        assert!(blank.listener.is_none() && blank.slow_ms.is_none());
        assert_eq!(settings(&[("SLOW_REQUEST_MS", "0")]).unwrap().slow_ms, None);
        assert_eq!(
            settings(&[("SLOW_REQUEST_MS", "1000")]).unwrap().slow_ms,
            Some(1000)
        );
        assert!(settings(&[("SLOW_REQUEST_MS", "soon")]).is_err());
    }

    #[test]
    fn the_slow_log_alone_starts_no_listener_and_no_registry() {
        let slow = settings(&[("SLOW_REQUEST_MS", "250")]).unwrap();
        assert!(slow.listener.is_none());
        let observation = Observation::new(None, slow.slow_ms).unwrap();
        assert!(observation.metrics().is_none());
    }

    #[test]
    fn a_missing_blank_or_short_token_refuses_startup() {
        let short = "a".repeat(MIN_TOKEN_BYTES - 1);
        let spaces = " ".repeat(64);
        let inner_space = format!("{} {}", "a".repeat(20), "b".repeat(20));
        let padded = format!(" {TOKEN}");
        let tokens: [&[(&str, &str)]; 6] = [
            &[],
            &[("METRICS_TOKEN", "")],
            &[("METRICS_TOKEN", &spaces)],
            &[("METRICS_TOKEN", &short)],
            &[("METRICS_TOKEN", &inner_space)],
            &[("METRICS_TOKEN", &padded)],
        ];
        for token in tokens {
            let mut env = vec![("METRICS_ADDR", "127.0.0.1:9090")];
            env.extend_from_slice(token);
            assert!(refusal(&env).contains("METRICS_TOKEN"), "{token:?}");
        }
        let token = "a".repeat(MIN_TOKEN_BYTES);
        settings(&[
            ("METRICS_ADDR", "127.0.0.1:9090"),
            ("METRICS_TOKEN", &token),
        ])
        .unwrap();
    }

    #[test]
    fn plain_http_is_for_loopback_only() {
        let plain = [("METRICS_TOKEN", TOKEN)];
        for addr in ["127.0.0.1:9090", "[::1]:9090"] {
            let mut env = vec![("METRICS_ADDR", addr)];
            env.extend_from_slice(&plain);
            assert!(settings(&env).unwrap().listener.is_some(), "{addr}");
        }
        for addr in ["0.0.0.0:9090", "10.1.2.3:9090", "[::]:9090"] {
            let mut env = vec![("METRICS_ADDR", addr)];
            env.extend_from_slice(&plain);
            assert!(refusal(&env).contains("METRICS_TLS_CERT"), "{addr}");
        }
        let one_file = [
            ("METRICS_ADDR", "127.0.0.1:9090"),
            ("METRICS_TOKEN", TOKEN),
            ("METRICS_TLS_CERT", "/tls/cert.pem"),
        ];
        assert!(refusal(&one_file).contains("go together"));
        assert!(
            refusal(&[
                ("METRICS_ADDR", "metrics.local:9090"),
                ("METRICS_TOKEN", TOKEN)
            ])
            .contains("METRICS_ADDR")
        );
    }

    struct Pki {
        dir: PathBuf,
        ca_pem: String,
    }

    impl Pki {
        /// A CA and a server certificate for `metrics.test`, written to a fresh directory.
        fn new() -> Pki {
            let dir = std::env::temp_dir().join(format!(
                "open-pact-metrics-{}",
                hex::encode(rand::random::<[u8; 8]>())
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
            let issuer = Issuer::new(ca_params, ca_key);
            let server_key = KeyPair::generate().unwrap();
            let server = CertificateParams::new(vec!["metrics.test".to_owned()])
                .unwrap()
                .signed_by(&server_key, &issuer)
                .unwrap();
            std::fs::write(dir.join("tls.crt"), server.pem()).unwrap();
            std::fs::write(dir.join("tls.key"), server_key.serialize_pem()).unwrap();
            Pki { dir, ca_pem }
        }

        fn settings(&self, addr: &str) -> ListenerSettings {
            let env = [
                ("METRICS_ADDR", addr.to_owned()),
                ("METRICS_TOKEN", TOKEN.to_owned()),
                (
                    "METRICS_TLS_CERT",
                    self.dir.join("tls.crt").display().to_string(),
                ),
                (
                    "METRICS_TLS_KEY",
                    self.dir.join("tls.key").display().to_string(),
                ),
            ];
            Settings::parse(|name| env.iter().find(|(k, _)| *k == name).map(|(_, v)| v.clone()))
                .unwrap()
                .listener
                .unwrap()
        }
    }

    impl Drop for Pki {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn recorded() -> Arc<Metrics> {
        let metrics = Arc::new(Metrics::new());
        metrics.request("/v1/claim", "POST", "2xx", 0.2);
        metrics
    }

    #[tokio::test]
    async fn the_tls_listener_serves_only_a_scraper_with_the_token() {
        let pki = Pki::new();
        // Not a loopback address: the scraper reaches it through 127.0.0.1 with a name.
        let bound = start(pki.settings("0.0.0.0:0"), recorded(), lazy_pool())
            .await
            .unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
            .resolve(
                "metrics.test",
                SocketAddr::from(([127, 0, 0, 1], bound.port())),
            )
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("https://metrics.test:{}/metrics", bound.port());

        let ok = client.get(&url).bearer_auth(TOKEN).send().await.unwrap();
        assert_eq!(ok.status(), 200);
        let text = ok.text().await.unwrap();
        assert!(
            text.contains("openpact_http_request_duration_seconds_count{route=\"/v1/claim\",method=\"POST\",status=\"2xx\"} 1"),
            "{text}"
        );
        assert!(text.contains("openpact_db_pool_max 7"), "{text}");
        assert!(text.ends_with("# EOF\n"));

        let anonymous = client.get(&url).send().await.unwrap();
        assert_eq!(anonymous.status(), 401);
        let wrong = client
            .get(&url)
            .bearer_auth(format!("{TOKEN}x"))
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), 401);
        let other_path = client
            .get(format!("https://metrics.test:{}/v1/manifest", bound.port()))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(other_path.status(), 404);
        let post = client.post(&url).bearer_auth(TOKEN).send().await.unwrap();
        assert_eq!(post.status(), 405);
        let head = client.head(&url).bearer_auth(TOKEN).send().await.unwrap();
        assert_eq!(head.status(), 405);
        // The scheme name is case-insensitive.
        let lowercase = client
            .get(&url)
            .header(header::AUTHORIZATION, format!("bearer {TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_eq!(lowercase.status(), 200);

        let plain = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .get(format!("http://127.0.0.1:{}/metrics", bound.port()))
            .bearer_auth(TOKEN)
            .send()
            .await;
        assert!(plain.is_err(), "plain HTTP got an answer: {plain:?}");
    }

    #[tokio::test]
    async fn a_client_that_never_finishes_its_handshake_blocks_no_one() {
        let pki = Pki::new();
        let bound = start(pki.settings("127.0.0.1:0"), recorded(), lazy_pool())
            .await
            .unwrap();
        let _stalled = tokio::net::TcpStream::connect(bound).await.unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap())
            .resolve("metrics.test", bound)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let ok = client
            .get(format!("https://metrics.test:{}/metrics", bound.port()))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
    }

    #[tokio::test]
    async fn a_client_that_sends_no_request_is_closed_after_the_header_timeout() {
        let env = [("METRICS_ADDR", "127.0.0.1:0"), ("METRICS_TOKEN", TOKEN)];
        let listener = settings(&env).unwrap().listener.unwrap();
        let bound = start(listener, recorded(), lazy_pool()).await.unwrap();
        let mut idle = tokio::net::TcpStream::connect(bound).await.unwrap();
        let closed =
            tokio::time::timeout(Duration::from_secs(10), idle.read_to_end(&mut Vec::new())).await;
        assert!(matches!(closed, Ok(Ok(_))), "{closed:?}");
    }

    #[tokio::test]
    async fn a_scrape_waits_for_a_slot_behind_stalled_connections() {
        let env = [("METRICS_ADDR", "127.0.0.1:0"), ("METRICS_TOKEN", TOKEN)];
        let listener = settings(&env).unwrap().listener.unwrap();
        let bound = start(listener, recorded(), lazy_pool()).await.unwrap();
        let mut stalled = Vec::new();
        for _ in 0..CONNECTIONS_AT_ONCE {
            stalled.push(tokio::net::TcpStream::connect(bound).await.unwrap());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let ok = client
            .get(format!("http://{bound}/metrics"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
        drop(stalled);
    }

    #[tokio::test]
    async fn an_unreadable_key_or_certificate_refuses_startup() {
        let pki = Pki::new();
        let mut missing_key = pki.settings("127.0.0.1:0");
        missing_key.tls.as_mut().unwrap().1 = pki.dir.join("none.key");
        let error = start(missing_key, recorded(), lazy_pool())
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("METRICS_TLS_KEY"),
            "{error:#}"
        );

        std::fs::write(pki.dir.join("empty.crt"), "").unwrap();
        let mut no_certificate = pki.settings("127.0.0.1:0");
        no_certificate.tls.as_mut().unwrap().0 = pki.dir.join("empty.crt");
        let error = start(no_certificate, recorded(), lazy_pool())
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("METRICS_TLS_CERT"),
            "{error:#}"
        );

        let mut mismatched = pki.settings("127.0.0.1:0");
        let other = Pki::new();
        mismatched.tls.as_mut().unwrap().1 = other.dir.join("tls.key");
        assert!(start(mismatched, recorded(), lazy_pool()).await.is_err());
    }

    #[tokio::test]
    async fn loopback_serves_plain_http_with_the_token() {
        let env = [("METRICS_ADDR", "127.0.0.1:0"), ("METRICS_TOKEN", TOKEN)];
        let listener = settings(&env).unwrap().listener.unwrap();
        let bound = start(listener, recorded(), lazy_pool()).await.unwrap();
        let client = reqwest::Client::new();
        let url = format!("http://{bound}/metrics");
        assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
        assert_eq!(
            client
                .get(&url)
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }

    fn observed() -> (Router, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::new());
        let observation = Observation::new(Some(metrics.clone()), None).unwrap();
        let router = Router::new()
            .route("/v1/manifest", get(|| async { "ok" }))
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    "late"
                }),
            )
            .route("/hang", get(std::future::pending::<&'static str>));
        (layer(router, observation), metrics)
    }

    async fn send(router: &Router, method: &str, path: &str) -> StatusCode {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        router.clone().oneshot(request).await.unwrap().status()
    }

    fn label_values<'a>(text: &'a str, label: &str) -> std::collections::BTreeSet<&'a str> {
        let key = format!("{label}=\"");
        text.lines()
            .filter(|line| line.starts_with("openpact_http_request_duration_seconds_count"))
            .filter_map(|line| line.split(&key).nth(1)?.split('"').next())
            .collect()
    }

    #[tokio::test]
    async fn labels_come_from_bounded_sets() {
        let (router, metrics) = observed();
        assert_eq!(send(&router, "GET", "/v1/manifest").await, 200);
        assert_eq!(
            send(&router, "GET", "/v1/manifest/pseudonym:ab12cd").await,
            404
        );
        assert_eq!(send(&router, "GET", "/v1/device/9f2c4e/status").await, 404);
        assert_eq!(send(&router, "FOO", "/v1/manifest").await, 405);
        let text = metrics.scrape(&lazy_pool());
        assert!(
            text.contains("openpact_http_request_duration_seconds_count{route=\"/v1/manifest\",method=\"GET\",status=\"2xx\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("openpact_http_request_duration_seconds_count{route=\"unmatched\",method=\"GET\",status=\"4xx\"} 2"),
            "{text}"
        );
        assert_eq!(
            label_values(&text, "route"),
            ["/v1/manifest", "unmatched"].into_iter().collect()
        );
        assert_eq!(
            label_values(&text, "method"),
            ["GET", "other"].into_iter().collect()
        );
        assert_eq!(
            label_values(&text, "status"),
            ["2xx", "4xx"].into_iter().collect()
        );
        for leak in ["pseudonym", "ab12cd", "9f2c4e", "FOO"] {
            assert!(!text.contains(leak), "{leak} reached the scrape: {text}");
        }
    }

    #[tokio::test]
    async fn a_slow_handler_lands_in_the_bucket_that_holds_its_time() {
        let (router, metrics) = observed();
        assert_eq!(send(&router, "GET", "/slow").await, 200);
        let text = metrics.scrape(&lazy_pool());
        let bucket = |le: &str| -> u64 {
            let prefix = format!(
                "openpact_http_request_duration_seconds_bucket{{le=\"{le}\",route=\"/slow\",method=\"GET\",status=\"2xx\"}} "
            );
            text.lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .unwrap_or_else(|| panic!("no bucket {le}: {text}"))
                .parse()
                .unwrap()
        };
        // 150 ms of sleep leaves 50 ms of room for a late timer on either side.
        assert_eq!(bucket("0.1"), 0);
        assert_eq!(bucket("0.25"), 1);
    }

    #[tokio::test]
    async fn a_handler_that_never_answers_counts_as_aborted_and_not_as_a_response() {
        let (router, metrics) = observed();
        let pending = tokio::spawn({
            let router = router.clone();
            async move { send(&router, "GET", "/hang").await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        pending.abort();
        let aborted = "openpact_http_requests_aborted_total{route=\"/hang\",method=\"GET\"} 1";
        for _ in 0..50 {
            if metrics.scrape(&lazy_pool()).contains(aborted) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let text = metrics.scrape(&lazy_pool());
        assert!(text.contains(aborted), "{text}");
        assert!(
            !text.contains("route=\"/hang\",method=\"GET\",status"),
            "{text}"
        );
    }

    /// A writer that takes `pause` for every write, as a blocked stderr would.
    struct Pausing {
        sink: Arc<Mutex<Vec<u8>>>,
        pause: Duration,
    }

    impl Write for Pausing {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.pause);
            self.sink.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn captured(pause: Duration, window: Duration) -> (SlowLog, Arc<Mutex<Vec<u8>>>) {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let out = Pausing {
            sink: sink.clone(),
            pause,
        };
        let slow = SlowLog::with_output(Duration::from_millis(1000), window, Box::new(out));
        (slow, sink)
    }

    #[test]
    fn the_slow_log_writes_one_line_a_window_and_counts_what_it_left_out() {
        let window = Duration::from_millis(300);
        let (slow, sink) = captured(Duration::ZERO, window);
        let ms = Duration::from_millis;
        assert_eq!(slow.emit("/v1/claim", "POST", "2xx", ms(999)), None);
        assert_eq!(
            slow.emit("/v1/claim", "POST", "2xx", ms(1234)).as_deref(),
            Some("slow_request route=/v1/claim method=POST status=2xx ms=1234")
        );
        // Each check comes well inside the window, so the margins hold on a loaded machine.
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(slow.emit("/v1/nonce", "POST", "5xx", ms(2000)), None);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(slow.emit("/v1/nonce", "POST", "5xx", ms(2000)), None);
        std::thread::sleep(window);
        assert_eq!(
            slow.emit("/v1/nonce", "POST", "5xx", ms(2000)).as_deref(),
            Some("slow_request route=/v1/nonce method=POST status=5xx ms=2000 suppressed=2")
        );
        std::thread::sleep(window);
        assert_eq!(
            slow.emit("/", "GET", "2xx", ms(1000)).as_deref(),
            Some("slow_request route=/ method=GET status=2xx ms=1000")
        );
        let written = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert_eq!(written.lines().count(), 3, "{written}");
    }

    #[test]
    fn a_request_that_waited_for_a_slow_write_keeps_the_window() {
        let window = Duration::from_millis(100);
        let (slow, sink) = captured(Duration::from_millis(300), window);
        let slow = Arc::new(slow);
        let first = {
            let slow = slow.clone();
            std::thread::spawn(move || {
                slow.emit("/v1/claim", "POST", "2xx", Duration::from_secs(2))
            })
        };
        // The first line now holds the lock for its 300 ms write. The second request arrives during
        // that write, 150 ms after the first started, which is more than one window after the first
        // started but less than one window after the first line finished.
        std::thread::sleep(Duration::from_millis(150));
        let second = slow.emit("/v1/nonce", "POST", "5xx", Duration::from_secs(2));
        assert!(first.join().unwrap().is_some());
        assert_eq!(second, None);
        let written = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert_eq!(written.lines().count(), 1, "{written}");
    }

    #[tokio::test]
    async fn the_off_path_reads_no_clock() {
        let metrics = Metrics::new();
        let before = clock_reads();
        assert_eq!(
            timed(None, |m, s| m.db_acquire(Site::Conn, s), async { 8 }).await,
            8
        );
        let mut off = StageClock::new(None);
        off.mark(Stage::Verify);
        off.mark(Stage::Commit);
        assert_eq!(
            clock_reads(),
            before,
            "observation read the clock while off"
        );
        let mut on = StageClock::new(Some(&metrics));
        on.mark(Stage::Verify);
        assert!(clock_reads() > before);
    }

    #[tokio::test]
    async fn the_log_size_is_unknown_until_the_first_read() {
        let metrics = Metrics::new();
        let has = |text: &str, line: &str| text.lines().any(|l| l == line);
        assert!(has(&metrics.scrape(&lazy_pool()), "openpact_log_size NaN"));
        metrics.log_size(3);
        assert!(has(&metrics.scrape(&lazy_pool()), "openpact_log_size 3.0"));
    }

    #[tokio::test]
    async fn timers_record_only_when_metrics_are_on() {
        let metrics = Metrics::new();
        let value = timed(Some(&metrics), |m, s| m.db_acquire(Site::Conn, s), async {
            7
        })
        .await;
        assert_eq!(value, 7);
        let mut clock = StageClock::new(Some(&metrics));
        clock.mark(Stage::Verify);
        metrics.nonce_issue(NonceResult::CapReached);
        metrics.witness_push(Push::Conflict, 0.01);
        metrics.checkpoint_served(Caller::Claim, Served::NotYet);
        metrics.log_size(3);
        let text = metrics.scrape(&lazy_pool());
        for expected in [
            "openpact_db_acquire_seconds_count{site=\"conn\"} 1",
            "openpact_claim_stage_seconds_count{stage=\"verify\"} 1",
            "openpact_nonce_issue_total{result=\"cap_reached\"} 1",
            "openpact_witness_push_seconds_count{result=\"conflict\"} 1",
            "openpact_checkpoint_served_total{caller=\"claim\",result=\"not_yet\"} 1",
            "openpact_log_size 3.0",
            "openpact_db_pool_connections{state=\"idle\"} 0",
        ] {
            assert!(text.contains(expected), "{expected} missing: {text}");
        }
    }
}
