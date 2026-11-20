use std::{
    collections::{BTreeMap, VecDeque},
    fs::{File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use time::OffsetDateTime;

use anyhow::{Context, bail};
use open_pact_core::{Claim, ControlStanding, Manifest, Pseudonym, verified_trust_level};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serde_json::{Value, json};

const CAPACITY: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long `devices approve` and `devices revoke` wait for one event before they give up.
const ONE_SHOT_TIMEOUT: Duration = Duration::from_secs(15);

// Control values keep their original JSON type. Prefixing avoids collisions with event metadata.
// `standings` is the gateway's own evaluation of the claim, so the status of a control cannot
// differ from the verdict.
pub fn event(
    manifest: &Manifest,
    claim: &Claim,
    device_note: &str,
    reasons: &[String],
    warnings: &[String],
    access_until: Option<OffsetDateTime>,
    standings: &BTreeMap<String, ControlStanding>,
) -> Value {
    let mut body = json!({
        "schema_version": 1,
        "time": open_pact_core::timestamp::rfc3339_auto(claim.time),
        "device_pseudonym": claim.device,
        "manifest_hash": claim.manifest,
        "client_version": claim.client,
        "os": claim.os,
        "verified_trust_level": verified_trust_level(claim),
        "asserted_trust_level": claim.trust_level,
        "verdict": if reasons.is_empty() { "allow" } else { "deny" },
        "reasons": reasons,
        "warnings": warnings,
        "access_until": access_until.map(open_pact_core::timestamp::rfc3339_secs),
        "access_ends": standings
            .values()
            .filter_map(|standing| match standing {
                ControlStanding::Warn { deadline } => *deadline,
                _ => None,
            })
            .min()
            .map(open_pact_core::timestamp::rfc3339_secs),
    });
    if !device_note.is_empty() {
        body["device_note"] = json!(device_note);
    }
    for control in &manifest.body().controls {
        let Some(value) = claim.results.get(&control.id) else {
            continue;
        };
        let standing = standings.get(&control.id);
        let (status, deadline) = match standing {
            Some(ControlStanding::Warn { deadline }) => ("warn", *deadline),
            Some(ControlStanding::Fail) => ("fail", None),
            _ if value == "n/a" => ("n/a", None),
            Some(ControlStanding::Pass) => ("pass", None),
            None => ("report", None),
        };
        body[format!("result_{}", control.id)] = json!(value);
        body[format!("status_{}", control.id)] = json!(status);
        body[format!("deadline_{}", control.id)] =
            json!(deadline.map(open_pact_core::timestamp::rfc3339_secs));
    }
    json!({"open_pact": body})
}

/// The event IT's approval or revocation of a device produces. It shares the `open_pact` key and
/// `schema_version` with the claim event, so rule 100500 matches it too. Unlike a claim event it has
/// an `event` field, `device_state`; a claim event has no `event` field.
/// `at` is the time of the change, and `log_index` is the index of the transparency-log entry that
/// recorded it. Order one device's `device_state` events by `log_index`: the send time and the
/// arrival order do not follow the change.
pub fn state_event(
    device: &Pseudonym,
    device_note: &str,
    state: &str,
    log_index: u64,
    at: OffsetDateTime,
) -> Value {
    json!({"open_pact": {
        "schema_version": 1,
        "event": "device_state",
        "time": open_pact_core::timestamp::rfc3339_auto(at),
        "device_pseudonym": device,
        "device_note": (!device_note.is_empty()).then_some(device_note),
        "state": state,
        "log_index": log_index,
    }})
}

// RFC 5425 counts the UTF-8 bytes of the entire RFC 5424 message, excluding the prefix.
fn frame(json: &[u8]) -> Vec<u8> {
    let mut message = b"<134>1 - - open-pact - status - ".to_vec();
    message.extend_from_slice(json);
    let mut framed = format!("{} ", message.len()).into_bytes();
    framed.extend(message);
    framed
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum FileMode {
    #[default]
    OwnerOnly,
    GroupReadable,
}

impl FileMode {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "0600" => Ok(Self::OwnerOnly),
            "0640" => Ok(Self::GroupReadable),
            _ => bail!("SIEM file mode must be 0600 or 0640"),
        }
    }

    #[cfg(unix)]
    fn unix_mode(self) -> u32 {
        match self {
            Self::OwnerOnly => 0o600,
            Self::GroupReadable => 0o640,
        }
    }
}

enum Sink {
    File {
        path: std::path::PathBuf,
        mode: FileMode,
    },
    Tls {
        host: String,
        port: u16,
        name: ServerName<'static>,
        config: Arc<ClientConfig>,
    },
    #[cfg(test)]
    Blocking(Arc<BlockingSink>),
}

#[cfg(test)]
struct BlockingSink {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

#[cfg(test)]
impl BlockingSink {
    fn new() -> Self {
        Self {
            state: Mutex::new((false, false)),
            changed: Condvar::new(),
        }
    }

    fn deliver(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn wait_until_started(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.0 {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

impl Sink {
    fn tls(url: &str, ca: &str) -> anyhow::Result<Self> {
        let parsed = reqwest::Url::parse(url)?;
        if parsed.scheme() != "tls"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != ""
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            bail!("SIEM URL must be tls://host:port without credentials, path, query or fragment");
        }
        let host = parsed
            .host_str()
            .context("SIEM URL needs a host")?
            .trim_matches(['[', ']'])
            .to_owned();
        let port = parsed.port().context("SIEM URL needs an explicit port")?;
        let name = ServerName::try_from(host.clone())?;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_reader_iter(&mut BufReader::new(File::open(ca)?)) {
            roots.add(cert?)?;
        }
        if roots.is_empty() {
            bail!("SIEM CA file contains no certificates");
        }
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Self::Tls {
            host,
            port,
            name,
            config: Arc::new(config),
        })
    }

    fn deliver(&self, json: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::File { path, mode } => {
                let mut options = OpenOptions::new();
                options.create(true).append(true).read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(mode.unix_mode());
                }
                #[cfg(not(unix))]
                let _ = mode;
                let mut file = options.open(path)?;
                append_json_line(&mut file, json)?;
                file.flush()?;
            }
            Self::Tls {
                host,
                port,
                name,
                config,
            } => {
                let mut tcp = None;
                for addr in (host.as_str(), *port).to_socket_addrs()? {
                    if let Ok(stream) = TcpStream::connect_timeout(&addr, IO_TIMEOUT) {
                        tcp = Some(stream);
                        break;
                    }
                }
                let tcp = tcp.context("cannot connect to SIEM")?;
                tcp.set_read_timeout(Some(IO_TIMEOUT))?;
                tcp.set_write_timeout(Some(IO_TIMEOUT))?;
                let connection = ClientConnection::new(config.clone(), name.clone())?;
                let mut stream = StreamOwned::new(connection, tcp);
                stream.write_all(&frame(json))?;
                stream.flush()?;
                stream.conn.send_close_notify();
                stream.flush()?;
            }
            #[cfg(test)]
            Self::Blocking(blocker) => blocker.deliver(),
        }
        Ok(())
    }
}

// One write per line: the file is opened in append mode, and the CLI's device_state events can
// share it with the server.
fn append_json_line(file: &mut (impl Read + Write + Seek), json: &[u8]) -> std::io::Result<()> {
    let mut line = Vec::with_capacity(json.len() + 2);
    if file.seek(SeekFrom::End(0))? > 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0];
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            line.push(b'\n');
        }
    }
    line.extend_from_slice(json);
    line.push(b'\n');
    file.write_all(&line)
}

#[derive(Default)]
struct Queue {
    events: VecDeque<(u64, Vec<u8>)>,
    next_id: u64,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    dropped: AtomicU64,
    reported_drops: AtomicU64,
}

#[derive(Clone)]
pub struct Exporter(Arc<Shared>);

impl Exporter {
    #[cfg(test)]
    pub fn file_for_test(path: std::path::PathBuf) -> Self {
        Self::start(Sink::File {
            path,
            mode: FileMode::OwnerOnly,
        })
        .unwrap()
    }

    #[cfg(test)]
    pub fn sink_id(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }

    fn start(sink: Sink) -> anyhow::Result<Self> {
        Self::start_with_report_interval(sink, Duration::from_secs(60))
    }

    fn start_with_report_interval(sink: Sink, report_interval: Duration) -> anyhow::Result<Self> {
        let exporter = Self(Arc::default());
        let reporter = Arc::downgrade(&exporter.0);
        std::thread::Builder::new()
            .name("siem-drop-reporter".into())
            .spawn(move || report_drops(reporter, report_interval))?;
        let worker = exporter.clone();
        std::thread::Builder::new()
            .name("siem-delivery".into())
            .spawn(move || worker.run(sink))?;
        Ok(exporter)
    }

    pub fn submit(&self, event: Value) {
        let bytes = serde_json::to_vec(&event).expect("JSON value serializes");
        let mut queue = self.0.queue.lock().unwrap();
        if queue.events.len() == CAPACITY {
            queue.events.pop_front();
            self.0.dropped.fetch_add(1, Ordering::Relaxed);
        }
        let id = queue.next_id;
        queue.next_id = queue.next_id.wrapping_add(1);
        queue.events.push_back((id, bytes));
        drop(queue);
        self.0.ready.notify_one();
    }

    fn run(&self, sink: Sink) {
        let mut backoff = 1;
        loop {
            let (id, bytes) = {
                let mut queue = self.0.queue.lock().unwrap();
                while queue.events.is_empty() {
                    queue = self.0.ready.wait(queue).unwrap();
                }
                queue.events.front().unwrap().clone()
            };
            match sink.deliver(&bytes) {
                Ok(()) => {
                    let mut queue = self.0.queue.lock().unwrap();
                    if queue.events.front().is_some_and(|(front, _)| *front == id) {
                        queue.events.pop_front();
                    }
                    backoff = 1;
                }
                Err(_) => {
                    eprintln!("WARNING: SIEM delivery failed; retry in {backoff}s");
                    std::thread::sleep(Duration::from_secs(backoff));
                    backoff = (backoff * 2).min(60);
                }
            }
        }
    }
}

fn report_drops(shared: Weak<Shared>, interval: Duration) {
    loop {
        std::thread::sleep(interval);
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let dropped = shared.dropped.load(Ordering::Relaxed);
        let reported = shared.reported_drops.load(Ordering::Relaxed);
        if dropped > reported {
            eprintln!(
                "WARNING: SIEM queue full, dropped {delta} oldest events; siem_dropped_total={dropped}",
                delta = dropped - reported
            );
            shared.reported_drops.store(dropped, Ordering::Relaxed);
        }
    }
}

/// One sink for one event, from the `GATEWAY_SIEM_*` variables the server reads. The CLI uses it:
/// its process ends right after the event, so it cannot queue.
pub struct OneShot(Sink);

impl OneShot {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Ok(sink_from_env()?.map(Self))
    }

    #[cfg(test)]
    pub fn file_for_test(path: std::path::PathBuf) -> Self {
        Self(Sink::File {
            path,
            mode: FileMode::OwnerOnly,
        })
    }

    /// Delivers `event` once and waits at most `ONE_SHOT_TIMEOUT`. No retry.
    pub fn send(self, event: &Value) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(event).expect("JSON value serializes");
        let (done, result) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("siem-one-shot".into())
            .spawn(move || {
                let _ = done.send(self.0.deliver(&bytes));
            })?;
        match result.recv_timeout(ONE_SHOT_TIMEOUT) {
            Ok(delivered) => delivered,
            Err(_) => bail!(
                "no answer from the SIEM within {}s",
                ONE_SHOT_TIMEOUT.as_secs()
            ),
        }
    }
}

fn sink_from_env() -> anyhow::Result<Option<Sink>> {
    let url = std::env::var("GATEWAY_SIEM_SYSLOG_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let file = std::env::var("GATEWAY_SIEM_FILE")
        .ok()
        .filter(|s| !s.is_empty());
    Ok(Some(match (url, file) {
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => bail!("configure only one SIEM sink"),
        (Some(url), None) => Sink::tls(
            &url,
            &std::env::var("GATEWAY_SIEM_CA").context("GATEWAY_SIEM_CA")?,
        )?,
        (None, Some(path)) => {
            let mode = std::env::var("GATEWAY_SIEM_FILE_MODE")
                .ok()
                .map(|value| FileMode::parse(&value))
                .transpose()?
                .unwrap_or_default();
            Sink::File {
                path: path.into(),
                mode,
            }
        }
    }))
}

fn configured(manifest: &Manifest) -> anyhow::Result<Option<Exporter>> {
    let Some(sink) = sink_from_env()? else {
        return Ok(None);
    };
    if let Ok(days) = std::env::var("GATEWAY_SIEM_RETENTION_DAYS") {
        let days: i64 = days
            .parse()
            .context("SIEM retention must be whole nonnegative days")?;
        if days < 0 {
            bail!("SIEM retention must be nonnegative");
        }
        let now = OffsetDateTime::now_utc();
        let deadline = days
            .checked_mul(86400)
            .and_then(open_pact_core::timestamp::seconds)
            .and_then(|d| now.checked_add(d))
            .context("SIEM retention exceeds calendar range")?;
        if manifest
            .body()
            .claim_retention
            .after(now)
            .is_none_or(|end| deadline > end)
        {
            eprintln!(
                "WARNING: GATEWAY_SIEM_RETENTION_DAYS exceeds manifest claim_retention; the SIEM keeps its own copy"
            );
        }
    }
    Ok(Some(Exporter::start(sink)?))
}

pub fn from_env(manifest: &Manifest) -> Option<Exporter> {
    match configured(manifest) {
        Ok(exporter) => exporter,
        Err(_) => {
            eprintln!(
                "WARNING: SIEM export disabled because configuration is invalid; check sink URL, CA, and retention"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use open_pact_core::{Pseudonym, PublicKey, dev_key};
    use rustls::{ServerConfig, ServerConnection, pki_types::PrivatePkcs8KeyDer};
    use std::{
        io::{Cursor, Error},
        net::TcpListener,
    };

    fn temporary() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("open-pact-siem-{:032x}", rand::random::<u128>()))
    }

    struct PartialWriter {
        data: Cursor<Vec<u8>>,
        remaining: usize,
        failed: bool,
    }

    impl Read for PartialWriter {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.data.read(buffer)
        }
    }

    impl Write for PartialWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self.failed {
                return self.data.write(buffer);
            }
            if self.remaining == 0 {
                self.failed = true;
                return Err(Error::other("injected partial write"));
            }
            let written = self
                .data
                .write(&buffer[..buffer.len().min(self.remaining)])?;
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.data.flush()
        }
    }

    impl Seek for PartialWriter {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.data.seek(position)
        }
    }

    fn claim(manifest: &Manifest) -> Claim {
        let key = PublicKey::from(&dev_key::generate());
        serde_json::from_value(json!({
            "manifest": manifest.hash(), "device": Pseudonym::of(&key), "device_key": key,
            "nonce": "fictional", "time": "2026-10-20T00:00:00Z", "client": "open-pact-client 0.2.0",
            "os": "linux", "trust_level": "L1",
            "results": {"disk_encryption": "full", "os_patch_age_days": 31, "private_extra": "must not leave"}
        })).unwrap()
    }

    #[test]
    fn event_names_the_device_with_its_invitation_note() {
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        let claim = claim(&manifest);
        let named = event(
            &manifest,
            &claim,
            "Laptop, Example Person",
            &[],
            &[],
            None,
            &BTreeMap::new(),
        );
        assert_eq!(named["open_pact"]["device_note"], "Laptop, Example Person");
        let unnamed = event(&manifest, &claim, "", &[], &[], None, &BTreeMap::new());
        assert!(unnamed["open_pact"].get("device_note").is_none());
    }

    #[test]
    fn state_event_names_the_device_its_note_and_the_new_state() {
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let at = OffsetDateTime::from_unix_timestamp(1_792_000_000).unwrap();
        let named = state_event(&device, "Laptop, Example Person", "revoked", 7, at);
        assert_eq!(
            named,
            json!({"open_pact": {
                "schema_version": 1,
                "event": "device_state",
                "time": "2026-10-14T17:46:40Z",
                "device_pseudonym": device,
                "device_note": "Laptop, Example Person",
                "state": "revoked",
                "log_index": 7,
            }})
        );
        let unnamed = state_event(&device, "", "approved", 3, at);
        assert_eq!(unnamed["open_pact"]["log_index"], 3);
        assert_eq!(unnamed["open_pact"]["device_note"], Value::Null);
        assert_eq!(unnamed["open_pact"]["state"], "approved");
    }

    #[test]
    fn one_shot_writes_one_line_to_a_file_sink() {
        let path = temporary();
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let event = state_event(&device, "", "revoked", 0, OffsetDateTime::UNIX_EPOCH);
        OneShot::file_for_test(path.clone()).send(&event).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert_eq!(serde_json::from_str::<Value>(text.trim()).unwrap(), event);
    }

    #[test]
    fn event_contains_only_declared_results_and_selected_metadata() {
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        let claim = claim(&manifest);
        let event = event(
            &manifest,
            &claim,
            "",
            &["device revoked".into()],
            &[],
            None,
            &BTreeMap::new(),
        );
        let body = &event["open_pact"];
        assert_eq!(event.as_object().unwrap().len(), 1);
        assert_eq!(body["result_disk_encryption"], "full");
        assert_eq!(body["result_os_patch_age_days"], 31);
        assert!(body.get("result_firewall").is_none());
        assert_eq!(body["verdict"], "deny");
        assert!(body["access_until"].is_null());
        let until = open_pact_core::timestamp::parse_rfc3339("2026-11-17T10:20:00Z").unwrap();
        assert_eq!(
            super::event(
                &manifest,
                &claim,
                "",
                &[],
                &[],
                Some(until),
                &BTreeMap::new()
            )["open_pact"]["access_until"],
            "2026-11-17T10:20:00Z"
        );
        // The end is written in whole seconds and in UTC, whatever fraction or offset it had.
        let until =
            open_pact_core::timestamp::parse_rfc3339("2026-11-17T12:20:00.9+02:00").unwrap();
        assert_eq!(
            super::event(
                &manifest,
                &claim,
                "",
                &[],
                &[],
                Some(until),
                &BTreeMap::new()
            )["open_pact"]["access_until"],
            "2026-11-17T10:20:00Z"
        );
        assert_eq!(body["asserted_trust_level"], "L1");
        assert_eq!(body["verified_trust_level"], "L0");
        assert!(body.get("device_key").is_none());
        assert!(body.get("nonce").is_none());
        assert!(!event.to_string().contains("private_extra"));
        assert!(!event.to_string().contains("must not leave"));
        assert_eq!(
            super::event(&manifest, &claim, "", &[], &[], None, &BTreeMap::new())["open_pact"]["verdict"],
            "allow"
        );
    }

    fn claim_of(manifest: &Manifest, os: &str, results: Value) -> Claim {
        let key = PublicKey::from(&dev_key::generate());
        serde_json::from_value(json!({
            "manifest": manifest.hash(), "device": Pseudonym::of(&key), "device_key": key,
            "nonce": "fictional", "time": "2026-10-20T00:00:00Z", "client": "open-pact-client 0.2.0",
            "os": os, "trust_level": "L1", "results": results
        }))
        .unwrap()
    }

    fn at(text: &str) -> OffsetDateTime {
        open_pact_core::timestamp::parse_rfc3339(text).unwrap()
    }

    #[test]
    fn event_gives_each_supplied_control_a_status_and_a_deadline() {
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        let claim = claim_of(
            &manifest,
            "linux",
            json!({
                "disk_encryption": "full",
                "os_patch_age_days": 31,
                "screen_lock": "gt_15min",
                "firewall": "on",
                "process_audit": "n/a",
                "os_supported": "n/a",
            }),
        );
        let soon = at("2026-10-21T00:00:00Z");
        let later = at("2026-11-03T00:00:00Z");
        let standings = BTreeMap::from([
            ("disk_encryption".to_owned(), ControlStanding::Pass),
            ("os_patch_age_days".to_owned(), ControlStanding::Fail),
            (
                "screen_lock".to_owned(),
                ControlStanding::Warn {
                    deadline: Some(later),
                },
            ),
            // The gateway enforces this one, but the claim does not supply it.
            (
                "remote_wipe".to_owned(),
                ControlStanding::Warn {
                    deadline: Some(soon),
                },
            ),
            ("os_supported".to_owned(), ControlStanding::Pass),
        ]);
        let event = event(&manifest, &claim, "", &[], &[], None, &standings);
        let body = &event["open_pact"];
        for (id, status) in [
            ("disk_encryption", "pass"),
            ("os_patch_age_days", "fail"),
            ("screen_lock", "warn"),
            ("firewall", "report"),
            ("process_audit", "n/a"),
            ("os_supported", "n/a"),
        ] {
            assert_eq!(body[format!("status_{id}")], status, "{id}");
        }
        assert_eq!(
            body["result_screen_lock"], "gt_15min",
            "results stay as sent"
        );
        assert_eq!(body["deadline_screen_lock"], "2026-11-03T00:00:00Z");
        for id in [
            "disk_encryption",
            "os_patch_age_days",
            "firewall",
            "process_audit",
            "os_supported",
        ] {
            let field = body
                .get(format!("deadline_{id}"))
                .unwrap_or_else(|| panic!("deadline_{id} must be present as null, not omitted"));
            assert!(field.is_null(), "{id}");
        }
        assert!(body.get("status_remote_wipe").is_none());
        assert_eq!(
            body["access_ends"], "2026-10-21T00:00:00Z",
            "the earliest warn deadline of the evaluation"
        );
    }

    #[test]
    fn access_ends_is_null_without_a_warn_and_for_a_grace_that_never_ends() {
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        let claim = claim(&manifest);
        let none = event(
            &manifest,
            &claim,
            "",
            &[],
            &[],
            None,
            &BTreeMap::from([
                ("disk_encryption".to_owned(), ControlStanding::Pass),
                ("os_patch_age_days".to_owned(), ControlStanding::Fail),
            ]),
        );
        assert!(none["open_pact"]["access_ends"].is_null());
        let unbounded = event(
            &manifest,
            &claim,
            "",
            &[],
            &[],
            None,
            &BTreeMap::from([(
                "os_patch_age_days".to_owned(),
                ControlStanding::Warn { deadline: None },
            )]),
        );
        assert_eq!(unbounded["open_pact"]["status_os_patch_age_days"], "warn");
        assert!(unbounded["open_pact"]["deadline_os_patch_age_days"].is_null());
        assert!(unbounded["open_pact"]["access_ends"].is_null());
    }

    #[test]
    fn event_statuses_follow_the_gateway_evaluation() {
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        let claim = claim_of(
            &manifest,
            "linux",
            json!({
                "disk_encryption": "none",
                "firewall": "off",
                "os_supported": "no",
                "screen_lock": "le_5min",
                "os_patch_age_days": 12,
            }),
        );
        let now = at("2026-10-20T00:00:00Z");
        let evaluation = open_pact_core::evaluate(
            &manifest,
            &claim,
            now,
            &open_pact_core::FirstFailures::new(),
        );
        let event = event(&manifest, &claim, "", &[], &[], None, &evaluation.controls);
        let body = &event["open_pact"];
        assert_eq!(body["status_disk_encryption"], "fail", "grace 0d");
        assert!(body["deadline_disk_encryption"].is_null());
        assert_eq!(body["status_firewall"], "warn", "grace 1d");
        assert_eq!(body["deadline_firewall"], "2026-10-21T00:00:00Z");
        assert_eq!(body["status_os_supported"], "warn", "grace 14d");
        assert_eq!(body["deadline_os_supported"], "2026-11-03T00:00:00Z");
        assert_eq!(body["status_screen_lock"], "pass");
        assert_eq!(body["status_os_patch_age_days"], "pass");
        assert_eq!(body["access_ends"], "2026-10-21T00:00:00Z");

        let late = at("2026-10-22T00:00:00Z");
        let first = open_pact_core::FirstFailures::from([("firewall".to_owned(), now)]);
        let ended = open_pact_core::evaluate(&manifest, &claim, late, &first);
        let event = super::event(&manifest, &claim, "", &[], &[], None, &ended.controls);
        assert_eq!(
            event["open_pact"]["status_firewall"], "fail",
            "the grace is over"
        );
        assert!(event["open_pact"]["deadline_firewall"].is_null());
    }

    #[test]
    fn framing_counts_utf8_octets_without_newline() {
        let framed = frame("{\"open_pact\":\"é\"}".as_bytes());
        let split = framed.iter().position(|b| *b == b' ').unwrap();
        let count: usize = std::str::from_utf8(&framed[..split])
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(count, framed.len() - split - 1);
        assert!(framed[split + 1..].starts_with(b"<134>1 - - open-pact - status - {"));
        assert_eq!(framed.last(), Some(&b'}'));
    }

    #[test]
    fn overflow_drops_oldest_and_counts_it() {
        let exporter = Exporter(Arc::default());
        for n in 0..CAPACITY + 3 {
            exporter.submit(json!(n));
        }
        let queue = exporter.0.queue.lock().unwrap();
        assert_eq!(queue.events.len(), CAPACITY);
        assert_eq!(
            serde_json::from_slice::<Value>(&queue.events.front().unwrap().1).unwrap(),
            3
        );
        assert_eq!(exporter.0.dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn file_mode_defaults_to_owner_only_and_validates_group_read_opt_in() {
        assert_eq!(FileMode::default(), FileMode::OwnerOnly);
        assert_eq!(FileMode::parse("0640").unwrap(), FileMode::GroupReadable);
        assert!(FileMode::parse("0660").is_err());
    }

    #[test]
    fn file_sink_appends_one_json_object_per_line() {
        let path = temporary();
        let sink = Sink::File {
            path: path.clone(),
            mode: FileMode::default(),
        };
        let event = json!({"open_pact": {"verdict": "deny"}}).to_string();
        sink.deliver(event.as_bytes()).unwrap();
        sink.deliver(event.as_bytes()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{event}\n{event}\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let rotated = path.with_extension("jsonl.1");
        std::fs::rename(&path, &rotated).unwrap();
        sink.deliver(event.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(rotated).unwrap();
    }

    #[test]
    fn retry_separates_an_event_after_an_injected_partial_write() {
        let event = json!({"open_pact": {"verdict": "allow"}});
        let bytes = serde_json::to_vec(&event).unwrap();
        let mut writer = PartialWriter {
            data: Cursor::default(),
            remaining: 12,
            failed: false,
        };
        assert!(append_json_line(&mut writer, &bytes).is_err());
        append_json_line(&mut writer, &bytes).unwrap();
        let contents = String::from_utf8(writer.data.into_inner()).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(serde_json::from_str::<Value>(lines[0]).is_err());
        assert_eq!(serde_json::from_str::<Value>(lines[1]).unwrap(), event);
    }

    #[test]
    fn queue_drops_are_reported_while_delivery_is_blocked() {
        let blocker = Arc::new(BlockingSink::new());
        let exporter = Exporter::start_with_report_interval(
            Sink::Blocking(blocker.clone()),
            Duration::from_millis(10),
        )
        .unwrap();
        exporter.submit(json!({"sequence": 0}));
        blocker.wait_until_started();
        for sequence in 1..=CAPACITY {
            exporter.submit(json!({"sequence": sequence}));
        }
        assert_eq!(exporter.0.dropped.load(Ordering::Relaxed), 1);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while exporter.0.reported_drops.load(Ordering::Relaxed) == 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(exporter.0.reported_drops.load(Ordering::Relaxed), 1);
        blocker.release();
    }

    fn server() -> (String, String, std::thread::JoinHandle<Vec<u8>>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = cert.cert.pem();
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
                )
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("tls://localhost:{}", listener.local_addr().unwrap().port());
        let task = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            tcp.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
            let mut stream =
                StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), tcp);
            let mut bytes = vec![];
            let _ = stream.read_to_end(&mut bytes);
            bytes
        });
        (url, ca, task)
    }

    #[test]
    fn tls_sink_sends_rfc5425_to_a_pinned_server() {
        let (url, ca, task) = server();
        let path = temporary();
        std::fs::write(&path, ca).unwrap();
        let sink = Sink::tls(&url, path.to_str().unwrap()).unwrap();
        let event = br#"{"open_pact":{"verdict":"allow"}}"#;
        sink.deliver(event).unwrap();
        assert_eq!(task.join().unwrap(), frame(event));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn tls_sink_rejects_an_untrusted_server_and_plaintext_urls() {
        let (url, _, task) = server();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let path = temporary();
        std::fs::write(&path, other.cert.pem()).unwrap();
        assert!(
            Sink::tls(&url, path.to_str().unwrap())
                .unwrap()
                .deliver(b"{}")
                .is_err()
        );
        assert!(task.join().unwrap().is_empty());
        assert!(Sink::tls("tcp://localhost:514", path.to_str().unwrap()).is_err());
        assert!(Sink::tls("tls://localhost:6514/path", path.to_str().unwrap()).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn tls_sink_checks_the_receiver_name() {
        let (url, ca, task) = server();
        let path = temporary();
        std::fs::write(&path, ca).unwrap();
        let url = url.replace("localhost", "127.0.0.1");
        assert!(
            Sink::tls(&url, path.to_str().unwrap())
                .unwrap()
                .deliver(b"{}")
                .is_err()
        );
        assert!(task.join().unwrap().is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn worker_retries_failed_file_delivery() {
        let directory = temporary();
        let path = directory.join("events.jsonl");
        let exporter = Exporter::start(Sink::File {
            path: path.clone(),
            mode: FileMode::default(),
        })
        .unwrap();
        exporter.submit(json!({"open_pact": {"verdict": "allow"}}));
        std::thread::sleep(Duration::from_millis(100));
        std::fs::create_dir(&directory).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut delivered = None;
        while delivered.is_none() && std::time::Instant::now() < deadline {
            delivered = std::fs::read_to_string(&path)
                .ok()
                .and_then(|contents| serde_json::from_str::<Value>(&contents).ok());
            if delivered.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(delivered.unwrap()["open_pact"]["verdict"], "allow");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
