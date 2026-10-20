use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{BufReader, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, bail};
use open_pact_core::{Claim, Manifest, verified_trust_level};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serde_json::{Value, json};

const CAPACITY: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// Control values keep their original JSON type. Prefixing avoids collisions with event metadata.
pub fn event(manifest: &Manifest, claim: &Claim, reasons: &[String], warnings: &[String]) -> Value {
    let mut body = json!({
        "schema_version": 1,
        "time": claim.time,
        "device_pseudonym": claim.device,
        "manifest_hash": claim.manifest,
        "client_version": claim.client,
        "os": claim.os,
        "verified_trust_level": verified_trust_level(claim),
        "asserted_trust_level": claim.trust_level,
        "verdict": if reasons.is_empty() { "allow" } else { "deny" },
        "reasons": reasons,
        "warnings": warnings,
    });
    for control in &manifest.body().controls {
        if let Some(value) = claim.results.get(&control.id) {
            body[format!("result_{}", control.id)] = json!(value);
        }
    }
    json!({"open_pact": body})
}

// RFC 5425 counts the UTF-8 bytes of the entire RFC 5424 message, excluding the prefix.
fn frame(json: &[u8]) -> Vec<u8> {
    let mut message = b"<134>1 - - open-pact - status - ".to_vec();
    message.extend_from_slice(json);
    let mut framed = format!("{} ", message.len()).into_bytes();
    framed.extend(message);
    framed
}

enum Sink {
    File(std::path::PathBuf),
    Tls {
        host: String,
        port: u16,
        name: ServerName<'static>,
        config: Arc<ClientConfig>,
    },
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
            Self::File(path) => {
                let mut line = json.to_vec();
                line.push(b'\n');
                let mut file = OpenOptions::new().create(true).append(true).open(path)?;
                file.write_all(&line)?;
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
        }
        Ok(())
    }
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
}

#[derive(Clone)]
pub struct Exporter(Arc<Shared>);

impl Exporter {
    fn start(sink: Sink) -> anyhow::Result<Self> {
        let exporter = Self(Arc::default());
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
        let mut reported_drops = 0;
        loop {
            let dropped = self.0.dropped.load(Ordering::Relaxed);
            if dropped != reported_drops {
                eprintln!(
                    "WARNING: SIEM queue full, dropped oldest events; siem_dropped_total={dropped}"
                );
                reported_drops = dropped;
            }
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

fn configured(manifest: &Manifest) -> anyhow::Result<Option<Exporter>> {
    let url = std::env::var("GATEWAY_SIEM_SYSLOG_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let file = std::env::var("GATEWAY_SIEM_FILE")
        .ok()
        .filter(|s| !s.is_empty());
    let sink = match (url, file) {
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => bail!("configure only one SIEM sink"),
        (Some(url), None) => Sink::tls(&url, &std::env::var("GATEWAY_SIEM_CA")?)?,
        (None, Some(path)) => Sink::File(path.into()),
    };
    if let Ok(days) = std::env::var("GATEWAY_SIEM_RETENTION_DAYS") {
        let days: i64 = days
            .parse()
            .context("SIEM retention must be whole nonnegative days")?;
        if days < 0 {
            bail!("SIEM retention must be nonnegative");
        }
        let now = chrono::Utc::now();
        let deadline = chrono::Duration::try_days(days)
            .and_then(|d| now.checked_add_signed(d))
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
    use std::{io::Read, net::TcpListener};

    fn temporary() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("open-pact-siem-{:032x}", rand::random::<u128>()))
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
    fn event_contains_only_declared_results_and_selected_metadata() {
        let manifest = Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap();
        let claim = claim(&manifest);
        let event = event(&manifest, &claim, &["device revoked".into()], &[]);
        let body = &event["open_pact"];
        assert_eq!(event.as_object().unwrap().len(), 1);
        assert_eq!(body["result_disk_encryption"], "full");
        assert_eq!(body["result_os_patch_age_days"], 31);
        assert!(body.get("result_firewall").is_none());
        assert_eq!(body["verdict"], "deny");
        assert_eq!(body["asserted_trust_level"], "L1");
        assert_eq!(body["verified_trust_level"], "L0");
        assert!(body.get("device_key").is_none());
        assert!(body.get("nonce").is_none());
        assert!(!event.to_string().contains("private_extra"));
        assert!(!event.to_string().contains("must not leave"));
        assert_eq!(
            super::event(&manifest, &claim, &[], &[])["open_pact"]["verdict"],
            "allow"
        );
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
    fn file_sink_appends_one_json_object_per_line() {
        let path = temporary();
        let sink = Sink::File(path.clone());
        let event = json!({"open_pact": {"verdict": "deny"}}).to_string();
        sink.deliver(event.as_bytes()).unwrap();
        sink.deliver(event.as_bytes()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{event}\n{event}\n")
        );
        std::fs::remove_file(path).unwrap();
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
        let exporter = Exporter::start(Sink::File(path.clone())).unwrap();
        exporter.submit(json!({"open_pact": {"verdict": "allow"}}));
        std::thread::sleep(Duration::from_millis(100));
        std::fs::create_dir(&directory).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["open_pact"]["verdict"], "allow");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
