//! A scripted HTTP gateway for client tests. It records every request line it receives.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use open_pact_core::{
    Checkpoint, Endorsement, Entry, LogHash, LogKey, Manifest, Note, PublicKey, SigningKey,
    WitnessKey, consistency_proof, dev_key, root,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const DEMO_MANIFEST: &str = include_str!("../../../examples/manifest.toml");

/// A full scripted answer: status, body and extra headers.
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Reply {
            status,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// A raw request target and its `policy` parameter.
type Target = (String, Option<String>);

type RespondFull = dyn Fn(&str, usize) -> Reply + Send + Sync;

pub struct FakeGateway {
    pub url: String,
    requests: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<(String, String)>>>,
    /// The raw request target of every request, and its `policy` parameter if it had one.
    targets: Arc<Mutex<Vec<Target>>>,
}

impl FakeGateway {
    pub async fn start(
        respond: impl Fn(&str, usize) -> (u16, String) + Send + Sync + 'static,
    ) -> Self {
        Self::start_with(move |line, nth| {
            let (status, body) = respond(line, nth);
            Reply::new(status, body)
        })
        .await
    }

    /// Like `start`, with headers. The `policy` query parameter is cut from the
    /// request line the closure sees; `policies` and `targets` keep it.
    pub async fn start_with(
        respond: impl Fn(&str, usize) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let respond: Arc<RespondFull> = Arc::new(respond);
        let seen = requests.clone();
        let sent = bodies.clone();
        let raw = targets.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (seen, sent, respond, raw) =
                    (seen.clone(), sent.clone(), respond.clone(), raw.clone());
                tokio::spawn(async move {
                    let Some((target, body)) = read_request(&mut stream).await else {
                        return;
                    };
                    let (line, policy) = split_policy(&target);
                    raw.lock().unwrap().push((target, policy));
                    sent.lock().unwrap().push((line.clone(), body));
                    let nth = {
                        let mut seen = seen.lock().unwrap();
                        let nth = seen.iter().filter(|l| **l == line).count();
                        seen.push(line.clone());
                        nth
                    };
                    let Reply {
                        status,
                        body,
                        headers,
                    } = respond(&line, nth);
                    if status == 0 {
                        return;
                    }
                    let extra: String = headers
                        .iter()
                        .map(|(k, v)| format!("{k}: {v}\r\n"))
                        .collect();
                    let reply = format!(
                        "HTTP/1.1 {} X\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        if status == 598 { 200 } else { status },
                        if status == 598 { 100 } else { body.len() }
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
        FakeGateway {
            url,
            requests,
            bodies,
            targets,
        }
    }

    /// The `policy` parameter of every request that had one, in order.
    pub fn policies(&self) -> Vec<String> {
        self.targets
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, p)| p.clone())
            .collect()
    }

    /// The raw request target (path and query) of every request, in order.
    pub fn targets(&self) -> Vec<String> {
        self.targets
            .lock()
            .unwrap()
            .iter()
            .map(|(t, _)| t.clone())
            .collect()
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// The bodies of every request with this request line, in order.
    pub fn bodies(&self, line: &str) -> Vec<String> {
        self.bodies
            .lock()
            .unwrap()
            .iter()
            .filter(|(l, _)| l == line)
            .map(|(_, body)| body.clone())
            .collect()
    }

    /// Every request that is not a GET, i.e. everything that sends data to the gateway.
    pub fn posts(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .filter(|l| !l.starts_with("GET "))
            .collect()
    }
}

/// Cuts the `policy` parameter from `METHOD /path?query`; the rest of the line stays.
fn split_policy(target: &str) -> (String, Option<String>) {
    let Some((head, query)) = target.split_once('?') else {
        return (target.to_string(), None);
    };
    let mut policy = None;
    let rest: Vec<&str> = query
        .split('&')
        .filter(|kv| match kv.strip_prefix("policy=") {
            Some(v) => {
                policy = Some(v.to_string());
                false
            }
            None => true,
        })
        .collect();
    if rest.is_empty() {
        (head.to_string(), policy)
    } else {
        (format!("{head}?{}", rest.join("&")), policy)
    }
}

/// The request line without the HTTP version, and the body.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<(String, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buf.len() < header_end + length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let first = head.lines().next()?;
    let body = String::from_utf8_lossy(&buf[header_end..]).into_owned();
    Some((first.rsplit_once(' ')?.0.to_string(), body))
}

/// The company and log keys of an honest gateway, and what it publishes.
pub struct Company {
    pub key: SigningKey,
    pub log: LogKey,
    log_signer: SigningKey,
}

impl Company {
    pub fn new() -> Self {
        let log_signer = dev_key::generate();
        Company {
            key: dev_key::generate(),
            log: LogKey::new("pact.example.com/log", &PublicKey::from(&log_signer)),
            log_signer,
        }
    }

    /// The body of `GET /v1/log/checkpoint` for an empty log.
    pub fn empty_checkpoint(&self) -> String {
        let checkpoint = Checkpoint {
            origin: self.log.origin().into(),
            size: 0,
            root: root(&[]),
        };
        self.log.sign(&self.log_signer, &checkpoint).to_string()
    }

    /// A checkpoint note for `checkpoint`, signed with the log key.
    pub fn sign(&self, checkpoint: &Checkpoint) -> Note {
        self.log.sign(&self.log_signer, checkpoint)
    }

    pub fn fingerprint(&self) -> String {
        PublicKey::from(&self.key).fingerprint()
    }

    /// The body of `GET /v1/manifest` for `toml`, signed by `key`.
    pub fn published(toml: &str, key: &SigningKey) -> String {
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        json!({"toml": toml, "company": Endorsement::sign(key, manifest.hash())}).to_string()
    }
}

pub fn not_found() -> (u16, String) {
    (404, "{}".into())
}

/// Every file directly in `dir`, read through links, with its contents. The claim lock holds no
/// data and is left out.
pub fn snapshot(dir: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| !e.path().is_dir() && e.file_name() != "claim.lock")
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

/// A witness with its own key, as a manifest's [log] section lists it.
pub struct Witness {
    pub key: WitnessKey,
    signer: ed25519_dalek::SigningKey,
}

impl Witness {
    pub fn new() -> Self {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        Witness {
            key: WitnessKey::new("witness.example.org/test", signer.verifying_key()),
            signer,
        }
    }

    /// Adds a cosignature made at Unix time `at`.
    pub fn cosign(&self, note: &mut Note, at: u64) {
        let checkpoint = Checkpoint::parse(&note.text).unwrap();
        note.signatures
            .push(self.key.cosign(&self.signer, &checkpoint, at));
    }
}

/// The Merkle checkpoint of the first `size` entries.
pub fn checkpoint_of(origin: &str, entries: &[Entry], size: u64) -> Checkpoint {
    Checkpoint {
        origin: origin.into(),
        size,
        root: root(&leaves(&entries[..size as usize])),
    }
}

fn leaves(entries: &[Entry]) -> Vec<LogHash> {
    entries.iter().map(Entry::leaf_hash).collect()
}

/// Answers public consistency proof requests. Returns `None` for other requests.
pub fn serve_log(entries: &[Entry], line: &str) -> Option<(u16, String)> {
    let (path, query) = line.strip_prefix("GET ")?.split_once('?')?;
    let arg = |name: &str| -> Option<u64> {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))?
            .parse()
            .ok()
    };
    let body = match path {
        "/v1/log/proof/consistency" => {
            let to = arg("to")? as usize;
            json!({ "proof": consistency_proof(&leaves(entries.get(..to)?), arg("from")?).ok()? })
        }
        _ => return None,
    };
    Some((200, body.to_string()))
}
