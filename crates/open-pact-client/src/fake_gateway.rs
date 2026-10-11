//! A scripted HTTP gateway for client tests. It records every request line it receives.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use open_pact_core::{
    Checkpoint, Endorsement, LogKey, Manifest, PublicKey, SigningKey, dev_key, root,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const DEMO_MANIFEST: &str = include_str!("../../../examples/manifest.toml");

/// Answers a request line such as `GET /v1/manifest`; `nth` counts earlier requests with the same line.
pub type Respond = dyn Fn(&str, usize) -> (u16, String) + Send + Sync;

pub struct FakeGateway {
    pub url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl FakeGateway {
    pub async fn start(
        respond: impl Fn(&str, usize) -> (u16, String) + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let respond: Arc<Respond> = Arc::new(respond);
        let seen = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (seen, respond) = (seen.clone(), respond.clone());
                tokio::spawn(async move {
                    let Some(line) = read_request(&mut stream).await else {
                        return;
                    };
                    let nth = {
                        let mut seen = seen.lock().unwrap();
                        let nth = seen.iter().filter(|l| **l == line).count();
                        seen.push(line.clone());
                        nth
                    };
                    let (status, body) = respond(&line, nth);
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
        FakeGateway { url, requests }
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// Every request that is not a GET, i.e. everything that sends data to the gateway.
    pub fn posts(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .filter(|l| !l.starts_with("GET "))
            .collect()
    }
}

/// The request line without the HTTP version, after reading headers and body.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<String> {
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
    Some(first.rsplit_once(' ')?.0.to_string())
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

/// Every file under `dir` with its contents.
pub fn snapshot(dir: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}
