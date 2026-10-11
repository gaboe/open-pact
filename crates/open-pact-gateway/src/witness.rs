//! Sends each checkpoint to the witnesses in WITNESS_URLS with the c2sp.org/tlog-witness
//! add-checkpoint call and keeps the cosignatures from the witnesses the manifest names.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use open_pact_core::{
    AddCheckpoint, Checkpoint, LogHash, LogPolicy, Note, NoteSignature, WitnessKey,
    consistency_proof,
};
use reqwest::StatusCode;
use tokio::sync::Mutex;

pub struct Witnesses {
    urls: Vec<String>,
    keys: Vec<WitnessKey>,
    pub quorum: usize,
    http: reqwest::Client,
    /// The size each witness last cosigned. The lock also keeps pushes in order.
    cosigned: Mutex<HashMap<String, u64>>,
    last_retry: std::sync::Mutex<Option<Instant>>,
}

/// How often a request may retry a push that left the checkpoint short of its quorum. A slow
/// witness then delays one request in this interval, not every request.
const RETRY_EVERY: Duration = Duration::from_secs(30);

impl Witnesses {
    pub fn new(urls: Vec<String>, policy: Option<&LogPolicy>) -> anyhow::Result<Witnesses> {
        Ok(Witnesses {
            urls: urls
                .into_iter()
                .map(|u| u.trim_end_matches('/').to_string())
                .collect(),
            keys: policy.map_or(vec![], |p| {
                p.witnesses.iter().map(|w| w.key.clone()).collect()
            }),
            quorum: policy.map_or(0, |p| p.witness_quorum),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
            cosigned: Mutex::default(),
            last_retry: std::sync::Mutex::default(),
        })
    }

    pub fn keys(&self) -> &[WitnessKey] {
        &self.keys
    }

    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Whether a request may retry pushing now; at most once per RETRY_EVERY.
    pub fn retry_due(&self) -> bool {
        let mut last = self.last_retry.lock().expect("witness retry time");
        let due = last.is_none_or(|t| t.elapsed() >= RETRY_EVERY);
        if due {
            *last = Some(Instant::now());
        }
        due
    }

    /// Waits until no push is in flight.
    pub async fn settled(&self) {
        drop(self.cosigned.lock().await);
    }

    /// Asks every witness to cosign `cp`, whose tree has `leaves`. Returns the witness name and
    /// cosignature for each one that a manifest witness key verifies. Failures are logged.
    pub async fn cosign(
        &self,
        note: &Note,
        cp: &Checkpoint,
        leaves: &[LogHash],
    ) -> Vec<(String, NoteSignature)> {
        let mut cosigned = self.cosigned.lock().await;
        let mut valid = vec![];
        for url in &self.urls {
            let mut old = cosigned.get(url).copied().unwrap_or(0);
            // One retry: a 409 tells the size the witness holds.
            for _ in 0..2 {
                match self.add_checkpoint(url, note, cp, leaves, old).await {
                    Ok(Pushed::Cosigned(sigs)) => {
                        cosigned.insert(url.clone(), cp.size);
                        valid.extend(self.verified(url, cp, &sigs));
                        break;
                    }
                    Ok(Pushed::Conflict(size)) if size <= cp.size && size != old => {
                        cosigned.insert(url.clone(), size);
                        old = size;
                    }
                    Ok(Pushed::Conflict(size)) => {
                        eprintln!(
                            "witness {url} holds size {size}, this log has {}: it saw another history",
                            cp.size
                        );
                        break;
                    }
                    Err(e) => {
                        eprintln!("witness {url} did not cosign size {}: {e:#}", cp.size);
                        break;
                    }
                }
            }
        }
        valid
    }

    fn verified(
        &self,
        url: &str,
        cp: &Checkpoint,
        sigs: &[NoteSignature],
    ) -> Vec<(String, NoteSignature)> {
        let valid: Vec<(String, NoteSignature)> = sigs
            .iter()
            .filter_map(|sig| {
                self.keys
                    .iter()
                    .find(|k| matches!(k.verify(cp, sig), Some(Ok(_))))
                    .map(|k| (k.name().to_string(), sig.clone()))
            })
            .collect();
        if valid.is_empty() {
            eprintln!("witness {url} answered without a cosignature from a manifest witness key");
        }
        valid
    }

    async fn add_checkpoint(
        &self,
        url: &str,
        note: &Note,
        cp: &Checkpoint,
        leaves: &[LogHash],
        old: u64,
    ) -> anyhow::Result<Pushed> {
        let old = if old > cp.size { 0 } else { old };
        let proof = if old == 0 || old == cp.size {
            vec![]
        } else {
            consistency_proof(leaves, old)?
        };
        let body = AddCheckpoint {
            old_size: old,
            proof,
            note: note.clone(),
        };
        let resp = self
            .http
            .post(format!("{url}/add-checkpoint"))
            .body(body.to_string())
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        match status {
            StatusCode::OK => Ok(Pushed::Cosigned(
                text.lines()
                    .map(NoteSignature::parse)
                    .collect::<Result<_, _>>()?,
            )),
            StatusCode::CONFLICT => Ok(Pushed::Conflict(text.trim().parse()?)),
            _ => anyhow::bail!("{status}: {}", text.trim()),
        }
    }
}

enum Pushed {
    Cosigned(Vec<NoteSignature>),
    Conflict(u64),
}
