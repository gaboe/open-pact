use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{Error, PublicKey, Signature, SigningKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LogHash([u8; 32]);

impl LogHash {
    pub const GENESIS: LogHash = LogHash([0; 32]);
}

impl TryFrom<String> for LogHash {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let mut bytes = [0; 32];
        match hex::decode_to_slice(&s, &mut bytes) {
            Ok(()) if s.bytes().all(|b| !b.is_ascii_uppercase()) => Ok(Self(bytes)),
            _ => Err(format!("expected 64 lowercase hex, got {s:?}")),
        }
    }
}

impl From<LogHash> for String {
    fn from(h: LogHash) -> String {
        h.to_string()
    }
}

impl fmt::Display for LogHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    ManifestPublished,
    DeviceEnrolled,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryKind::ManifestPublished => "manifest_published",
            EntryKind::DeviceEnrolled => "device_enrolled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub index: u64,
    pub kind: EntryKind,
    pub data: Value,
    pub prev_hash: LogHash,
    pub hash: LogHash,
}

impl Entry {
    pub fn new(index: u64, kind: EntryKind, data: Value, prev_hash: LogHash) -> Self {
        let hash = Self::hash_of(index, kind, &data, &prev_hash);
        Entry {
            index,
            kind,
            data,
            prev_hash,
            hash,
        }
    }

    pub fn first(kind: EntryKind, data: Value) -> Self {
        Self::new(0, kind, data, LogHash::GENESIS)
    }

    pub fn next(&self, kind: EntryKind, data: Value) -> Self {
        Self::new(self.index + 1, kind, data, self.hash)
    }

    fn hash_of(index: u64, kind: EntryKind, data: &Value, prev_hash: &LogHash) -> LogHash {
        let body = json!({"index": index, "kind": kind, "data": data});
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.0);
        hasher.update(serde_jcs::to_vec(&body).expect("entry body always serializes"));
        LogHash(hasher.finalize().into())
    }
}

/// The gateway signs `"{index}:{hash}"` so contractors can compare heads and prove a split view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub index: u64,
    pub hash: LogHash,
    pub signature: Signature,
    pub key: PublicKey,
}

impl Head {
    fn message(index: u64, hash: &LogHash) -> String {
        format!("{index}:{hash}")
    }

    pub fn sign(key: &SigningKey, last: &Entry) -> Self {
        Head {
            index: last.index,
            hash: last.hash,
            signature: Signature::sign(key, Self::message(last.index, &last.hash).as_bytes()),
            key: PublicKey::from(key),
        }
    }

    pub fn verify(&self) -> bool {
        self.key.verify(
            Self::message(self.index, &self.hash).as_bytes(),
            &self.signature,
        )
    }
}

fn broken(msg: String) -> Error {
    Error::Log(msg)
}

/// `prev` is the head the client already verified; `None` means a full download from index 0 that pins the log key.
pub fn verify_chain(prev: Option<&Head>, entries: &[Entry], head: &Head) -> Result<Head, Error> {
    if let Some(p) = prev
        && head.key != p.key
    {
        return Err(broken("log key changed".into()));
    }
    if !head.verify() {
        return Err(Error::BadSignature("log head"));
    }
    let (mut next, mut hash) = match prev {
        Some(p) => (p.index + 1, p.hash),
        None => (0, LogHash::GENESIS),
    };
    for e in entries {
        if e.index != next {
            return Err(broken(format!("entry {} where {next} expected", e.index)));
        }
        if e.prev_hash != hash {
            return Err(broken(format!(
                "entry {} does not extend the history this client holds",
                e.index
            )));
        }
        if e.hash != Entry::hash_of(e.index, e.kind, &e.data, &e.prev_hash) {
            return Err(broken(format!(
                "entry {} hash does not match its content",
                e.index
            )));
        }
        hash = e.hash;
        next += 1;
    }
    match next.checked_sub(1) {
        Some(last) if head.index == last && head.hash == hash => Ok(head.clone()),
        _ => Err(broken(format!(
            "signed head {}:{} does not match the verified entries",
            head.index, head.hash
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_key;

    fn chain(len: usize) -> Vec<Entry> {
        let mut entries = vec![Entry::first(
            EntryKind::ManifestPublished,
            json!({"manifest": "sha256:00"}),
        )];
        while entries.len() < len {
            let n = entries.len();
            let e = entries[n - 1].next(EntryKind::DeviceEnrolled, json!({"commitment": n}));
            entries.push(e);
        }
        entries
    }

    fn fails(prev: Option<&Head>, entries: &[Entry], head: &Head) -> String {
        verify_chain(prev, entries, head).unwrap_err().to_string()
    }

    #[test]
    fn hash_is_sha256_of_prev_hash_and_canonical_body() {
        let e = Entry::first(EntryKind::ManifestPublished, json!({"manifest": "m"}));
        let mut hasher = Sha256::new();
        hasher.update([0u8; 32]);
        hasher.update(br#"{"data":{"manifest":"m"},"index":0,"kind":"manifest_published"}"#);
        assert_eq!(e.hash.0, <[u8; 32]>::from(hasher.finalize()));
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["prev_hash"], "0".repeat(64));
        assert_eq!(serde_json::from_value::<Entry>(json).unwrap(), e);
    }

    #[test]
    fn verifies_full_download_then_increment() {
        let key = dev_key::generate();
        let entries = chain(5);
        let first = verify_chain(None, &entries[..3], &Head::sign(&key, &entries[2])).unwrap();
        assert_eq!(first.index, 2);
        let second =
            verify_chain(Some(&first), &entries[3..], &Head::sign(&key, &entries[4])).unwrap();
        assert_eq!((second.index, second.hash), (4, entries[4].hash));
        assert_eq!(verify_chain(Some(&second), &[], &second).unwrap(), second);
    }

    #[test]
    fn rejects_tampered_entry() {
        let key = dev_key::generate();
        let mut entries = chain(3);
        let head = Head::sign(&key, &entries[2]);
        entries[1].data = json!({"commitment": "other"});
        assert_eq!(
            fails(None, &entries, &head),
            "transparency log: entry 1 hash does not match its content"
        );
    }

    #[test]
    fn rejects_reordered_entries() {
        let key = dev_key::generate();
        let mut entries = chain(3);
        let head = Head::sign(&key, &entries[2]);
        entries.swap(1, 2);
        assert_eq!(
            fails(None, &entries, &head),
            "transparency log: entry 2 where 1 expected"
        );
    }

    #[test]
    fn rejects_gap() {
        let key = dev_key::generate();
        let entries = chain(4);
        let head = Head::sign(&key, &entries[3]);
        let gapped = [entries[0].clone(), entries[2].clone(), entries[3].clone()];
        assert_eq!(
            fails(None, &gapped, &head),
            "transparency log: entry 2 where 1 expected"
        );
        let known = Head::sign(&key, &entries[0]);
        assert_eq!(
            fails(Some(&known), &entries[2..], &head),
            "transparency log: entry 2 where 1 expected"
        );
    }

    #[test]
    fn rejects_bad_head_signature() {
        let key = dev_key::generate();
        let entries = chain(2);
        let mut head = Head::sign(&key, &entries[1]);
        head.signature = Head::sign(&dev_key::generate(), &entries[1]).signature;
        assert_eq!(
            fails(None, &entries, &head),
            "signature does not verify: log head"
        );
    }

    #[test]
    fn rejects_head_that_does_not_match_entries() {
        let key = dev_key::generate();
        let entries = chain(3);
        let stale = Head::sign(&key, &entries[1]);
        assert!(fails(None, &entries, &stale).contains("does not match the verified entries"));
        let known = Head::sign(&key, &entries[2]);
        assert!(fails(Some(&known), &[], &stale).contains("does not match the verified entries"));
    }

    #[test]
    fn rejects_rewritten_history_signed_by_the_same_key() {
        let key = dev_key::generate();
        let honest = chain(3);
        let known = Head::sign(&key, &honest[2]);
        let f1 = honest[0].next(EntryKind::DeviceEnrolled, json!({"commitment": "forged"}));
        let f2 = f1.next(EntryKind::DeviceEnrolled, json!({}));
        let extra = f2.next(EntryKind::DeviceEnrolled, json!({}));
        assert_eq!(
            fails(Some(&known), &[extra.clone()], &Head::sign(&key, &extra)),
            "transparency log: entry 3 does not extend the history this client holds"
        );
    }

    #[test]
    fn rejects_new_log_key() {
        let entries = chain(2);
        let known = Head::sign(&dev_key::generate(), &entries[0]);
        let head = Head::sign(&dev_key::generate(), &entries[1]);
        assert_eq!(
            fails(Some(&known), &entries[1..], &head),
            "transparency log: log key changed"
        );
    }
}
