#![allow(dead_code)]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub time: String,
    pub sent_b64: String,
    pub sent_sha256: String,
    pub response_b64: String,
    pub response_sha256: String,
}

impl Record {
    pub fn sent(&self) -> io::Result<Vec<u8>> {
        decode(&self.sent_b64, &self.sent_sha256)
    }

    pub fn response(&self) -> io::Result<Vec<u8>> {
        decode(&self.response_b64, &self.response_sha256)
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn decode(b64: &str, sha256: &str) -> io::Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| invalid(format!("bad base64: {e}")))?;
    if hex::encode(Sha256::digest(&bytes)) != sha256 {
        return Err(invalid("sha256 mismatch"));
    }
    Ok(bytes)
}

pub fn append(path: &Path, sent_bytes: &[u8], response_bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let record = Record {
        time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        sent_b64: STANDARD.encode(sent_bytes),
        sent_sha256: hex::encode(Sha256::digest(sent_bytes)),
        response_b64: STANDARD.encode(response_bytes),
        response_sha256: hex::encode(Sha256::digest(response_bytes)),
    };
    let mut line = serde_json::to_vec(&record).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&line)?;
    file.sync_all()
}

pub fn read(path: &Path) -> io::Result<Vec<Record>> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, line)| {
            let record: Record =
                serde_json::from_str(line).map_err(|e| invalid(format!("line {}: {e}", i + 1)))?;
            record
                .sent()
                .and_then(|_| record.response())
                .map_err(|e| invalid(format!("line {}: {e}", i + 1)))?;
            Ok(record)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_then_read_returns_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/log.jsonl");
        let sent = b"{\"results\":{\"firewall\":\"on\"}}\x00\xff";
        let response = b"{\"ok\":true}\n";
        append(&path, sent, response).unwrap();
        append(&path, b"second", b"").unwrap();

        let records = read(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sent().unwrap(), sent);
        assert_eq!(records[0].response().unwrap(), response);
        assert_eq!(records[1].sent().unwrap(), b"second");
        assert_eq!(records[1].response().unwrap(), b"");
        assert_eq!(
            records[1].sent_sha256,
            "16367aacb67a4a017c8da8ab95682ccb390863780f7114dda0a0e0c55644c7c4"
        );
    }

    #[test]
    fn file_is_one_json_object_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        append(&path, b"a", b"b").unwrap();
        append(&path, b"c", b"d").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'));
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
    }

    #[test]
    fn append_never_rewrites_earlier_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        append(&path, b"a", b"b").unwrap();
        let first = fs::read_to_string(&path).unwrap();
        append(&path, b"c", b"d").unwrap();
        assert!(fs::read_to_string(&path).unwrap().starts_with(&first));
    }

    #[test]
    fn missing_file_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(&dir.path().join("none.jsonl")).unwrap().is_empty());
    }

    #[test]
    fn tampered_bytes_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        append(&path, b"original", b"resp").unwrap();
        let tampered = fs::read_to_string(&path)
            .unwrap()
            .replace(&STANDARD.encode(b"original"), &STANDARD.encode(b"changed!"));
        fs::write(&path, tampered).unwrap();
        let err = read(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
