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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
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
    let record = make_record(sent_bytes, response_bytes, None);
    let mut line = serde_json::to_vec(&record).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&line)?;
    file.sync_all()
}

pub fn append_report_retained(
    path: &Path,
    state_path: &Path,
    sent_bytes: &[u8],
    response_bytes: &[u8],
    status: u16,
) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let lock_path = path.with_extension("jsonl.lock");
    let mut lock_options = OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    let lock = lock_options.open(lock_path)?;
    lock.lock()?;
    let mut records = read(path)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::days(90);
    records.retain(|record| {
        chrono::DateTime::parse_from_rfc3339(&record.time).map_or(true, |time| time >= cutoff)
    });
    records.push(make_record(sent_bytes, response_bytes, Some(status)));

    let temp = path.with_extension("jsonl.tmp");
    let _ = fs::remove_file(&temp);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mode = fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o600)
            .unwrap_or(0o600)
            & fs::metadata(state_path)
                .map(|metadata| metadata.permissions().mode() & 0o600)
                .unwrap_or(0o600);
        options.mode(mode);
    }
    let mut file = options.open(&temp)?;
    let result = (|| {
        for record in records {
            serde_json::to_writer(&mut file, &record).map_err(io::Error::other)?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn make_record(sent_bytes: &[u8], response_bytes: &[u8], status: Option<u16>) -> Record {
    Record {
        time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        sent_b64: STANDARD.encode(sent_bytes),
        sent_sha256: hex::encode(Sha256::digest(sent_bytes)),
        response_b64: STANDARD.encode(response_bytes),
        response_sha256: hex::encode(Sha256::digest(response_bytes)),
        status,
    }
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
        assert!(err.to_string().contains("line 1"));
    }

    #[test]
    fn old_claim_record_parses_and_serializes_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claims.jsonl");
        let original = br#"{"time":"2026-10-01T00:00:00Z","sent_b64":"Y2xhaW0=","sent_sha256":"dd1b3c312cf7d816130354452e9629ce39355b0c534129dd26a08cd9a4502ede","response_b64":"b2s=","response_sha256":"2689367b205c16ce32ed4200942b8b8b1e262dfc70d9bc9fbc77c49699a4f1df"}"#;
        let mut record: Record = serde_json::from_slice(original).unwrap();
        assert_eq!(record.sent().unwrap(), b"claim");
        assert_eq!(record.response().unwrap(), b"ok");
        assert_eq!(serde_json::to_vec(&record).unwrap(), original);
        record.status = Some(200);
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(read(&path).unwrap()[0].status, Some(200));
    }

    #[test]
    fn report_append_drops_records_older_than_ninety_days() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reports.jsonl");
        let state_path = dir.path().join("report-state.json");
        let mut old = make_record(b"old", b"response", Some(200));
        old.time = (chrono::Utc::now() - chrono::Duration::days(91))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        append_report_retained(&path, &state_path, b"new", b"ok", 201).unwrap();
        let records = read(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sent().unwrap(), b"new");
        assert_eq!(records[0].status, Some(201));
    }

    #[cfg(unix)]
    #[test]
    fn report_log_keeps_stricter_state_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reports.jsonl");
        let state_path = dir.path().join("report-state.json");
        fs::write(&state_path, b"{}").unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o400)).unwrap();
        append_report_retained(&path, &state_path, b"sent", b"response", 200).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }
}
