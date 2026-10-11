//! Development-only software keys in PKCS#8 PEM files. Real device keys live in a TPM or Secure Enclave and are never exported.

use std::path::Path;

use p256::elliptic_curve::Generate;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};

use crate::{Error, SigningKey};

fn key_error(path: &Path, reason: impl ToString) -> Error {
    Error::KeyFile {
        path: path.display().to_string(),
        reason: reason.to_string(),
    }
}

pub fn generate() -> SigningKey {
    SigningKey::generate()
}

pub fn save(path: &Path, key: &SigningKey) -> Result<(), Error> {
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| key_error(path, e))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| key_error(path, e))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| key_error(path, e))?;
    std::io::Write::write_all(&mut file, pem.as_bytes()).map_err(|e| key_error(path, e))
}

pub fn load(path: &Path) -> Result<SigningKey, Error> {
    let pem = std::fs::read_to_string(path).map_err(|e| key_error(path, e))?;
    SigningKey::from_pkcs8_pem(&pem).map_err(|e| key_error(path, e))
}

pub fn load_or_create(path: &Path) -> Result<SigningKey, Error> {
    if path.exists() {
        return load(path);
    }
    let key = generate();
    save(path, &key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_roundtrip_and_no_overwrite() {
        let dir = std::env::temp_dir().join(format!("open-pact-devkey-{}", std::process::id()));
        let path = dir.join("device-dev.pem");
        let _ = std::fs::remove_dir_all(&dir);
        let created = load_or_create(&path).unwrap();
        assert_eq!(load_or_create(&path).unwrap(), created);
        assert!(save(&path, &generate()).is_err());
        assert_eq!(load(&path).unwrap(), created);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
