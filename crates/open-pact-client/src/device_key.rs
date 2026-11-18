//! The device key that signs claims. Its backing sets the claim's trust level.

#[cfg(any(windows, test))]
use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use open_pact_core::{
    Claim, PublicKey, Signature, SigningKey, TrustLevel, dev_key, sign_claim_with,
};

#[cfg(target_os = "macos")]
use crate::secure_enclave::SecureEnclaveKey;

#[cfg(windows)]
#[path = "windows_key.rs"]
mod windows_key;

const TPM_FILE: &str = "device-tpm.key";
const SOFTWARE_FILE: &str = "device-dev.pem";
const SECURE_ENCLAVE_FILE: &str = "device-se.key";

/// The code that `join --json` puts on the error line of a [`NeedsElevation`] refusal.
pub const NEEDS_ELEVATION_CODE: &str = "needs_elevation";

/// A new device on Windows joins from an elevated process, or it would end with a software key and
/// no SYSTEM job. The refusal comes before the first network request.
#[derive(Debug)]
pub struct NeedsElevation;

impl std::fmt::Display for NeedsElevation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "Join on Windows needs an elevated PowerShell, so that the device key goes into the \
             TPM and the scheduled job runs as SYSTEM. Open PowerShell with Run as administrator, \
             using the account you sign in with every day, and run the same join command again. \
             The join enrols the account that runs it. If Windows asks for another person's \
             password, stop and ask IT. Nothing was sent. To join without that, for testing \
             only, add --software-key.",
        )
    }
}

impl std::error::Error for NeedsElevation {}

/// True when a join must stop: the process is not elevated, the owner did not ask for a software
/// key, and the home holds no device key yet. A home with a key keeps using it.
#[cfg(any(windows, test))]
fn windows_join_needs_elevation(elevated: bool, software_key: bool, has_key: bool) -> bool {
    !elevated && !software_key && !has_key
}

/// Whether `home` already holds a device key of any kind.
#[cfg(any(windows, test))]
fn holds_key(home: &Path) -> bool {
    [TPM_FILE, SECURE_ENCLAVE_FILE, SOFTWARE_FILE]
        .iter()
        .any(|name| home.join(name).exists())
}

#[cfg(any(windows, test))]
#[derive(Debug)]
pub(super) struct ProviderUnavailable;

#[cfg(any(windows, test))]
impl std::fmt::Display for ProviderUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TPM provider unavailable")
    }
}

#[cfg(any(windows, test))]
impl std::error::Error for ProviderUnavailable {}

#[cfg(any(windows, test))]
fn hardware_result<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(key) => Ok(Some(key)),
        Err(error) if error.is::<ProviderUnavailable>() => {
            eprintln!("No TPM key ({error:#}); using a software device key.");
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(windows, test))]
fn write_marker(path: &Path, bytes: &[u8]) -> Result<()> {
    write_marker_with(path, |file| {
        file.write_all(bytes)?;
        file.sync_all()
    })
}

#[cfg(any(windows, test))]
fn write_marker_with(
    path: &Path,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    if let Err(error) = write(&mut file) {
        drop(file);
        std::fs::remove_file(path)?;
        return Err(error.into());
    }
    Ok(())
}

fn key_lock(home: &Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(home.join("device-key.lock"))?;
    file.lock()?;
    Ok(file)
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub enum DeviceKey {
    Software(SigningKey),
    #[cfg(windows)]
    Tpm(windows_key::WindowsKey),
    #[cfg(target_os = "macos")]
    SecureEnclave(SecureEnclaveKey),
}

impl DeviceKey {
    /// The key `join` created. Never creates one.
    pub fn load(home: &Path) -> Result<Self> {
        if home.join(TPM_FILE).exists() {
            #[cfg(windows)]
            return Ok(Self::Tpm(windows_key::WindowsKey::load(home)?));
            #[cfg(not(windows))]
            bail!("{} needs the Windows TPM key store", home.display());
        }
        let blob_path = home.join(SECURE_ENCLAVE_FILE);
        if blob_path.exists() {
            #[cfg(target_os = "macos")]
            return Ok(Self::SecureEnclave(SecureEnclaveKey::from_blob(
                &std::fs::read(&blob_path)?,
            )?));
            #[cfg(not(target_os = "macos"))]
            bail!("{} needs a Mac's Secure Enclave", blob_path.display());
        }
        let bytes = crate::read_home_file(&home.join(SOFTWARE_FILE))?;
        let pem = std::str::from_utf8(&bytes)?;
        Ok(Self::Software(dev_key::from_pem(pem)?))
    }

    /// Whether a join with these choices must stop for lack of an elevated process.
    #[cfg(windows)]
    pub fn join_needs_elevation(home: &Path, software: bool) -> Result<bool> {
        Ok(windows_join_needs_elevation(
            windows_key::is_elevated()?,
            software,
            holds_key(home),
        ))
    }

    /// Whether a join with these choices must stop for lack of an elevated process. Only Windows
    /// stops.
    #[cfg(not(windows))]
    pub fn join_needs_elevation(_home: &Path, _software: bool) -> Result<bool> {
        Ok(false)
    }

    /// Whether this process runs elevated on Windows. False when Windows does not say.
    #[cfg(windows)]
    pub fn process_is_elevated() -> bool {
        windows_key::is_elevated().unwrap_or(false)
    }

    /// Whether this process runs elevated on Windows. False everywhere else.
    #[cfg(not(windows))]
    pub fn process_is_elevated() -> bool {
        false
    }

    /// Reuses the existing key. Tries platform hardware for a new key unless `software`.
    pub fn load_or_create(home: &Path, software: bool) -> Result<Self> {
        let _lock = key_lock(home)?;
        if home.join(TPM_FILE).exists() {
            if software {
                bail!(
                    "this home already holds a TPM device key; use a new --home for a software key"
                );
            }
            return Self::load(home);
        }
        if home.join(SECURE_ENCLAVE_FILE).exists() {
            if software {
                bail!(
                    "{} already holds a Secure Enclave device key; use a new --home for a software key",
                    home.display()
                );
            }
            return Self::load(home);
        }
        let pem = home.join(SOFTWARE_FILE);
        #[cfg(windows)]
        if !software && !pem.exists() {
            if windows_key::is_elevated()? {
                if let Some(key) = hardware_result(windows_key::WindowsKey::create(home))? {
                    return Ok(Self::Tpm(key));
                }
            } else {
                eprintln!("TPM protection requires an elevated join; using a software device key.");
            }
        }
        #[cfg(target_os = "macos")]
        if !software && !pem.exists() {
            match SecureEnclaveKey::create() {
                Ok((key, blob)) => {
                    dev_key::write_new(&home.join(SECURE_ENCLAVE_FILE), &blob)?;
                    return Ok(Self::SecureEnclave(key));
                }
                Err(e) => eprintln!("No Secure Enclave key ({e:#}); using a software device key."),
            }
        }
        Ok(Self::Software(dev_key::load_or_create(&pem)?))
    }

    /// Destroy the device credential before full uninstall or rotation.
    pub fn delete(home: &Path) -> Result<()> {
        let _lock = key_lock(home)?;
        if home.join(TPM_FILE).exists() {
            #[cfg(windows)]
            windows_key::WindowsKey::delete(home)?;
            #[cfg(not(windows))]
            bail!("delete this home's TPM key on Windows before removing its marker");
        }
        remove_if_present(&home.join(SECURE_ENCLAVE_FILE))?;
        remove_if_present(&home.join(SOFTWARE_FILE))?;
        Ok(())
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Software(key) => PublicKey::from(key),
            #[cfg(windows)]
            Self::Tpm(key) => key.public_key().clone(),
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(key) => key.public_key().clone(),
        }
    }

    pub fn trust_level(&self) -> TrustLevel {
        match self {
            Self::Software(_) => TrustLevel::L0,
            #[cfg(windows)]
            Self::Tpm(_) => TrustLevel::L1,
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(_) => TrustLevel::L1,
        }
    }

    #[cfg(all(test, windows))]
    pub fn protection(&self) -> &'static str {
        match self {
            Self::Software(_) => "os_permissions",
            #[cfg(windows)]
            Self::Tpm(_) => "tpm",
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(_) => "secure_enclave",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Software(_) => "software key file",
            #[cfg(windows)]
            Self::Tpm(_) => "TPM",
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(_) => "Secure Enclave",
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        match self {
            Self::Software(key) => Ok(Signature::sign(key, message)),
            #[cfg(windows)]
            Self::Tpm(key) => key.sign(message),
            #[cfg(target_os = "macos")]
            Self::SecureEnclave(key) => key.sign(message),
        }
    }

    pub fn sign_claim(&self, claim: &Claim) -> Result<String> {
        sign_claim_with(claim, &self.public_key(), |input| self.sign(input))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use open_pact_core::{
        Endorsement, EnrolRequest, InvitationCode, ManifestHash, Os, Pseudonym, SignedManifest,
        Virtualized, verify_claim,
    };

    use super::*;

    pub(super) fn claim_for(key: &DeviceKey, nonce: usize) -> Claim {
        let device_key = key.public_key();
        Claim {
            manifest: ManifestHash::of(b"manifest_version = 1\n"),
            device: Pseudonym::of(&device_key),
            device_key,
            nonce: format!("n{nonce}"),
            time: open_pact_core::timestamp::parse_rfc3339("2026-11-03T08:12:44Z").unwrap(),
            client: "open-pact-client test".into(),
            os: Os::Macos,
            trust_level: key.trust_level(),
            virtualized: Some(Virtualized::No),
            results: BTreeMap::from([("firewall".into(), "on".into())]),
            csr_sha256: None,
            log_checkpoint: None,
        }
    }

    pub(super) fn enrol(key: &DeviceKey) -> EnrolRequest {
        let toml = include_str!("../../../examples/manifest.toml");
        let hash = ManifestHash::of(toml.as_bytes());
        let owner = dev_key::generate();
        let signed = SignedManifest {
            toml: toml.into(),
            company: Endorsement::sign(&dev_key::generate(), &hash),
            owner: Endorsement::sign(&owner, &hash),
        };
        EnrolRequest::sign_with(
            signed,
            InvitationCode::from_bytes([7; 32]),
            &owner,
            &key.public_key(),
            |statement| key.sign(statement),
        )
        .unwrap()
    }

    #[test]
    fn only_a_new_device_without_elevation_or_a_software_key_needs_elevation() {
        for elevated in [false, true] {
            for software_key in [false, true] {
                for has_key in [false, true] {
                    assert_eq!(
                        windows_join_needs_elevation(elevated, software_key, has_key),
                        !elevated && !software_key && !has_key,
                        "elevated {elevated}, software key {software_key}, has key {has_key}"
                    );
                }
            }
        }
        assert!(windows_join_needs_elevation(false, false, false));
        assert!(!windows_join_needs_elevation(false, false, true));
        assert!(!windows_join_needs_elevation(false, true, false));
        assert!(!windows_join_needs_elevation(true, false, false));
    }

    #[test]
    fn a_home_holds_a_key_when_any_key_file_exists() {
        for name in [TPM_FILE, SECURE_ENCLAVE_FILE, SOFTWARE_FILE] {
            let home = tempfile::tempdir().unwrap();
            assert!(!holds_key(home.path()), "{name}");
            std::fs::write(home.path().join(name), b"x").unwrap();
            assert!(holds_key(home.path()), "{name}");
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("owner-dev.pem"), b"x").unwrap();
        assert!(!holds_key(home.path()), "the owner key is not a device key");
    }

    #[test]
    fn the_refusal_says_what_to_do_and_that_nothing_was_sent() {
        let text = NeedsElevation.to_string();
        for part in [
            "elevated PowerShell",
            "Run as administrator",
            "account you sign in with every day",
            "enrols the account that runs it",
            "another person's password",
            "ask IT",
            "same join command again",
            "TPM",
            "SYSTEM",
            "Nothing was sent",
            "--software-key",
            "testing only",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
    }

    #[test]
    fn software_key_proves_possession_at_enrolment() {
        let home = tempfile::tempdir().unwrap();
        let key = DeviceKey::load_or_create(home.path(), true).unwrap();
        let request = enrol(&key);
        assert_eq!(request.device_key, key.public_key());
        request.verify().unwrap();
    }

    #[test]
    fn software_key_is_reused_and_signs_l0_claims() {
        let home = tempfile::tempdir().unwrap();
        let key = DeviceKey::load_or_create(home.path(), true).unwrap();
        assert_eq!(key.trust_level(), TrustLevel::L0);
        assert!(home.path().join(SOFTWARE_FILE).exists());
        let again = DeviceKey::load_or_create(home.path(), false).unwrap();
        assert_eq!(again.public_key(), key.public_key());
        let jws = DeviceKey::load(home.path())
            .unwrap()
            .sign_claim(&claim_for(&key, 0))
            .unwrap();
        assert_eq!(
            verify_claim(&jws).unwrap().claim().trust_level,
            TrustLevel::L0
        );
    }

    #[test]
    fn load_never_creates_a_key() {
        let home = tempfile::tempdir().unwrap();
        assert!(DeviceKey::load(home.path()).is_err());
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn software_flag_refuses_a_home_with_a_secure_enclave_key() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(SECURE_ENCLAVE_FILE), b"blob").unwrap();
        assert!(DeviceKey::load_or_create(home.path(), true).is_err());
        assert!(!home.path().join(SOFTWARE_FILE).exists());
    }

    #[test]
    fn tpm_marker_never_silently_becomes_a_software_key() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(TPM_FILE), b"invalid-key-name").unwrap();
        assert!(DeviceKey::load(home.path()).is_err());
        assert!(DeviceKey::load_or_create(home.path(), false).is_err());
        assert!(DeviceKey::load_or_create(home.path(), true).is_err());
        assert!(!home.path().join(SOFTWARE_FILE).exists());
    }

    #[test]
    fn partial_marker_write_is_removed_and_does_not_fall_back() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(TPM_FILE);
        let result: Result<()> = write_marker_with(&path, |file| {
            file.write_all(b"partial")?;
            Err(std::io::Error::other("injected write failure"))
        });
        assert!(hardware_result(result).is_err());
        assert!(!path.exists());
        assert!(!home.path().join(SOFTWARE_FILE).exists());
    }

    #[test]
    fn competing_marker_is_preserved_and_does_not_fall_back() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(TPM_FILE);
        write_marker(&path, b"winner").unwrap();
        assert!(hardware_result(write_marker(&path, b"loser")).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"winner");
        assert!(!home.path().join(SOFTWARE_FILE).exists());
    }

    #[test]
    fn only_provider_unavailability_permits_hardware_fallback() {
        assert!(
            hardware_result::<()>(Err(ProviderUnavailable.into()))
                .unwrap()
                .is_none()
        );
        assert!(hardware_result::<()>(Err(anyhow::anyhow!("ACL setup failed"))).is_err());
    }

    #[test]
    fn delete_removes_software_identity_and_can_be_repeated() {
        let home = tempfile::tempdir().unwrap();
        DeviceKey::load_or_create(home.path(), true).unwrap();
        DeviceKey::delete(home.path()).unwrap();
        assert!(!home.path().join(SOFTWARE_FILE).exists());
        assert!(DeviceKey::load(home.path()).is_err());
        DeviceKey::delete(home.path()).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs a Mac with a Secure Enclave"]
    fn secure_enclave_key_signs_l1_claims_that_verify() {
        let home = tempfile::tempdir().unwrap();
        let key = DeviceKey::load_or_create(home.path(), false).unwrap();
        assert!(matches!(key, DeviceKey::SecureEnclave(_)));
        assert!(!home.path().join(SOFTWARE_FILE).exists());
        let reloaded = DeviceKey::load(home.path()).unwrap();
        assert_eq!(reloaded.public_key(), key.public_key());
        for nonce in 0..32 {
            let jws = reloaded.sign_claim(&claim_for(&key, nonce)).unwrap();
            let verified = verify_claim(&jws).unwrap();
            assert_eq!(verified.claim().trust_level, TrustLevel::L1);
            assert_eq!(verified.claim().device_key, key.public_key());
        }
        let request = enrol(&reloaded);
        assert_eq!(request.device_key, key.public_key());
        request.verify().unwrap();
        let other = tempfile::tempdir().unwrap();
        let foreign = DeviceKey::load_or_create(other.path(), false).unwrap();
        assert!(reloaded.sign_claim(&claim_for(&foreign, 0)).is_err());
    }
}
