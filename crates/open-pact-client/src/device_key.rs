//! The device key that signs claims. Its backing sets the claim's trust level.

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

    /// Reuses the existing key. Tries platform hardware for a new key unless `software`.
    pub fn load_or_create(home: &Path, software: bool) -> Result<Self> {
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
            match windows_key::WindowsKey::create(home) {
                Ok(key) => return Ok(Self::Tpm(key)),
                Err(e) => eprintln!("No TPM key ({e:#}); using a software device key."),
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
            time: "2026-11-03T08:12:44Z".parse().unwrap(),
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
