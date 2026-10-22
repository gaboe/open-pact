//! Machine-scope CNG keys shared by the joining user and SYSTEM.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use open_pact_core::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use std::{path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        Cryptography::*,
        *,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const PLATFORM: &str = "Microsoft Platform Crypto Provider";
const FLAGS: u32 = NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG;

struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.0);
        }
    }
}

pub struct WindowsKey {
    key: Handle,
    public: PublicKey,
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn check(status: i32) -> Result<()> {
    ensure!(status == 0, "CNG status 0x{:08x}", status as u32);
    Ok(())
}

fn provider(name: &str) -> Result<Handle> {
    let mut handle = 0;
    check(unsafe { NCryptOpenStorageProvider(&mut handle, wide(name).as_ptr(), 0) })?;
    Ok(Handle(handle))
}

pub(super) fn is_elevated() -> Result<bool> {
    let mut token = ptr::null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "open process token"
    );
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size = 0;
    let success = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    ensure!(success != 0, "read process token elevation");
    Ok(elevation.TokenIsElevated != 0)
}

fn current_sid() -> Result<String> {
    let mut token = ptr::null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "open process token"
    );
    let result = (|| {
        let mut size = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        }
        ensure!(size > 0, "read token user size");
        let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        ensure!(
            unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    size,
                    &mut size,
                )
            } != 0,
            "read token user"
        );
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = ptr::null_mut();
        ensure!(
            unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } != 0,
            "format user SID"
        );
        let mut len = 0;
        unsafe {
            while *text.add(len) != 0 {
                len += 1;
            }
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe {
            LocalFree(text.cast());
        }
        Ok(sid?)
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

fn grant_user_and_system(key: &Handle) -> Result<()> {
    let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", current_sid()?));
    let mut descriptor = ptr::null_mut();
    let mut size = 0;
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                &mut size,
            )
        } != 0,
        "build key ACL"
    );
    let result = check(unsafe {
        NCryptSetProperty(
            key.0,
            NCRYPT_SECURITY_DESCR_PROPERTY,
            descriptor.cast(),
            size,
            DACL_SECURITY_INFORMATION | NCRYPT_PERSIST_FLAG,
        )
    });
    unsafe {
        LocalFree(descriptor);
    }
    result.context("grant key access to the joining user and SYSTEM")
}

impl WindowsKey {
    pub fn create(home: &Path) -> Result<Self> {
        Self::create_with_provider(home, PLATFORM)
    }

    fn create_with_provider(home: &Path, name: &str) -> Result<Self> {
        ensure!(is_elevated()?, "TPM protection requires an elevated join");
        let provider = provider(name).map_err(|error| error.context(super::ProviderUnavailable))?;
        let home_name = std::fs::canonicalize(home)?;
        let id = format!(
            "open-pact-{}-{}",
            hex::encode(Sha256::digest(home_name.as_os_str().as_encoded_bytes())),
            uuid::Uuid::new_v4()
        );
        let mut raw = 0;
        check(unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut raw,
                BCRYPT_ECDSA_P256_ALGORITHM,
                wide(&id).as_ptr(),
                0,
                FLAGS,
            )
        })
        .context("create machine-scope CNG key")?;
        let key = Handle(raw);
        let result: Result<PublicKey> = (|| {
            check(unsafe {
                NCryptSetProperty(
                    key.0,
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    0u32.to_le_bytes().as_ptr(),
                    4,
                    0,
                )
            })
            .context("set CNG key export policy")?;
            check(unsafe {
                NCryptSetProperty(
                    key.0,
                    NCRYPT_KEY_USAGE_PROPERTY,
                    NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes().as_ptr(),
                    4,
                    0,
                )
            })
            .context("set CNG key signing usage")?;
            check(unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) })
                .context("finalize machine-scope CNG key")?;
            grant_user_and_system(&key)?;
            let public = Self::export_public(&key)?;
            // The marker contains no key material. A failed marker write must not orphan a key.
            super::write_marker(&home.join(super::TPM_FILE), id.as_bytes())?;
            Ok(public)
        })();
        match result {
            Ok(public) => Ok(Self { key, public }),
            Err(error) => {
                check(unsafe { NCryptDeleteKey(key.0, NCRYPT_SILENT_FLAG) })
                    .with_context(|| format!("clean up failed CNG creation after {error:#}"))?;
                std::mem::forget(key);
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists)
                {
                    return Self::load_with_provider(home, name)
                        .context("load the competing device identity");
                }
                Err(error)
            }
        }
    }

    pub fn delete(home: &Path) -> Result<()> {
        Self::delete_with_provider(home, PLATFORM)
    }

    fn delete_with_provider(home: &Path, name: &str) -> Result<()> {
        let key = Self::load_with_provider(home, name)?;
        check(unsafe { NCryptDeleteKey(key.key.0, NCRYPT_SILENT_FLAG) })
            .context("delete persisted device key; use the creating user or SYSTEM")?;
        std::mem::forget(key.key);
        super::remove_if_present(&home.join(super::TPM_FILE))
    }

    pub fn load(home: &Path) -> Result<Self> {
        Self::load_with_provider(home, PLATFORM)
    }

    fn load_with_provider(home: &Path, name: &str) -> Result<Self> {
        let id = String::from_utf8(crate::read_home_file(&home.join(super::TPM_FILE))?)?;
        ensure!(
            !id.contains('\0') && id.starts_with("open-pact-"),
            "invalid TPM key name"
        );
        let provider = provider(name)?;
        let mut raw = 0;
        check(unsafe { NCryptOpenKey(provider.0, &mut raw, wide(&id).as_ptr(), 0, FLAGS) })?;
        let key = Handle(raw);
        let public = Self::export_public(&key)?;
        Ok(Self { key, public })
    }

    fn export_public(key: &Handle) -> Result<PublicKey> {
        let mut blob = [0u8; 72];
        let mut size = 0;
        check(unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                blob.as_mut_ptr(),
                blob.len() as u32,
                &mut size,
                0,
            )
        })?;
        ensure!(
            size == 72
                && u32::from_le_bytes(blob[..4].try_into()?) == BCRYPT_ECDSA_PUBLIC_P256_MAGIC
                && u32::from_le_bytes(blob[4..8].try_into()?) == 32,
            "invalid CNG P-256 public key"
        );
        let mut sec1 = vec![4];
        sec1.extend_from_slice(&blob[8..]);
        Ok(PublicKey::from_sec1(&sec1)?)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let hash = Sha256::digest(message);
        let mut signature = [0u8; 64];
        let mut size = 0;
        check(unsafe {
            NCryptSignHash(
                self.key.0,
                ptr::null(),
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_mut_ptr(),
                64,
                &mut size,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        if size != 64 {
            bail!("invalid CNG ES256 signature length");
        }
        Signature::try_from(URL_SAFE_NO_PAD.encode(signature)).map_err(anyhow::Error::msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOFTWARE: &str = "Microsoft Software Key Storage Provider";

    fn roundtrip(name: &str) {
        let home = tempfile::tempdir().unwrap();
        let key = WindowsKey::create_with_provider(home.path(), name).unwrap();
        let competing = WindowsKey::create_with_provider(home.path(), name).unwrap();
        assert_eq!(key.public_key(), competing.public_key());
        drop(competing);
        let loaded = WindowsKey::load_with_provider(home.path(), name).unwrap();
        assert_eq!(key.public_key(), loaded.public_key());
        let device = super::super::DeviceKey::Tpm(loaded);
        assert_eq!(device.protection(), "tpm");
        let jws = device
            .sign_claim(&super::super::tests::claim_for(&device, 0))
            .unwrap();
        assert_eq!(
            open_pact_core::verify_claim(&jws)
                .unwrap()
                .claim()
                .trust_level,
            open_pact_core::TrustLevel::L1
        );
        let request = super::super::tests::enrol(&device);
        request.verify().unwrap();
        let mut size = 0;
        assert_ne!(
            unsafe {
                NCryptExportKey(
                    key.key.0,
                    0,
                    BCRYPT_ECCPRIVATE_BLOB,
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    &mut size,
                    0,
                )
            },
            0
        );
        assert!(super::super::DeviceKey::load_or_create(home.path(), true).is_err());
        check(unsafe { NCryptDeleteKey(key.key.0, NCRYPT_SILENT_FLAG) }).unwrap();
        std::mem::forget(key.key);
    }

    #[test]
    #[ignore = "Windows CI invokes this under a standard user and SYSTEM"]
    fn windows_cng_shared_fixture() {
        let home = std::path::PathBuf::from(std::env::var_os("OPEN_PACT_CNG_HOME").unwrap());
        let action = std::env::var("OPEN_PACT_CNG_ACTION").unwrap();
        if action == "retry-delete" {
            let key = WindowsKey::load_with_provider(&home, SOFTWARE).unwrap();
            check(unsafe { NCryptDeleteKey(key.key.0, NCRYPT_SILENT_FLAG) }).unwrap();
            std::mem::forget(key.key);
            assert!(home.join(super::super::TPM_FILE).exists());
            WindowsKey::delete_with_provider(&home, SOFTWARE).unwrap();
            assert!(!home.join(super::super::TPM_FILE).exists());
            assert!(WindowsKey::load_with_provider(&home, SOFTWARE).is_err());
            return;
        }
        let key = match action.as_str() {
            "software" => {
                assert!(!is_elevated().unwrap());
                let key = super::super::DeviceKey::load_or_create(&home, false).unwrap();
                assert_eq!(key.protection(), "os_permissions");
                assert!(!home.join(super::super::TPM_FILE).exists());
                super::super::tests::enrol(&key).verify().unwrap();
                return;
            }
            "deny-delete" => {
                let error = match WindowsKey::delete_with_provider(&home, SOFTWARE) {
                    Ok(()) => panic!("unrelated administrator deleted the device key"),
                    Err(error) => error,
                };
                assert!(
                    error
                        .to_string()
                        .contains("use the creating user or SYSTEM")
                );
                assert!(home.join(super::super::TPM_FILE).exists());
                return;
            }
            "create" => WindowsKey::create_with_provider(&home, SOFTWARE).unwrap(),
            "sign" | "delete" => WindowsKey::load_with_provider(&home, SOFTWARE).unwrap(),
            _ => panic!("unknown fixture action"),
        };
        let device = super::super::DeviceKey::Tpm(key);
        super::super::tests::enrol(&device).verify().unwrap();
        if action == "delete" {
            let super::super::DeviceKey::Tpm(key) = device else {
                unreachable!()
            };
            drop(key);
            WindowsKey::delete_with_provider(&home, SOFTWARE).unwrap();
            assert!(!home.join(super::super::TPM_FILE).exists());
            assert!(WindowsKey::load_with_provider(&home, SOFTWARE).is_err());
        }
    }

    #[test]
    #[ignore = "requires elevation; Windows CI invokes explicitly"]
    fn windows_cng_software_provider_roundtrip() {
        roundtrip(SOFTWARE);
    }

    #[test]
    #[ignore = "requires a real TPM; unverified on hosted runners"]
    fn windows_tpm_roundtrip() {
        roundtrip(PLATFORM);
    }
}
