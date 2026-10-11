//! A P-256 device key inside the Secure Enclave, kept as a wrapped blob in a file.
//!
//! The key is not stored in the keychain, so the client needs no keychain entitlement.
//! The blob is useless on any other Mac. On this Mac, any program that can read the file can sign with it.

use anyhow::{Context, Result, anyhow, bail};
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use open_pact_core::{PublicKey, Signature};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::item::{
    kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits,
    kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave,
};
use security_framework_sys::key::SecKeyCreateWithData;

/// `kSecAttrTokenOID` from Apple's private SecItemPriv.h. Its value is the same blob as CryptoKit's
/// `SecureEnclave.P256.Signing.PrivateKey.dataRepresentation`.
const TOKEN_OBJECT_ID: &str = "toid";

pub struct SecureEnclaveKey {
    key: SecKey,
    public: PublicKey,
}

impl SecureEnclaveKey {
    /// A new non-permanent key and its wrapped blob. Fails where there is no Secure Enclave, such as in a VM.
    pub fn create() -> Result<(Self, Vec<u8>)> {
        let key = SecKey::new(
            GenerateKeyOptions::default()
                .set_key_type(KeyType::ec_sec_prime_random())
                .set_size_in_bits(256)
                .set_token(Token::SecureEnclave),
        )
        .map_err(|e| anyhow!("create a Secure Enclave key: {e}"))?;
        let id = CFString::from_static_string(TOKEN_OBJECT_ID);
        let attributes = key.attributes();
        let Some(blob) = attributes
            .find(id.as_CFTypeRef())
            .map(|v| unsafe { CFType::wrap_under_get_rule(*v) })
            .and_then(|v| v.downcast::<CFData>())
        else {
            bail!("the Secure Enclave key has no wrapped blob");
        };
        let blob = blob.bytes().to_vec();
        Ok((Self::from_key(key)?, blob))
    }

    /// Fails on a blob from another Mac or a damaged file; it never creates a new key.
    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        let attr = |k| unsafe { CFString::wrap_under_get_rule(k) }.as_CFType();
        let attributes = CFDictionary::from_CFType_pairs(&[
            (
                attr(unsafe { kSecAttrTokenID }),
                attr(unsafe { kSecAttrTokenIDSecureEnclave }),
            ),
            (
                CFString::from_static_string(TOKEN_OBJECT_ID).as_CFType(),
                CFData::from_buffer(blob).as_CFType(),
            ),
            (
                attr(unsafe { kSecAttrKeyType }),
                attr(unsafe { kSecAttrKeyTypeECSECPrimeRandom }),
            ),
            (
                attr(unsafe { kSecAttrKeyClass }),
                attr(unsafe { kSecAttrKeyClassPrivate }),
            ),
            (
                attr(unsafe { kSecAttrKeySizeInBits }),
                CFNumber::from(256).as_CFType(),
            ),
            (
                attr(unsafe { kSecAttrIsPermanent }),
                CFBoolean::false_value().as_CFType(),
            ),
        ]);
        let mut error = std::ptr::null_mut();
        let key = unsafe {
            SecKeyCreateWithData(
                CFData::from_buffer(&[]).as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            )
        };
        if key.is_null() {
            let error = unsafe { CFError::wrap_under_create_rule(error) };
            bail!("load the Secure Enclave key: {error}");
        }
        Self::from_key(unsafe { SecKey::wrap_under_create_rule(key) })
    }

    fn from_key(key: SecKey) -> Result<Self> {
        let point = key
            .public_key()
            .and_then(|p| p.external_representation())
            .context("export the Secure Enclave public key")?;
        let public = PublicKey::from_sec1(point.bytes())?;
        Ok(Self { key, public })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let der = self
            .key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|e| anyhow!("sign with the Secure Enclave key: {e}"))?;
        Signature::from_der(&der).context("the Secure Enclave returned a malformed signature")
    }
}
