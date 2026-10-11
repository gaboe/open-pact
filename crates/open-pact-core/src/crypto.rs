use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{
    SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Manifest};

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_prefixed_sha256(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

macro_rules! prefixed_hash {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;
            fn try_from(s: String) -> Result<Self, String> {
                if is_prefixed_sha256(&s, $prefix) {
                    Ok(Self(s))
                } else {
                    Err(format!("expected {}<64 lowercase hex>, got {s:?}", $prefix))
                }
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

prefixed_hash!(ManifestHash, "sha256:");
prefixed_hash!(Pseudonym, "pseudonym:");

impl ManifestHash {
    pub fn of(manifest_bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", sha256_hex(manifest_bytes)))
    }
}

impl Pseudonym {
    pub fn of(key: &PublicKey) -> Self {
        Self(format!(
            "pseudonym:{}",
            sha256_hex(&key.sec1_uncompressed())
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Jwk", into = "Jwk")]
pub struct PublicKey(VerifyingKey);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

impl PublicKey {
    pub fn sec1_uncompressed(&self) -> Vec<u8> {
        self.0.to_sec1_point(false).as_bytes().to_vec()
    }

    pub fn fingerprint(&self) -> String {
        format!("sha256:{}", sha256_hex(&self.sec1_uncompressed()))
    }

    pub(crate) fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        self.0.verify(message, &sig.0).is_ok()
    }
}

impl From<&SigningKey> for PublicKey {
    fn from(key: &SigningKey) -> Self {
        Self(*key.verifying_key())
    }
}

impl TryFrom<Jwk> for PublicKey {
    type Error = Error;
    fn try_from(jwk: Jwk) -> Result<Self, Error> {
        if jwk.kty != "EC" || jwk.crv != "P-256" {
            return Err(Error::InvalidKey);
        }
        let coord = |c: &str| {
            B64.decode(c)
                .ok()
                .filter(|b| b.len() == 32)
                .ok_or(Error::InvalidKey)
        };
        let mut sec1 = vec![0x04];
        sec1.extend(coord(&jwk.x)?);
        sec1.extend(coord(&jwk.y)?);
        VerifyingKey::from_sec1_bytes(&sec1)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }
}

impl From<PublicKey> for Jwk {
    fn from(key: PublicKey) -> Jwk {
        let sec1 = key.sec1_uncompressed();
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: B64.encode(&sec1[1..33]),
            y: B64.encode(&sec1[33..65]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Signature(p256::ecdsa::Signature);

impl Signature {
    pub(crate) fn sign(key: &SigningKey, message: &[u8]) -> Self {
        Self(key.sign(message))
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        p256::ecdsa::Signature::from_slice(bytes).ok().map(Self)
    }

    pub(crate) fn to_b64(&self) -> String {
        B64.encode(self.0.to_bytes())
    }
}

impl TryFrom<String> for Signature {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        B64.decode(&s)
            .ok()
            .and_then(|b| Self::from_bytes(&b))
            .ok_or_else(|| "expected base64url ES256 signature (r||s)".into())
    }
}

impl From<Signature> for String {
    fn from(sig: Signature) -> String {
        sig.to_b64()
    }
}

/// A signature over the rendered manifest hash string (`sha256:<hex>`), the value the owner sees and signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endorsement {
    pub key: PublicKey,
    pub signature: Signature,
}

impl Endorsement {
    pub fn sign(key: &SigningKey, hash: &ManifestHash) -> Self {
        Self {
            key: PublicKey::from(key),
            signature: Signature::sign(key, hash.as_str().as_bytes()),
        }
    }

    pub fn verify(&self, hash: &ManifestHash) -> bool {
        self.key.verify(hash.as_str().as_bytes(), &self.signature)
    }
}

/// Callers must still pin `company.key` and `owner.key` to keys they trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub toml: String,
    pub company: Endorsement,
    pub owner: Endorsement,
}

impl SignedManifest {
    pub fn verify(&self) -> Result<Manifest, Error> {
        let manifest = Manifest::parse(self.toml.as_bytes())?;
        if !self.company.verify(manifest.hash()) {
            return Err(Error::BadSignature("company manifest signature"));
        }
        if !self.owner.verify(manifest.hash()) {
            return Err(Error::BadSignature("owner manifest signature"));
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_key;

    const DEMO: &str = include_str!("../../../examples/manifest.toml");

    #[test]
    fn manifest_hash_is_sha256_of_exact_bytes() {
        assert_eq!(
            ManifestHash::of(b"manifest_version = 1\n").as_str(),
            "sha256:0e7703839cc84cfdd6ecfb5302c1a2c4b1161c7a0642bb4518e37a43f6db9c0a"
        );
        assert_ne!(
            ManifestHash::of(b"manifest_version = 1\n"),
            ManifestHash::of(b"manifest_version = 1 \n")
        );
    }

    #[test]
    fn pseudonym_is_sha256_of_uncompressed_sec1_key() {
        let key = SigningKey::from_slice(&[1; 32]).unwrap();
        let public = PublicKey::from(&key);
        assert_eq!(public.sec1_uncompressed().len(), 65);
        assert_eq!(
            Pseudonym::of(&public).as_str(),
            "pseudonym:256b1be32745d1d1c9d49121cc87bc451c4f2dfa756d89b4c910afaeb6258ae0"
        );
    }

    #[test]
    fn jwk_roundtrip_and_rejects_private_part() {
        let public = PublicKey::from(&dev_key::generate());
        let json = serde_json::to_value(&public).unwrap();
        assert_eq!(json["kty"], "EC");
        assert_eq!(json["crv"], "P-256");
        assert_eq!(
            serde_json::from_value::<PublicKey>(json.clone()).unwrap(),
            public
        );
        let mut with_d = json;
        with_d["d"] = "AAAA".into();
        assert!(serde_json::from_value::<PublicKey>(with_d).is_err());
    }

    fn signed_demo() -> SignedManifest {
        let (company, owner) = (dev_key::generate(), dev_key::generate());
        let hash = ManifestHash::of(DEMO.as_bytes());
        SignedManifest {
            toml: DEMO.into(),
            company: Endorsement::sign(&company, &hash),
            owner: Endorsement::sign(&owner, &hash),
        }
    }

    #[test]
    fn signed_manifest_roundtrips_through_json_and_verifies() {
        let signed = signed_demo();
        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedManifest = serde_json::from_str(&json).unwrap();
        let manifest = back.verify().unwrap();
        assert_eq!(manifest.hash(), &ManifestHash::of(DEMO.as_bytes()));
    }

    #[test]
    fn signed_manifest_rejects_tampered_toml() {
        let mut signed = signed_demo();
        signed.toml = signed.toml.replace("grace = \"0d\"", "grace = \"9d\"");
        assert!(matches!(
            signed.verify(),
            Err(Error::BadSignature("company manifest signature"))
        ));
    }

    #[test]
    fn signed_manifest_rejects_owner_signature_by_other_key() {
        let mut signed = signed_demo();
        let other = Endorsement::sign(&dev_key::generate(), &ManifestHash::of(DEMO.as_bytes()));
        signed.owner.signature = other.signature;
        assert!(matches!(
            signed.verify(),
            Err(Error::BadSignature("owner manifest signature"))
        ));
    }
}
