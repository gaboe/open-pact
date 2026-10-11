use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    Error, LogHash, ManifestHash, Os, Pseudonym, PublicKey, Signature, SigningKey, TrustLevel,
};

const HEADER: &str = r#"{"alg":"ES256","typ":"open-pact-claim+jws"}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Virtualized {
    Yes,
    No,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub manifest: ManifestHash,
    pub device: Pseudonym,
    pub device_key: PublicKey,
    pub nonce: String,
    pub time: DateTime<Utc>,
    pub client: String,
    pub os: Os,
    pub trust_level: TrustLevel,
    pub virtualized: Virtualized,
    pub results: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csr_pem: Option<String>,
    /// The last log checkpoint this client verified, so each claim commits to the rules history it saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_checkpoint: Option<LogCheckpoint>,
}

/// Size and root as the checkpoint text writes them; the root is standard base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogCheckpoint {
    pub size: u64,
    #[serde(with = "base64_root")]
    pub root: LogHash,
}

mod base64_root {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    use crate::LogHash;

    pub fn serialize<S: Serializer>(root: &LogHash, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(root.0))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<LogHash, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD
            .decode(&text)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(LogHash)
            .ok_or_else(|| D::Error::custom(format!("expected base64 of 32 bytes, got {text:?}")))
    }
}

impl Claim {
    pub fn canonical_json(&self) -> Vec<u8> {
        serde_jcs::to_vec(self).expect("claim fields always serialize")
    }
}

/// A claim whose signature, canonical form and pseudonym were checked. Only `verify_claim` builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaim {
    jws: String,
    claim: Claim,
}

impl VerifiedClaim {
    pub fn jws(&self) -> &str {
        &self.jws
    }

    pub fn claim(&self) -> &Claim {
        &self.claim
    }
}

pub fn sign_claim(claim: &Claim, key: &SigningKey) -> Result<String, Error> {
    sign_claim_with(claim, &PublicKey::from(key), |input| {
        Ok::<_, Error>(Signature::sign(key, input))
    })
}

/// Signs with a key held elsewhere, such as a Secure Enclave; `key` is the public half of the signer.
pub fn sign_claim_with<E: From<Error>>(
    claim: &Claim,
    key: &PublicKey,
    sign: impl FnOnce(&[u8]) -> Result<Signature, E>,
) -> Result<String, E> {
    if &claim.device_key != key {
        return Err(Error::KeyMismatch.into());
    }
    if claim.device != Pseudonym::of(&claim.device_key) {
        return Err(Error::PseudonymMismatch.into());
    }
    let input = format!(
        "{}.{}",
        B64.encode(HEADER),
        B64.encode(claim.canonical_json())
    );
    let signature = sign(input.as_bytes())?;
    Ok(format!("{input}.{}", signature.to_b64()))
}

pub fn verify_claim(jws: &str) -> Result<VerifiedClaim, Error> {
    let mut parts = jws.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::MalformedJws("expected three dot-separated parts"));
    };
    let decode = |part: &str, what| B64.decode(part).map_err(|_| Error::MalformedJws(what));
    if decode(header, "header is not base64url")? != HEADER.as_bytes() {
        return Err(Error::MalformedJws(
            "header must be exactly {\"alg\":\"ES256\",\"typ\":\"open-pact-claim+jws\"}",
        ));
    }
    let payload_bytes = decode(payload, "payload is not base64url")?;
    let claim: Claim = serde_json::from_slice(&payload_bytes)
        .map_err(|_| Error::MalformedJws("payload is not a claim"))?;
    if claim.canonical_json() != payload_bytes {
        return Err(Error::MalformedJws(
            "payload is not RFC 8785 canonical JSON",
        ));
    }
    let signature = Signature::from_bytes(&decode(signature, "signature is not base64url")?)
        .ok_or(Error::MalformedJws("signature is not 64 bytes r||s"))?;
    let signing_input = &jws[..header.len() + 1 + payload.len()];
    if !claim
        .device_key
        .verify(signing_input.as_bytes(), &signature)
    {
        return Err(Error::BadSignature("claim signature"));
    }
    if claim.device != Pseudonym::of(&claim.device_key) {
        return Err(Error::PseudonymMismatch);
    }
    Ok(VerifiedClaim {
        jws: jws.to_string(),
        claim,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_key;

    fn fixed_key() -> SigningKey {
        SigningKey::from_slice(&[1; 32]).unwrap()
    }

    pub(crate) fn claim_for(key: &SigningKey) -> Claim {
        let device_key = PublicKey::from(key);
        Claim {
            manifest: ManifestHash::of(b"manifest_version = 1\n"),
            device: Pseudonym::of(&device_key),
            device_key,
            nonce: "n0".into(),
            time: "2026-11-03T08:12:44Z".parse().unwrap(),
            client: "open-pact-client 0.0.1".into(),
            os: Os::Macos,
            trust_level: TrustLevel::L0,
            virtualized: Virtualized::No,
            results: BTreeMap::from([
                ("firewall".into(), "on".into()),
                ("disk_encryption".into(), "full".into()),
            ]),
            csr_pem: None,
            log_checkpoint: None,
        }
    }

    #[test]
    fn canonical_json_is_sorted_compact_and_fixed() {
        let json = String::from_utf8(claim_for(&fixed_key()).canonical_json()).unwrap();
        assert_eq!(
            json,
            concat!(
                r#"{"client":"open-pact-client 0.0.1","device":"pseudonym:256b1be32745d1d1c9d49121cc87bc451c4f2dfa756d89b4c910afaeb6258ae0","#,
                r#""device_key":{"crv":"P-256","kty":"EC","x":"b_A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhY","y":"PE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo"},"#,
                r#""manifest":"sha256:0e7703839cc84cfdd6ecfb5302c1a2c4b1161c7a0642bb4518e37a43f6db9c0a","nonce":"n0","os":"macos","#,
                r#""results":{"disk_encryption":"full","firewall":"on"},"time":"2026-11-03T08:12:44Z","trust_level":"L0","virtualized":"no"}"#
            )
        );
    }

    #[test]
    fn log_checkpoint_is_signed_with_the_claim() {
        let key = fixed_key();
        let mut claim = claim_for(&key);
        claim.log_checkpoint = Some(LogCheckpoint {
            size: 3,
            root: LogHash([0xab; 32]),
        });
        let json = String::from_utf8(claim.canonical_json()).unwrap();
        assert!(json.contains(
            r#""log_checkpoint":{"root":"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=","size":3}"#
        ));
        let jws = sign_claim(&claim, &key).unwrap();
        assert_eq!(verify_claim(&jws).unwrap().claim(), &claim);
    }

    #[test]
    fn canonical_json_ignores_input_key_order() {
        let claim = claim_for(&fixed_key());
        let value = serde_json::to_value(&claim).unwrap();
        let mut reversed = serde_json::Map::new();
        for (k, v) in value.as_object().unwrap().iter().rev() {
            reversed.insert(k.clone(), v.clone());
        }
        let reparsed: Claim = serde_json::from_value(serde_json::Value::Object(reversed)).unwrap();
        assert_eq!(reparsed.canonical_json(), claim.canonical_json());
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = dev_key::generate();
        let claim = claim_for(&key);
        let jws = sign_claim(&claim, &key).unwrap();
        let header = jws.split('.').next().unwrap();
        assert_eq!(B64.decode(header).unwrap(), HEADER.as_bytes());
        let verified = verify_claim(&jws).unwrap();
        assert_eq!(verified.claim(), &claim);
        assert_eq!(verified.jws(), jws);
    }

    #[test]
    fn sign_refuses_a_foreign_key() {
        assert!(matches!(
            sign_claim(&claim_for(&fixed_key()), &dev_key::generate()),
            Err(Error::KeyMismatch)
        ));
    }

    fn resign(key: &SigningKey, payload: &[u8]) -> String {
        let input = format!("{}.{}", B64.encode(HEADER), B64.encode(payload));
        format!(
            "{input}.{}",
            Signature::sign(key, input.as_bytes()).to_b64()
        )
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = dev_key::generate();
        let jws = sign_claim(&claim_for(&key), &key).unwrap();
        let mut claim = claim_for(&key);
        claim
            .results
            .insert("disk_encryption".into(), "none".into());
        let forged_payload = B64.encode(claim.canonical_json());
        let parts: Vec<&str> = jws.split('.').collect();
        let forged = format!("{}.{forged_payload}.{}", parts[0], parts[2]);
        assert!(matches!(verify_claim(&forged), Err(Error::BadSignature(_))));
    }

    #[test]
    fn verify_rejects_swapped_key() {
        let (key, other) = (dev_key::generate(), dev_key::generate());
        let mut claim = claim_for(&key);
        claim.device_key = PublicKey::from(&other);
        let jws = resign(&key, &claim.canonical_json());
        assert!(matches!(verify_claim(&jws), Err(Error::BadSignature(_))));
    }

    #[test]
    fn verify_rejects_pseudonym_of_another_key() {
        let key = dev_key::generate();
        let mut claim = claim_for(&key);
        claim.device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let jws = resign(&key, &claim.canonical_json());
        assert!(matches!(verify_claim(&jws), Err(Error::PseudonymMismatch)));
    }

    #[test]
    fn verify_rejects_non_canonical_payload() {
        let key = dev_key::generate();
        let claim = claim_for(&key);
        let pretty = serde_json::to_vec_pretty(&claim).unwrap();
        assert!(matches!(
            verify_claim(&resign(&key, &pretty)),
            Err(Error::MalformedJws(_))
        ));
    }

    #[test]
    fn verify_rejects_other_header() {
        let key = dev_key::generate();
        let jws = sign_claim(&claim_for(&key), &key).unwrap();
        let none_header = B64.encode(r#"{"alg":"none","typ":"open-pact-claim+jws"}"#);
        let rest = jws.split_once('.').unwrap().1;
        assert!(matches!(
            verify_claim(&format!("{none_header}.{rest}")),
            Err(Error::MalformedJws(_))
        ));
        assert!(matches!(
            verify_claim(&format!("{jws}.x")),
            Err(Error::MalformedJws(_))
        ));
    }
}
