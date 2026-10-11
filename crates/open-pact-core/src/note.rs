//! Log checkpoints (c2sp.org/tlog-checkpoint) in signed-note format (c2sp.org/signed-note).
//!
//! The gateway signs with ECDSA P-256, signed-note type 0x02 as transparency-dev/formats implements
//! it, so the log key can live in the same hardware as the other keys. Witnesses cosign with
//! Ed25519 `cosignature/v1`, type 0x04 (c2sp.org/tlog-cosignature).

use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use crate::crypto::sign_der;
use crate::{Error, LogHash, PublicKey, SigningKey};

const ALG_ECDSA_SHA256: u8 = 0x02;
const ALG_COSIGNATURE_V1: u8 = 0x04;

fn bad(msg: impl Into<String>) -> Error {
    Error::Log(msg.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: LogHash,
}

impl Checkpoint {
    pub fn body(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            STANDARD.encode(self.root.0)
        )
    }

    /// Parses a checkpoint body without checking any signature.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let lines: Vec<&str> = text
            .strip_suffix('\n')
            .ok_or_else(|| bad("checkpoint must end with a newline"))?
            .split('\n')
            .collect();
        let [origin, size, root] = lines.as_slice() else {
            return Err(bad(
                "checkpoint must have exactly origin, size and root lines",
            ));
        };
        let size = size
            .parse::<u64>()
            .ok()
            .filter(|n| n.to_string() == *size)
            .ok_or_else(|| bad(format!("bad checkpoint size {size:?}")))?;
        let root = STANDARD
            .decode(root)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| bad(format!("bad checkpoint root {root:?}")))?;
        if origin.is_empty() {
            return Err(bad("empty checkpoint origin"));
        }
        Ok(Checkpoint {
            origin: origin.to_string(),
            size,
            root: LogHash(root),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    pub name: String,
    /// Key ID (4 bytes) followed by the signature.
    pub payload: Vec<u8>,
}

impl fmt::Display for NoteSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "\u{2014} {} {}",
            self.name,
            STANDARD.encode(&self.payload)
        )
    }
}

impl NoteSignature {
    pub fn parse(line: &str) -> Result<Self, Error> {
        let rest = line.strip_prefix("\u{2014} ").ok_or_else(|| {
            bad(format!(
                "signature line must start with an em dash: {line:?}"
            ))
        })?;
        let (name, b64) = rest
            .split_once(' ')
            .ok_or_else(|| bad(format!("bad signature line {line:?}")))?;
        let payload = STANDARD
            .decode(b64)
            .ok()
            .filter(|p| p.len() > 4 && !name.is_empty())
            .ok_or_else(|| bad(format!("bad signature line {line:?}")))?;
        Ok(NoteSignature {
            name: name.to_string(),
            payload,
        })
    }

    fn id(&self) -> &[u8] {
        &self.payload[..4]
    }

    fn signature(&self) -> &[u8] {
        &self.payload[4..]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub text: String,
    pub signatures: Vec<NoteSignature>,
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.text)?;
        self.signatures.iter().try_for_each(|s| s.fmt(f))
    }
}

impl Note {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let split = s
            .rfind("\n\n")
            .ok_or_else(|| bad("signed note has no blank line before its signatures"))?;
        let sigs = &s[split + 2..];
        let signatures = sigs
            .strip_suffix('\n')
            .ok_or_else(|| bad("signed note must end with a newline"))?
            .split('\n')
            .map(NoteSignature::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Note {
            text: s[..split + 1].to_string(),
            signatures,
        })
    }
}

fn key_id(bytes: &[&[u8]]) -> [u8; 4] {
    let mut h = Sha256::new();
    bytes.iter().for_each(|b| h.update(b));
    h.finalize()[..4].try_into().expect("4 bytes")
}

fn parse_vkey(vkey: &str, alg: u8) -> Result<(String, [u8; 4], Vec<u8>), Error> {
    let mut parts = vkey.trim().splitn(3, '+');
    let (Some(name), Some(id), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(bad(format!("verifier key must be name+id+key: {vkey:?}")));
    };
    let id = hex::decode(id)
        .ok()
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .ok_or_else(|| bad(format!("bad key id in {vkey:?}")))?;
    let key = STANDARD
        .decode(key)
        .ok()
        .filter(|k| k.first() == Some(&alg))
        .ok_or_else(|| {
            bad(format!(
                "verifier key is not signature type {alg:#04x}: {vkey:?}"
            ))
        })?;
    Ok((name.to_string(), id, key[1..].to_vec()))
}

/// The gateway's checkpoint key. The key name is the log origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogKey {
    name: String,
    key: PublicKey,
}

impl LogKey {
    pub fn new(origin: &str, key: &PublicKey) -> Self {
        LogKey {
            name: origin.to_string(),
            key: key.clone(),
        }
    }

    pub fn origin(&self) -> &str {
        &self.name
    }

    fn id(&self) -> [u8; 4] {
        key_id(&[&self.key.spki_der()])
    }

    /// `<name>+<hex id>+<base64(0x02 || DER SPKI)>`, the verifier key format of transparency-dev/formats.
    pub fn vkey(&self) -> String {
        let mut key = vec![ALG_ECDSA_SHA256];
        key.extend(self.key.spki_der());
        format!(
            "{}+{}+{}",
            self.name,
            hex::encode(self.id()),
            STANDARD.encode(key)
        )
    }

    pub fn parse(vkey: &str) -> Result<Self, Error> {
        let (name, id, der) = parse_vkey(vkey, ALG_ECDSA_SHA256)?;
        let key = LogKey {
            name,
            key: PublicKey::from_spki_der(&der)?,
        };
        if key.id() != id {
            return Err(bad(format!("key id does not match the key in {vkey:?}")));
        }
        Ok(key)
    }

    pub fn sign(&self, signer: &SigningKey, checkpoint: &Checkpoint) -> Note {
        assert_eq!(
            PublicKey::from(signer),
            self.key,
            "signer is not this log key"
        );
        assert_eq!(
            checkpoint.origin, self.name,
            "checkpoint origin is the key name"
        );
        let text = checkpoint.body();
        let mut payload = self.id().to_vec();
        payload.extend(sign_der(signer, text.as_bytes()));
        Note {
            text,
            signatures: vec![NoteSignature {
                name: self.name.clone(),
                payload,
            }],
        }
    }

    /// Returns the checkpoint if this key signed it. Signatures by other keys are ignored.
    pub fn verify(&self, note: &Note) -> Result<Checkpoint, Error> {
        let checkpoint = Checkpoint::parse(&note.text)?;
        if checkpoint.origin != self.name {
            return Err(bad(format!(
                "checkpoint origin {:?} is not the pinned log {:?}",
                checkpoint.origin, self.name
            )));
        }
        let mine: Vec<&NoteSignature> = note
            .signatures
            .iter()
            .filter(|s| s.name == self.name && s.id() == self.id())
            .collect();
        if mine.is_empty() {
            return Err(Error::BadSignature(
                "checkpoint has no signature by the log key",
            ));
        }
        if !mine
            .iter()
            .all(|s| self.key.verify_der(note.text.as_bytes(), s.signature()))
        {
            return Err(Error::BadSignature("checkpoint"));
        }
        Ok(checkpoint)
    }
}

fn cosigned_message(checkpoint: &Checkpoint, timestamp: u64) -> String {
    format!("cosignature/v1\ntime {timestamp}\n{}", checkpoint.body())
}

/// A witness verifier key, c2sp.org/tlog-cosignature `cosignature/v1` (Ed25519).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessKey {
    name: String,
    key: ed25519_dalek::VerifyingKey,
}

impl WitnessKey {
    pub fn new(name: &str, key: ed25519_dalek::VerifyingKey) -> Self {
        WitnessKey {
            name: name.to_string(),
            key,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> [u8; 4] {
        key_id(&[
            self.name.as_bytes(),
            b"\n",
            &[ALG_COSIGNATURE_V1],
            self.key.as_bytes(),
        ])
    }

    pub fn vkey(&self) -> String {
        let mut key = vec![ALG_COSIGNATURE_V1];
        key.extend(self.key.as_bytes());
        format!(
            "{}+{}+{}",
            self.name,
            hex::encode(self.id()),
            STANDARD.encode(key)
        )
    }

    pub fn parse(vkey: &str) -> Result<Self, Error> {
        let (name, id, raw) = parse_vkey(vkey, ALG_COSIGNATURE_V1)?;
        let key = <[u8; 32]>::try_from(raw)
            .ok()
            .and_then(|k| ed25519_dalek::VerifyingKey::from_bytes(&k).ok())
            .ok_or(Error::InvalidKey)?;
        let key = WitnessKey { name, key };
        if key.id() != id {
            return Err(bad(format!("key id does not match the key in {vkey:?}")));
        }
        Ok(key)
    }

    pub fn cosign(
        &self,
        signer: &ed25519_dalek::SigningKey,
        checkpoint: &Checkpoint,
        timestamp: u64,
    ) -> NoteSignature {
        use ed25519_dalek::Signer;
        assert_eq!(
            signer.verifying_key(),
            self.key,
            "signer is not this witness key"
        );
        let sig = signer.sign(cosigned_message(checkpoint, timestamp).as_bytes());
        let mut payload = self.id().to_vec();
        payload.extend(timestamp.to_be_bytes());
        payload.extend(sig.to_bytes());
        NoteSignature {
            name: self.name.clone(),
            payload,
        }
    }

    /// `None` if the signature is not from this key; otherwise whether it verifies, with its timestamp.
    pub fn verify(
        &self,
        checkpoint: &Checkpoint,
        sig: &NoteSignature,
    ) -> Option<Result<u64, Error>> {
        if sig.name != self.name || sig.id() != self.id() {
            return None;
        }
        let body = sig.signature();
        let valid = <[u8; 72]>::try_from(body).ok().and_then(|b| {
            let timestamp = u64::from_be_bytes(b[..8].try_into().expect("8 bytes"));
            let signature = ed25519_dalek::Signature::from_bytes(&b[8..].try_into().expect("64"));
            self.key
                .verify_strict(
                    cosigned_message(checkpoint, timestamp).as_bytes(),
                    &signature,
                )
                .ok()
                .map(|()| timestamp)
        });
        Some(valid.ok_or(Error::BadSignature("witness cosignature")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_key;

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            origin: "pact.example.com/log".into(),
            size: 3,
            root: LogHash([7; 32]),
        }
    }

    fn witness() -> (ed25519_dalek::SigningKey, WitnessKey) {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let key = WitnessKey::new("witness.example.org/w1", signer.verifying_key());
        (signer, key)
    }

    #[test]
    fn checkpoint_body_is_origin_size_base64_root() {
        assert_eq!(
            checkpoint().body(),
            "pact.example.com/log\n3\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n"
        );
        assert_eq!(
            Checkpoint::parse(&checkpoint().body()).unwrap(),
            checkpoint()
        );
        for bad in [
            "pact.example.com/log\n03\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n",
            "pact.example.com/log\n3\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\next\n",
            "pact.example.com/log\n3\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwd=\n",
            "pact.example.com/log\n3\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        ] {
            assert!(Checkpoint::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn log_signature_roundtrips_through_text_and_vkey() {
        let signer = dev_key::generate();
        let key = LogKey::new("pact.example.com/log", &PublicKey::from(&signer));
        let note = key.sign(&signer, &checkpoint());
        let text = note.to_string();
        assert!(text.starts_with(&format!(
            "{}\n\u{2014} pact.example.com/log ",
            checkpoint().body()
        )));
        let pinned = LogKey::parse(&key.vkey()).unwrap();
        assert_eq!(pinned, key);
        assert_eq!(
            pinned.verify(&Note::parse(&text).unwrap()).unwrap(),
            checkpoint()
        );
    }

    #[test]
    fn log_key_rejects_forged_or_foreign_checkpoints() {
        let signer = dev_key::generate();
        let key = LogKey::new("pact.example.com/log", &PublicKey::from(&signer));
        let mut note = key.sign(&signer, &checkpoint());
        note.text = note.text.replace("\n3\n", "\n4\n");
        assert!(matches!(key.verify(&note), Err(Error::BadSignature(_))));

        let other = dev_key::generate();
        let impostor = LogKey::new("pact.example.com/log", &PublicKey::from(&other));
        let note = impostor.sign(&other, &checkpoint());
        assert!(matches!(key.verify(&note), Err(Error::BadSignature(_))));

        let renamed = LogKey::new("evil.example.net/log", &PublicKey::from(&signer));
        let cp = Checkpoint {
            origin: "evil.example.net/log".into(),
            ..checkpoint()
        };
        assert!(key.verify(&renamed.sign(&signer, &cp)).is_err());
    }

    #[test]
    fn vkey_rejects_wrong_id_or_type() {
        let key = LogKey::new(
            "pact.example.com/log",
            &PublicKey::from(&dev_key::generate()),
        );
        let vkey = key.vkey();
        let (name, rest) = vkey.split_once('+').unwrap();
        let wrong_id = format!("{name}+00000000+{}", rest.split_once('+').unwrap().1);
        assert!(LogKey::parse(&wrong_id).is_err());
        assert!(WitnessKey::parse(&vkey).is_err());
        assert!(LogKey::parse(&witness().1.vkey()).is_err());
    }

    #[test]
    fn witness_cosignature_verifies_and_rejects_other_checkpoints() {
        let (signer, key) = witness();
        let parsed = WitnessKey::parse(&key.vkey()).unwrap();
        let sig = key.cosign(&signer, &checkpoint(), 1_790_000_000);
        let sig = NoteSignature::parse(sig.to_string().trim_end_matches('\n')).unwrap();
        assert_eq!(
            parsed.verify(&checkpoint(), &sig).unwrap().unwrap(),
            1_790_000_000
        );
        let later = Checkpoint {
            size: 4,
            ..checkpoint()
        };
        assert!(parsed.verify(&later, &sig).unwrap().is_err());
        let other = WitnessKey::new("witness.example.org/w2", signer.verifying_key());
        assert!(other.verify(&checkpoint(), &sig).is_none());
    }

    /// The message layout of c2sp.org/tlog-cosignature, checked byte for byte.
    #[test]
    fn cosignature_signs_the_documented_message() {
        let (signer, key) = witness();
        let sig = key.cosign(&signer, &checkpoint(), 1_790_000_000);
        assert_eq!(&sig.payload[4..12], &1_790_000_000u64.to_be_bytes());
        let message = format!(
            "cosignature/v1\ntime 1790000000\npact.example.com/log\n3\n{}\n",
            STANDARD.encode([7u8; 32])
        );
        let signature =
            ed25519_dalek::Signature::from_bytes(&sig.payload[12..].try_into().unwrap());
        signer
            .verifying_key()
            .verify_strict(message.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn note_with_cosignatures_roundtrips() {
        let signer = dev_key::generate();
        let key = LogKey::new("pact.example.com/log", &PublicKey::from(&signer));
        let (wsigner, witness) = witness();
        let mut note = key.sign(&signer, &checkpoint());
        note.signatures
            .push(witness.cosign(&wsigner, &checkpoint(), 5));
        let back = Note::parse(&note.to_string()).unwrap();
        assert_eq!(back, note);
        assert_eq!(key.verify(&back).unwrap(), checkpoint());
        assert!(Note::parse(&checkpoint().body()).is_err());
    }
}
