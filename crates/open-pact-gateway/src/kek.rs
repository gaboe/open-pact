use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// The key-encryption key. AES-256-GCM with a random 96-bit nonce per value and the value's
/// name as associated data, so a sealed value cannot be moved to another name.
pub struct Kek(Aes256Gcm);

const PREFIX: &str = "kek1:";
const NONCE_LEN: usize = 12;
/// Public on purpose: `DEV_INSECURE_KEK=1` is for compose and tests, never for real data.
const DEV_INSECURE: &[u8; 32] = b"open-pact INSECURE dev KEK v1 ..";

impl Kek {
    pub fn new(key: &[u8; 32]) -> Kek {
        Kek(Aes256Gcm::new(key.into()))
    }

    /// `GATEWAY_KEK` (32 bytes, base64), or the public development key when only
    /// `DEV_INSECURE_KEK=1` is set.
    pub fn from_env() -> anyhow::Result<Kek> {
        if let Ok(b64) = std::env::var("GATEWAY_KEK") {
            return Kek::parse(&b64).context("GATEWAY_KEK");
        }
        if matches!(
            std::env::var("DEV_INSECURE_KEK").as_deref(),
            Ok("1" | "true")
        ) {
            eprintln!(
                "DEV_INSECURE_KEK=1: gateway secrets and claims are encrypted with a PUBLIC key. Development only."
            );
            return Ok(Kek::new(DEV_INSECURE));
        }
        bail!(
            "GATEWAY_KEK is not set. It encrypts the gateway keys and claims at rest. \
             Create one with `openssl rand -base64 32` and keep a copy outside the database; \
             without it the stored keys and claims cannot be read."
        )
    }

    pub fn parse(b64: &str) -> anyhow::Result<Kek> {
        let bytes = STANDARD.decode(b64.trim()).context("must be base64")?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| anyhow::anyhow!("must be 32 bytes, got {}", b.len()))?;
        Ok(Kek::new(&key))
    }

    pub fn is_sealed(value: &str) -> bool {
        value.starts_with(PREFIX)
    }

    pub fn seal(&self, name: &str, plaintext: &[u8]) -> String {
        let nonce: [u8; NONCE_LEN] = rand::random();
        let mut out = nonce.to_vec();
        out.extend(
            self.0
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: name.as_bytes(),
                    },
                )
                .expect("AES-GCM encrypts any message under 64 GiB"),
        );
        format!("{PREFIX}{}", STANDARD.encode(out))
    }

    pub fn open(&self, name: &str, sealed: &str) -> anyhow::Result<Vec<u8>> {
        let Some(b64) = sealed.strip_prefix(PREFIX) else {
            bail!("{name} is not sealed");
        };
        let bytes = STANDARD.decode(b64).with_context(|| name.to_string())?;
        if bytes.len() < NONCE_LEN {
            bail!("{name} is too short");
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        self.0
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("cannot decrypt {name}: wrong key or tampered value"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> Kek {
        Kek::new(&[7; 32])
    }

    #[test]
    fn opens_what_it_sealed_under_the_same_name_only() {
        let sealed = kek().seal("ca_key", b"-----BEGIN PRIVATE KEY-----");
        assert!(Kek::is_sealed(&sealed));
        assert!(!sealed.contains("BEGIN"));
        assert_eq!(
            kek().open("ca_key", &sealed).unwrap(),
            b"-----BEGIN PRIVATE KEY-----"
        );
        assert!(kek().open("log_signing_key", &sealed).is_err());
        assert!(Kek::new(&[8; 32]).open("ca_key", &sealed).is_err());
        assert_ne!(sealed, kek().seal("ca_key", b"-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn rejects_a_tampered_value() {
        let sealed = kek().seal("n", b"secret");
        let mut bytes = STANDARD.decode(&sealed[PREFIX.len()..]).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = format!("{PREFIX}{}", STANDARD.encode(bytes));
        assert!(kek().open("n", &tampered).is_err());
        assert!(kek().open("n", "-----BEGIN").is_err());
    }

    #[test]
    fn parses_32_base64_bytes_with_the_newline_openssl_prints() {
        let b64 = format!("{}\n", STANDARD.encode([1u8; 32]));
        assert!(Kek::parse(&b64).is_ok());
        assert!(Kek::parse(&STANDARD.encode([1u8; 16])).is_err());
        assert!(Kek::parse("not base64!").is_err());
    }
}
