//! The invitation IT sends to a device owner: the gateway address, the keys the client must find
//! there, and a one-time code. The gateway stores only the code's hash.

use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{LogKey, PublicKey};

const PREFIX: &str = "opi1:";

/// 256 random bits. Debug does not print them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InvitationCode([u8; 32]);

impl InvitationCode {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn hash(&self) -> InvitationHash {
        InvitationHash(format!("sha256:{}", hex::encode(Sha256::digest(self.0))))
    }
}

impl fmt::Debug for InvitationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InvitationCode({})", self.hash())
    }
}

impl TryFrom<String> for InvitationCode {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        B64.decode(&s)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(Self)
            .ok_or_else(|| "expected an invitation code of 32 bytes in base64url".into())
    }
}

impl From<InvitationCode> for String {
    fn from(code: InvitationCode) -> String {
        B64.encode(code.0)
    }
}

/// `sha256:<hex>` of the code bytes, the only form the gateway keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InvitationHash(String);

impl InvitationHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for InvitationHash {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let hex = s.strip_prefix("sha256:").unwrap_or_default();
        if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(s))
        } else {
            Err(format!("expected sha256:<64 lowercase hex>, got {s:?}"))
        }
    }
}

impl From<InvitationHash> for String {
    fn from(h: InvitationHash) -> String {
        h.0
    }
}

impl fmt::Display for InvitationHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub gateway: String,
    /// `PublicKey::fingerprint` of the company manifest-signing key.
    pub company: String,
    /// The log verifier key, `<origin>+<key id>+<base64 key>`.
    pub log: String,
    pub code: InvitationCode,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not a valid invitation: {0}")]
pub struct InvalidInvitation(String);

impl Invitation {
    pub fn new(gateway: &str, company: &PublicKey, log: &LogKey, code: InvitationCode) -> Self {
        Self {
            gateway: gateway.trim_end_matches('/').to_string(),
            company: company.fingerprint(),
            log: log.vkey(),
            code,
        }
    }

    pub fn encode(&self) -> String {
        let json = serde_jcs::to_vec(self).expect("invitation fields always serialize");
        format!("{PREFIX}{}", B64.encode(json))
    }

    pub fn decode(text: &str) -> Result<Self, InvalidInvitation> {
        let bad = |why: &str| InvalidInvitation(why.to_string());
        let body = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or_else(|| bad("it must start with opi1:"))?;
        let json = B64
            .decode(body)
            .map_err(|_| bad("the part after opi1: is not base64url"))?;
        let invitation: Invitation =
            serde_json::from_slice(&json).map_err(|e| InvalidInvitation(e.to_string()))?;
        LogKey::parse(&invitation.log).map_err(|e| InvalidInvitation(e.to_string()))?;
        if !invitation.company.starts_with("sha256:") {
            return Err(bad("company must be a sha256: key fingerprint"));
        }
        Ok(invitation)
    }

    pub fn log_key(&self) -> LogKey {
        LogKey::parse(&self.log).expect("decode checked the log key")
    }

    /// The form IT reads out or compares by eye. It leaves out the code.
    pub fn describe(&self) -> String {
        format!(
            "Gateway      {}\nCompany key  {}\nLog key      {}\n",
            self.gateway, self.company, self.log
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_key;

    fn invitation() -> Invitation {
        let key = PublicKey::from(&dev_key::generate());
        let log = LogKey::new(
            "pact.example.com/log",
            &PublicKey::from(&dev_key::generate()),
        );
        Invitation::new(
            "https://pact.example.com/",
            &key,
            &log,
            InvitationCode::from_bytes([7; 32]),
        )
    }

    #[test]
    fn encodes_and_decodes_to_the_same_invitation() {
        let inv = invitation();
        let text = inv.encode();
        assert!(text.starts_with("opi1:"));
        assert_eq!(Invitation::decode(&text).unwrap(), inv);
        assert_eq!(Invitation::decode(&format!("  {text}\n")).unwrap(), inv);
        assert_eq!(inv.gateway, "https://pact.example.com");
    }

    #[test]
    fn rejects_other_prefixes_extra_fields_and_short_codes() {
        let inv = invitation();
        assert!(Invitation::decode(&inv.encode().replacen("opi1:", "opi2:", 1)).is_err());
        let mut json = serde_json::to_value(&inv).unwrap();
        json["admin"] = true.into();
        let extra = format!("opi1:{}", B64.encode(json.to_string()));
        assert!(Invitation::decode(&extra).is_err());
        json.as_object_mut().unwrap().remove("admin");
        json["code"] = B64.encode([1u8; 16]).into();
        let short = format!("opi1:{}", B64.encode(json.to_string()));
        assert!(Invitation::decode(&short).is_err());
    }

    #[test]
    fn hash_is_sha256_of_the_code_bytes_and_debug_hides_the_code() {
        let code = InvitationCode::from_bytes([0; 32]);
        assert_eq!(
            code.hash().as_str(),
            "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
        let shown = format!("{code:?}");
        assert!(!shown.contains(&String::from(code.clone())));
        assert_ne!(
            InvitationCode::from_bytes([1; 32]).hash(),
            InvitationCode::from_bytes([0; 32]).hash()
        );
    }

    #[test]
    fn describe_leaves_out_the_code() {
        let inv = invitation();
        assert!(!inv.describe().contains(&String::from(inv.code.clone())));
        assert!(inv.describe().contains(&inv.company));
    }
}
