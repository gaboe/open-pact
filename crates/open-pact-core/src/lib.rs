mod claim;
mod crypto;
pub mod dev_key;
mod evaluate;
mod log;
mod manifest;
mod narrowing;

pub use claim::{Claim, VerifiedClaim, Virtualized, sign_claim, verify_claim};
pub use crypto::{Endorsement, ManifestHash, Pseudonym, PublicKey, Signature, SignedManifest};
pub use evaluate::{Decision, Reason, evaluate};
pub use log::{Entry, EntryKind, Head, LogHash, verify_chain};
pub use manifest::{Accepted, Control, Manifest, ManifestBody, Os, Source, Span, TrustLevel};
pub use narrowing::{Violation, is_narrowing};
pub use p256::ecdsa::SigningKey;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("manifest is not valid TOML: {0}")]
    ManifestToml(#[from] toml::de::Error),
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid public key")]
    InvalidKey,
    #[error("signature does not verify: {0}")]
    BadSignature(&'static str),
    #[error("malformed JWS: {0}")]
    MalformedJws(&'static str),
    #[error("device pseudonym does not match the device key")]
    PseudonymMismatch,
    #[error("signing key does not match the claim's device key")]
    KeyMismatch,
    #[error("transparency log: {0}")]
    Log(String),
    #[error("key file {path}: {reason}")]
    KeyFile { path: String, reason: String },
}
