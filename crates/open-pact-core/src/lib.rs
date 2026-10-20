mod claim;
mod crypto;
pub mod dev_key;
mod enrol;
mod evaluate;
mod invitation;
mod log;
mod manifest;
mod narrowing;
mod note;
mod witness;

pub use claim::{
    Claim, LogCheckpoint, VerifiedClaim, Virtualized, sign_claim, sign_claim_with, verify_claim,
};
pub use crypto::{
    CsrHash, Endorsement, ManifestHash, Pseudonym, PublicKey, Signature, SignedManifest,
};
pub use enrol::{EnrolRequest, enrol_statement};
pub use evaluate::{
    Decision, Evaluation, FirstFailures, Grace, Reason, evaluate, verified_trust_level,
};
pub use invitation::{InvalidInvitation, Invitation, InvitationCode, InvitationHash};
pub use log::{
    Entry, EntryKind, LogHash, consistency_proof, inclusion_proof, leaf_hash, root,
    verify_consistency, verify_inclusion,
};
pub use manifest::{
    Accepted, AcceptedValues, Control, ControlValue, IntegerOutput, IntegerRange, LogPolicy,
    Manifest, ManifestBody, Maximum, Metadata, Minimum, Os, Output, Source, Span, TrustLevel,
    Witness,
};
pub use narrowing::{Violation, is_narrowing};
pub use note::{Checkpoint, LogKey, Note, NoteSignature, WitnessKey};
pub use p256::ecdsa::SigningKey;
pub use witness::{AddCheckpoint, CLOCK_SKEW_SECS, Refusal, add_checkpoint, verify_cosignatures};

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
