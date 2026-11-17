//! Keyless verification of a release: proves that the SHA256SUMS of a tag was signed by this
//! repository's release workflow, from bytes only.
//!
//! Input: the SHA256SUMS bytes, the Sigstore bundle (SHA256SUMS.sigstore.json) bytes, the tag and
//! the repository the caller expects. Output: [Verified] or a typed [ReleaseVerifyError]. The module
//! opens no connection and reads no clock; the only time it uses is the Rekor integrated time that
//! the bundle records and the pinned Rekor key signs.
//!
//! Checks, in this order:
//! 1. The bundle is a Sigstore bundle v0.3 with one hashedrekord entry that has a signed entry
//!    timestamp (SET), and its message digest is the SHA-256 of the SHA256SUMS bytes.
//! 2. The SET verifies with the pinned Rekor key (ECDSA P-256), which makes the integrated time
//!    trustworthy. The entry body names the same digest, signature and certificate.
//! 3. The certificate chains to the pinned Fulcio intermediate and root, and each of the three is
//!    valid at the integrated time.
//! 4. The certificate names the identity
//!    `https://github.com/<repository>/.github/workflows/client-release.yml@refs/tags/<tag>`,
//!    the issuer `https://token.actions.githubusercontent.com` and the code signing purpose.
//! 5. The signature over the SHA256SUMS bytes verifies with the certificate key (ECDSA P-256).
//!
//! Left out on purpose: the signed certificate timestamp (the SET already proves that the log saw
//! the certificate at signing time), the Merkle inclusion proof and the timestamp authority. A
//! bundle that has no SET (Rekor v2) fails with [ReleaseVerifyError::RekorEntryMissing]; the release
//! job runs this verifier on its own bundle before upload, so a format change fails the release,
//! not the devices.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::der_parser::der::parse_der_utf8string;
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

/// The OIDC issuer of GitHub Actions, the only issuer a release signature may name.
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The workflow file whose run signs the release.
pub const WORKFLOW: &str = ".github/workflows/client-release.yml";

/// Fulcio v2 issuer extension (a DER UTF8String) and its deprecated v1 form (the raw string).
const OID_ISSUER_V2: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 8];
const OID_ISSUER_V1: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];

// Pinned Sigstore public-good instance trust material.
// Source: https://tuf-repo-cdn.sigstore.dev/targets/6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66.trusted_root.json
// (the same file as https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json,
// media type application/vnd.dev.sigstore.trustedroot+json;version=0.1), fetched 2026-11-17.
// Fulcio: the certificateAuthorities entry for https://fulcio.sigstore.dev valid from 2022-04-13,
// chain order intermediate (sigstore-intermediate) then root (sigstore), both DER in base64.
// Rekor: the tlogs entry for https://rekor.sigstore.dev, PKIX ECDSA P-256 SPKI DER in base64.
const FULCIO_INTERMEDIATE: &str = "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=";
const FULCIO_ROOT: &str = "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ";
const REKOR_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";

/// The keys a release signature must chain to.
#[derive(Clone, Debug)]
pub struct TrustRoot {
    /// DER of the Fulcio intermediate that signs the leaf certificate.
    pub fulcio_intermediate: Vec<u8>,
    /// DER of the Fulcio root that signs the intermediate.
    pub fulcio_root: Vec<u8>,
    /// DER SubjectPublicKeyInfo of the Rekor key (ECDSA P-256) that signs entry timestamps.
    pub rekor_key: Vec<u8>,
}

impl TrustRoot {
    /// The Sigstore public-good instance, compiled in.
    pub fn pinned() -> Self {
        let decode = |text: &str| {
            STANDARD
                .decode(text)
                .expect("pinned trust material is base64")
        };
        Self {
            fulcio_intermediate: decode(FULCIO_INTERMEDIATE),
            fulcio_root: decode(FULCIO_ROOT),
            rekor_key: decode(REKOR_KEY),
        }
    }
}

/// The parsed SHA256SUMS of a verified release: asset name to lower-case hex SHA-256.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sums(BTreeMap<String, String>);

impl Sums {
    /// The hex SHA-256 that the release lists for an asset, if it lists one.
    pub fn hash_of(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, hash)| (name.as_str(), hash.as_str()))
    }

    fn parse(bytes: &[u8]) -> Result<Self, ReleaseVerifyError> {
        let bad = |line: usize, why: &str| {
            ReleaseVerifyError::MalformedSums(format!("line {line}: {why}"))
        };
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ReleaseVerifyError::MalformedSums("not UTF-8".to_owned()))?;
        let mut entries = BTreeMap::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            if line.is_empty() {
                continue;
            }
            let (hash, rest) = line
                .split_at_checked(64)
                .ok_or_else(|| bad(number, "too short"))?;
            if !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(bad(number, "the hash is not hex"));
            }
            let name = rest
                .strip_prefix("  ")
                .or_else(|| rest.strip_prefix(" *"))
                .ok_or_else(|| bad(number, "no separator after the hash"))?;
            if name.is_empty() || name.contains(['/', '\\']) {
                return Err(bad(number, "the asset name is empty or has a path"));
            }
            if entries
                .insert(name.to_owned(), hash.to_ascii_lowercase())
                .is_some()
            {
                return Err(bad(number, "the asset is listed twice"));
            }
        }
        if entries.is_empty() {
            return Err(ReleaseVerifyError::MalformedSums("no entries".to_owned()));
        }
        Ok(Self(entries))
    }
}

/// A release whose SHA256SUMS was signed by this repository's release workflow for this tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified {
    pub tag: String,
    pub sums: Sums,
}

/// Why a release did not verify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseVerifyError {
    /// The bundle is not valid JSON or lacks a field.
    MalformedBundle(String),
    /// The bundle has a shape this verifier does not read (media type, entry kind, no SET).
    UnsupportedBundle(String),
    MalformedSums(String),
    /// The bundle digest is not the SHA-256 of the SHA256SUMS bytes.
    DigestMismatch,
    /// The bundle has no Rekor entry with a signed entry timestamp.
    RekorEntryMissing,
    /// The entry was signed by a log other than the pinned one.
    RekorKeyUnknown,
    /// The signed entry timestamp does not verify with the pinned Rekor key.
    RekorSetInvalid,
    /// The Rekor entry body does not bind the signature, the digest or the certificate of the bundle.
    RekorEntryMismatch(&'static str),
    /// The certificate does not parse.
    BadCertificate(String),
    /// The certificate does not chain to the pinned Fulcio root.
    UntrustedCertificate,
    /// The certificate, or a pinned CA, was not valid at the Rekor integrated time.
    CertificateNotValidAtLogTime {
        integrated_time: i64,
    },
    WrongIdentity {
        expected: String,
        found: Vec<String>,
    },
    WrongIssuer {
        expected: String,
        found: Vec<String>,
    },
    /// The certificate is not issued for code signing.
    WrongPurpose,
    /// The signature over SHA256SUMS does not verify with the certificate key.
    SignatureInvalid,
}

impl fmt::Display for ReleaseVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedBundle(why) => {
                write!(f, "the release signature bundle is malformed: {why}")
            }
            Self::UnsupportedBundle(why) => {
                write!(f, "the release signature bundle is not supported: {why}")
            }
            Self::MalformedSums(why) => write!(f, "SHA256SUMS is malformed: {why}"),
            Self::DigestMismatch => {
                write!(f, "SHA256SUMS is not the file that the signature covers")
            }
            Self::RekorEntryMissing => write!(f, "the release signature has no signed Rekor entry"),
            Self::RekorKeyUnknown => write!(
                f,
                "the Rekor entry comes from a log this client does not trust"
            ),
            Self::RekorSetInvalid => write!(f, "the Rekor entry signature is invalid"),
            Self::RekorEntryMismatch(what) => {
                write!(f, "the Rekor entry does not match the bundle: {what}")
            }
            Self::BadCertificate(why) => write!(f, "the signing certificate is malformed: {why}"),
            Self::UntrustedCertificate => write!(
                f,
                "the signing certificate does not chain to the Sigstore root"
            ),
            Self::CertificateNotValidAtLogTime { integrated_time } => {
                write!(
                    f,
                    "the signing certificate was not valid at the log time {integrated_time}"
                )
            }
            Self::WrongIdentity { expected, found } => {
                write!(f, "the signing identity is {found:?}, not {expected}")
            }
            Self::WrongIssuer { expected, found } => {
                write!(f, "the signing issuer is {found:?}, not {expected}")
            }
            Self::WrongPurpose => {
                write!(f, "the signing certificate is not issued for code signing")
            }
            Self::SignatureInvalid => write!(f, "the signature over SHA256SUMS is invalid"),
        }
    }
}

impl std::error::Error for ReleaseVerifyError {}

/// Verify with the pinned Sigstore trust root.
pub fn verify_release(
    sums: &[u8],
    bundle: &[u8],
    tag: &str,
    repository: &str,
) -> Result<Verified, ReleaseVerifyError> {
    verify_release_with(&TrustRoot::pinned(), sums, bundle, tag, repository)
}

/// Verify with a given trust root. Production calls [verify_release]; tests pass a fictional root.
pub fn verify_release_with(
    root: &TrustRoot,
    sums: &[u8],
    bundle: &[u8],
    tag: &str,
    repository: &str,
) -> Result<Verified, ReleaseVerifyError> {
    let bundle: Bundle = serde_json::from_slice(bundle)
        .map_err(|error| ReleaseVerifyError::MalformedBundle(error.to_string()))?;
    if bundle.media_type != "application/vnd.dev.sigstore.bundle.v0.3+json" {
        return Err(ReleaseVerifyError::UnsupportedBundle(format!(
            "media type {}",
            bundle.media_type
        )));
    }
    let parsed_sums = Sums::parse(sums)?;

    // 1. The digest in the bundle is the digest of the bytes in hand.
    let digest = Sha256::digest(sums);
    let signed_digest = bundle
        .message_signature
        .message_digest
        .as_ref()
        .ok_or_else(|| ReleaseVerifyError::MalformedBundle("no message digest".to_owned()))?;
    if signed_digest.algorithm != "SHA2_256"
        || decode(&signed_digest.digest, "message digest")? != digest.as_slice()
    {
        return Err(ReleaseVerifyError::DigestMismatch);
    }
    let signature = decode(&bundle.message_signature.signature, "signature")?;

    let leaf_der = decode(
        &bundle
            .verification_material
            .certificate
            .as_ref()
            .ok_or_else(|| ReleaseVerifyError::MalformedBundle("no certificate".to_owned()))?
            .raw_bytes,
        "certificate",
    )?;
    let (_, leaf) = parse_x509_certificate(&leaf_der)
        .map_err(|error| ReleaseVerifyError::BadCertificate(error.to_string()))?;

    // 2. The Rekor entry: its time is trusted once the pinned key signed it.
    let [entry] = bundle.verification_material.tlog_entries.as_slice() else {
        return Err(ReleaseVerifyError::RekorEntryMissing);
    };
    let integrated_time = verify_rekor_entry(root, entry, &digest, &signature, &leaf_der)?;

    // 3. The chain, at the time the log saw the certificate.
    verify_chain(root, &leaf, integrated_time)?;

    // 4. Identity, issuer and purpose.
    let expected_identity = format!("https://github.com/{repository}/{WORKFLOW}@refs/tags/{tag}");
    let identities = uri_names(&leaf)?;
    if !identities.contains(&expected_identity) {
        return Err(ReleaseVerifyError::WrongIdentity {
            expected: expected_identity,
            found: identities,
        });
    }
    let issuers = issuers(&leaf)?;
    if issuers.is_empty() || issuers.iter().any(|issuer| issuer != ISSUER) {
        return Err(ReleaseVerifyError::WrongIssuer {
            expected: ISSUER.to_owned(),
            found: issuers,
        });
    }
    match leaf.extended_key_usage() {
        Ok(Some(usage)) if usage.value.code_signing => {}
        _ => return Err(ReleaseVerifyError::WrongPurpose),
    }

    // 5. The signature of SHA256SUMS.
    verify_p256(&leaf.public_key().subject_public_key.data, sums, &signature)
        .map_err(|()| ReleaseVerifyError::SignatureInvalid)?;

    Ok(Verified {
        tag: tag.to_owned(),
        sums: parsed_sums,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    media_type: String,
    verification_material: Material,
    message_signature: MessageSignature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Material {
    certificate: Option<RawCertificate>,
    #[serde(default)]
    tlog_entries: Vec<TlogEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCertificate {
    raw_bytes: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlogEntry {
    log_index: String,
    log_id: LogId,
    kind_version: KindVersion,
    integrated_time: String,
    inclusion_promise: Option<InclusionPromise>,
    canonicalized_body: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogId {
    key_id: String,
}

#[derive(Deserialize)]
struct KindVersion {
    kind: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionPromise {
    signed_entry_timestamp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageSignature {
    message_digest: Option<MessageDigest>,
    signature: String,
}

#[derive(Deserialize)]
struct MessageDigest {
    algorithm: String,
    digest: String,
}

/// What Rekor signs for a signed entry timestamp: these four fields, keys in this (sorted) order,
/// compact JSON.
#[derive(Serialize)]
struct SetPayload<'a> {
    body: &'a str,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logID")]
    log_id: String,
    #[serde(rename = "logIndex")]
    log_index: i64,
}

/// The hashedrekord 0.0.1 body, the part that binds the signed file, signature and certificate.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HashedRekord {
    api_version: String,
    kind: String,
    spec: RekordSpec,
}

#[derive(Deserialize)]
struct RekordSpec {
    data: RekordData,
    signature: RekordSignature,
}

#[derive(Deserialize)]
struct RekordData {
    hash: RekordHash,
}

#[derive(Deserialize)]
struct RekordHash {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekordSignature {
    content: String,
    public_key: RekordKey,
}

#[derive(Deserialize)]
struct RekordKey {
    content: String,
}

fn decode(text: &str, what: &str) -> Result<Vec<u8>, ReleaseVerifyError> {
    STANDARD
        .decode(text)
        .map_err(|_| ReleaseVerifyError::MalformedBundle(format!("{what} is not base64")))
}

fn number(text: &str, what: &str) -> Result<i64, ReleaseVerifyError> {
    text.parse()
        .map_err(|_| ReleaseVerifyError::MalformedBundle(format!("{what} is not a number")))
}

/// Verify the signed entry timestamp and the entry body. Returns the integrated time.
fn verify_rekor_entry(
    root: &TrustRoot,
    entry: &TlogEntry,
    digest: &[u8],
    signature: &[u8],
    leaf_der: &[u8],
) -> Result<i64, ReleaseVerifyError> {
    if entry.kind_version.kind != "hashedrekord" || entry.kind_version.version != "0.0.1" {
        return Err(ReleaseVerifyError::UnsupportedBundle(format!(
            "entry kind {} {}",
            entry.kind_version.kind, entry.kind_version.version
        )));
    }
    let promise = entry
        .inclusion_promise
        .as_ref()
        .ok_or(ReleaseVerifyError::RekorEntryMissing)?;
    let log_key_id = Sha256::digest(&root.rekor_key);
    if decode(&entry.log_id.key_id, "log id")? != log_key_id.as_slice() {
        return Err(ReleaseVerifyError::RekorKeyUnknown);
    }
    let integrated_time = number(&entry.integrated_time, "integrated time")?;
    let payload = serde_json::to_string(&SetPayload {
        body: &entry.canonicalized_body,
        integrated_time,
        log_id: hex::encode(log_key_id),
        log_index: number(&entry.log_index, "log index")?,
    })
    .map_err(|error| ReleaseVerifyError::MalformedBundle(error.to_string()))?;
    let (_, rekor_key) = SubjectPublicKeyInfo::from_der(&root.rekor_key).map_err(|error| {
        ReleaseVerifyError::BadCertificate(format!("the pinned Rekor key: {error}"))
    })?;
    verify_p256(
        &rekor_key.subject_public_key.data,
        payload.as_bytes(),
        &decode(&promise.signed_entry_timestamp, "signed entry timestamp")?,
    )
    .map_err(|()| ReleaseVerifyError::RekorSetInvalid)?;

    // The signed body must bind this file, this signature and this certificate.
    let body: HashedRekord =
        serde_json::from_slice(&decode(&entry.canonicalized_body, "entry body")?)
            .map_err(|error| ReleaseVerifyError::MalformedBundle(format!("entry body: {error}")))?;
    if body.kind != "hashedrekord" || body.api_version != "0.0.1" {
        return Err(ReleaseVerifyError::RekorEntryMismatch("kind"));
    }
    if body.spec.data.hash.algorithm != "sha256"
        || !body
            .spec
            .data
            .hash
            .value
            .eq_ignore_ascii_case(&hex::encode(digest))
    {
        return Err(ReleaseVerifyError::RekorEntryMismatch("digest"));
    }
    if decode(&body.spec.signature.content, "entry signature")? != signature {
        return Err(ReleaseVerifyError::RekorEntryMismatch("signature"));
    }
    let pem = decode(&body.spec.signature.public_key.content, "entry certificate")?;
    let entry_certificate = parse_x509_pem(&pem)
        .map_err(|_| ReleaseVerifyError::RekorEntryMismatch("certificate"))?
        .1;
    if entry_certificate.contents != leaf_der {
        return Err(ReleaseVerifyError::RekorEntryMismatch("certificate"));
    }
    Ok(integrated_time)
}

fn verify_chain(
    root: &TrustRoot,
    leaf: &X509Certificate<'_>,
    integrated_time: i64,
) -> Result<(), ReleaseVerifyError> {
    let (_, intermediate) = parse_x509_certificate(&root.fulcio_intermediate).map_err(|error| {
        ReleaseVerifyError::BadCertificate(format!("the pinned intermediate: {error}"))
    })?;
    let (_, anchor) = parse_x509_certificate(&root.fulcio_root)
        .map_err(|error| ReleaseVerifyError::BadCertificate(format!("the pinned root: {error}")))?;
    if leaf.issuer() != intermediate.subject()
        || intermediate.issuer() != anchor.subject()
        || leaf
            .verify_signature(Some(intermediate.public_key()))
            .is_err()
        || intermediate
            .verify_signature(Some(anchor.public_key()))
            .is_err()
    {
        return Err(ReleaseVerifyError::UntrustedCertificate);
    }
    let at = ASN1Time::from_timestamp(integrated_time).map_err(|_| {
        ReleaseVerifyError::MalformedBundle("integrated time is out of range".to_owned())
    })?;
    if [leaf, &intermediate, &anchor]
        .iter()
        .any(|certificate| !certificate.validity().is_valid_at(at))
    {
        return Err(ReleaseVerifyError::CertificateNotValidAtLogTime { integrated_time });
    }
    Ok(())
}

/// The URI names of the subject alternative name extension.
fn uri_names(leaf: &X509Certificate<'_>) -> Result<Vec<String>, ReleaseVerifyError> {
    let names = leaf
        .subject_alternative_name()
        .map_err(|error| ReleaseVerifyError::BadCertificate(error.to_string()))?;
    Ok(names
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::URI(uri) => Some((*uri).to_owned()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Every OIDC issuer that the certificate names, from the v2 and the v1 extension.
fn issuers(leaf: &X509Certificate<'_>) -> Result<Vec<String>, ReleaseVerifyError> {
    let mut found = Vec::new();
    for (oid, der_encoded) in [(OID_ISSUER_V2, true), (OID_ISSUER_V1, false)] {
        let oid = Oid::from(oid).expect("the issuer OID is valid");
        let extension = leaf
            .get_extension_unique(&oid)
            .map_err(|error| ReleaseVerifyError::BadCertificate(error.to_string()))?;
        let Some(extension) = extension else { continue };
        let text = if der_encoded {
            // A DER UTF8String: tag 0x0c, then the length, then the text.
            match parse_der_utf8string(extension.value) {
                Ok(([], object)) => object.as_str().ok().map(str::to_owned),
                _ => None,
            }
        } else {
            std::str::from_utf8(extension.value).ok().map(str::to_owned)
        };
        found.push(text.unwrap_or_default());
    }
    Ok(found)
}

/// ECDSA P-256 over SHA-256, DER signature, key as the uncompressed point.
fn verify_p256(point: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ()> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, point)
        .verify(message, signature)
        .map_err(|_| ())
}
