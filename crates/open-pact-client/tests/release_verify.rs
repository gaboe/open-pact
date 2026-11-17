//! The release verifier on the real v0.7.1 release (public data of this repository) and on
//! releases signed by a fictional Sigstore (example-org, version 9.9.9) that this file builds.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use open_pact_client::release_verify::{
    ISSUER, ReleaseVerifyError, TrustRoot, verify_release, verify_release_with,
};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData, SanType, date_time_ymd, string::Ia5String,
};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Date = (i32, u8, u8);
type Change = fn(&mut Value);

const REAL_SUMS: &[u8] = include_bytes!("fixtures/release-v0.7.1/SHA256SUMS");
const REAL_BUNDLE: &[u8] = include_bytes!("fixtures/release-v0.7.1/SHA256SUMS.sigstore.json");
const REPOSITORY: &str = "gaboe/open-pact";

fn real(tag: &str, repository: &str) -> Result<(), ReleaseVerifyError> {
    verify_release(REAL_SUMS, REAL_BUNDLE, tag, repository).map(|_| ())
}

fn real_bundle_with(change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut bundle: Value = serde_json::from_slice(REAL_BUNDLE).unwrap();
    change(&mut bundle);
    serde_json::to_vec(&bundle).unwrap()
}

/// The pinned Fulcio chain with a Rekor key that this file owns: the real bundle names the real log.
fn root_with_fictional_rekor() -> TrustRoot {
    let mut root = TrustRoot::pinned();
    root.rekor_key = KeyPair::generate().unwrap().subject_public_key_info();
    root
}

#[test]
fn release_verify_accepts_the_real_release() {
    let verified = verify_release(REAL_SUMS, REAL_BUNDLE, "v0.7.1", REPOSITORY).unwrap();
    assert_eq!(verified.tag, "v0.7.1");
    assert_eq!(
        verified.sums.hash_of("NOTICE"),
        Some("3385839d995506741f63da8708d9a663f6c3162936440cec8e1d269bfabe515a")
    );
    assert_eq!(verified.sums.hash_of("not-listed"), None);
    assert_eq!(verified.sums.iter().count(), 7);
}

#[test]
fn release_verify_rejects_a_changed_sums_byte() {
    let mut sums = REAL_SUMS.to_vec();
    sums[0] = if sums[0] == b'9' { b'8' } else { b'9' };
    assert_eq!(
        verify_release(&sums, REAL_BUNDLE, "v0.7.1", REPOSITORY).unwrap_err(),
        ReleaseVerifyError::DigestMismatch
    );
}

#[test]
fn release_verify_rejects_another_tag() {
    assert!(matches!(
        real("v0.7.2", REPOSITORY),
        Err(ReleaseVerifyError::WrongIdentity { .. })
    ));
    assert!(matches!(
        real("v0.7", REPOSITORY),
        Err(ReleaseVerifyError::WrongIdentity { .. })
    ));
    assert!(matches!(
        real("", REPOSITORY),
        Err(ReleaseVerifyError::WrongIdentity { .. })
    ));
}

#[test]
fn release_verify_rejects_another_repository() {
    assert!(matches!(
        real("v0.7.1", "example-org/open-pact"),
        Err(ReleaseVerifyError::WrongIdentity { .. })
    ));
    assert!(matches!(
        real("v0.7.1", "gaboe/open-pact-fork"),
        Err(ReleaseVerifyError::WrongIdentity { .. })
    ));
}

#[test]
fn release_verify_rejects_a_tampered_signature() {
    let bundle = real_bundle_with(|bundle| {
        let signature = bundle["messageSignature"]["signature"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut bytes = STANDARD.decode(signature).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        bundle["messageSignature"]["signature"] = Value::String(STANDARD.encode(bytes));
    });
    // The Rekor entry still binds the original signature.
    assert_eq!(
        verify_release(REAL_SUMS, &bundle, "v0.7.1", REPOSITORY).unwrap_err(),
        ReleaseVerifyError::RekorEntryMismatch("signature")
    );
}

#[test]
fn release_verify_rejects_a_tampered_rekor_entry() {
    let cases: [(&str, Change); 5] = [
        ("integrated time", |bundle| {
            let entry = &mut bundle["verificationMaterial"]["tlogEntries"][0];
            let time: i64 = entry["integratedTime"].as_str().unwrap().parse().unwrap();
            entry["integratedTime"] = Value::String((time + 1).to_string());
        }),
        ("log index", |bundle| {
            bundle["verificationMaterial"]["tlogEntries"][0]["logIndex"] =
                Value::String("1".to_owned());
        }),
        ("body", |bundle| {
            let entry = &mut bundle["verificationMaterial"]["tlogEntries"][0];
            let body = STANDARD
                .decode(entry["canonicalizedBody"].as_str().unwrap())
                .unwrap();
            let text = String::from_utf8(body)
                .unwrap()
                .replacen("sha256", "sha257", 1);
            entry["canonicalizedBody"] = Value::String(STANDARD.encode(text));
        }),
        ("entry signature", |bundle| {
            let entry = &mut bundle["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"];
            let mut bytes = STANDARD
                .decode(entry["signedEntryTimestamp"].as_str().unwrap())
                .unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            entry["signedEntryTimestamp"] = Value::String(STANDARD.encode(bytes));
        }),
        ("entry signature of garbage", |bundle| {
            bundle["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]["signedEntryTimestamp"] =
                Value::String(STANDARD.encode(b"not a signature"));
        }),
    ];
    for (name, change) in cases {
        let bundle = real_bundle_with(change);
        assert_eq!(
            verify_release(REAL_SUMS, &bundle, "v0.7.1", REPOSITORY).unwrap_err(),
            ReleaseVerifyError::RekorSetInvalid,
            "{name}"
        );
    }
}

#[test]
fn release_verify_rejects_a_missing_or_foreign_rekor_entry() {
    let no_promise = real_bundle_with(|bundle| {
        bundle["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionPromise");
    });
    assert_eq!(
        verify_release(REAL_SUMS, &no_promise, "v0.7.1", REPOSITORY).unwrap_err(),
        ReleaseVerifyError::RekorEntryMissing
    );
    let no_entry =
        real_bundle_with(|bundle| bundle["verificationMaterial"]["tlogEntries"] = json!([]));
    assert_eq!(
        verify_release(REAL_SUMS, &no_entry, "v0.7.1", REPOSITORY).unwrap_err(),
        ReleaseVerifyError::RekorEntryMissing
    );
    assert_eq!(
        verify_release_with(
            &root_with_fictional_rekor(),
            REAL_SUMS,
            REAL_BUNDLE,
            "v0.7.1",
            REPOSITORY
        )
        .unwrap_err(),
        ReleaseVerifyError::RekorKeyUnknown
    );
}

#[test]
fn release_verify_rejects_a_bundle_it_cannot_read() {
    for (bundle, name) in [
        (b"not json".to_vec(), "not json"),
        (b"{}".to_vec(), "empty object"),
        (
            real_bundle_with(|bundle| {
                bundle["mediaType"] = json!("application/vnd.dev.sigstore.bundle+json;version=0.2")
            }),
            "media type",
        ),
        (
            real_bundle_with(|bundle| {
                bundle["verificationMaterial"]["certificate"]["rawBytes"] = json!("!!")
            }),
            "certificate",
        ),
        (
            real_bundle_with(|bundle| bundle["messageSignature"]["messageDigest"] = Value::Null),
            "digest",
        ),
    ] {
        let error = verify_release(REAL_SUMS, &bundle, "v0.7.1", REPOSITORY).unwrap_err();
        assert!(
            matches!(
                error,
                ReleaseVerifyError::MalformedBundle(_) | ReleaseVerifyError::UnsupportedBundle(_)
            ),
            "{name}: {error}"
        );
    }
}

#[test]
fn release_verify_rejects_a_malformed_sums_file() {
    let hash = "a".repeat(64);
    for sums in [
        String::new(),
        "short".to_owned(),
        format!("{hash}name\n"),
        format!("{}  name\n", "z".repeat(64)),
        format!("{hash}  \n"),
        format!("{hash}  dir/name\n"),
        format!("{hash}  name\n{hash}  name\n"),
    ] {
        let error = verify_release(sums.as_bytes(), REAL_BUNDLE, "v0.7.1", REPOSITORY).unwrap_err();
        assert!(
            matches!(error, ReleaseVerifyError::MalformedSums(_)),
            "{sums:?}: {error}"
        );
    }
    assert!(matches!(
        verify_release(&[0xff, 0xfe], REAL_BUNDLE, "v0.7.1", REPOSITORY).unwrap_err(),
        ReleaseVerifyError::MalformedSums(_)
    ));
}

// A fictional Sigstore: root, intermediate, Rekor key.

const SUMS: &str = "ab9a0b3a8ed7bd5d3a3b4f9f0f3a5d3b6e5a1a0c4cb8f4a8f1d9c3b2a1f0e9d8  open-pact-client-9.9.9-x86_64-example\n";
const TAG: &str = "v9.9.9";
const FICTIONAL_REPOSITORY: &str = "example-org/example-repo";

struct Fiction {
    root: TrustRoot,
    intermediate_params: CertificateParams,
    intermediate_key: KeyPair,
    rekor_key: KeyPair,
}

fn fiction() -> Fiction {
    fiction_with_intermediate_valid(None)
}

fn fiction_with_intermediate_valid(valid: Option<(Date, Date)>) -> Fiction {
    let mut root_params = CertificateParams::new(vec![]).unwrap();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "fictional root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_key = KeyPair::generate().unwrap();
    let root_cert = root_params.clone().self_signed(&root_key).unwrap();

    let mut intermediate_params = CertificateParams::new(vec![]).unwrap();
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "fictional intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if let Some(((y1, m1, d1), (y2, m2, d2))) = valid {
        intermediate_params.not_before = date_time_ymd(y1, m1, d1);
        intermediate_params.not_after = date_time_ymd(y2, m2, d2);
    }
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate_cert = intermediate_params
        .clone()
        .signed_by(
            &intermediate_key,
            &Issuer::from_params(&root_params, &root_key),
        )
        .unwrap();

    let rekor_key = KeyPair::generate().unwrap();
    Fiction {
        root: TrustRoot {
            fulcio_intermediate: intermediate_cert.der().to_vec(),
            fulcio_root: root_cert.der().to_vec(),
            rekor_key: rekor_key.subject_public_key_info(),
        },
        intermediate_params,
        intermediate_key,
        rekor_key,
    }
}

/// What a test may change about a fictional release. Each default is the valid value.
struct Release {
    identity: String,
    issuer: String,
    v1_issuer: Option<String>,
    code_signing: bool,
    leaf_valid: (Date, Date),
    integrated_time: i64,
    /// What the leaf key signs; the default is SUMS.
    signed: Vec<u8>,
    /// The digest that the Rekor body names; the default is the digest of SUMS.
    body_digest: Option<String>,
    /// A second certificate for the Rekor body.
    body_certificate_from_other_leaf: bool,
}

impl Default for Release {
    fn default() -> Self {
        Self {
            identity: format!(
                "https://github.com/{FICTIONAL_REPOSITORY}/.github/workflows/client-release.yml@refs/tags/{TAG}"
            ),
            issuer: ISSUER.to_owned(),
            v1_issuer: Some(ISSUER.to_owned()),
            code_signing: true,
            leaf_valid: ((2026, 5, 31), (2026, 6, 2)),
            integrated_time: chrono_time(2026, 6, 1),
            signed: SUMS.as_bytes().to_vec(),
            body_digest: None,
            body_certificate_from_other_leaf: false,
        }
    }
}

fn chrono_time(year: i32, month: u32, day: u32) -> i64 {
    chrono::NaiveDate::from_ymd_opt(year, month, day)
        .unwrap()
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp()
}

fn sign(key: &KeyPair, message: &[u8]) -> Vec<u8> {
    let random = SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &key.serialize_der(),
        &random,
    )
    .unwrap();
    pair.sign(&random, message).unwrap().as_ref().to_vec()
}

fn leaf(fiction: &Fiction, release: &Release) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.subject_alt_names = vec![SanType::URI(
        Ia5String::try_from(release.identity.clone()).unwrap(),
    )];
    if release.code_signing {
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    }
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let ((y1, m1, d1), (y2, m2, d2)) = release.leaf_valid;
    params.not_before = date_time_ymd(y1, m1, d1);
    params.not_after = date_time_ymd(y2, m2, d2);
    let issuer = &release.issuer;
    let mut string = vec![0x0c, u8::try_from(issuer.len()).unwrap()];
    string.extend_from_slice(issuer.as_bytes());
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 57264, 1, 8],
            string,
        ));
    if let Some(v1) = &release.v1_issuer {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
                v1.as_bytes().to_vec(),
            ));
    }
    let key = KeyPair::generate().unwrap();
    let cert = params
        .signed_by(
            &key,
            &Issuer::from_params(&fiction.intermediate_params, &fiction.intermediate_key),
        )
        .unwrap();
    (cert, key)
}

/// The SHA256SUMS bytes and the bundle of a fictional release.
fn bundle(fiction: &Fiction, release: &Release) -> Vec<u8> {
    let (cert, key) = leaf(fiction, release);
    let signature = sign(&key, &release.signed);
    let digest = Sha256::digest(SUMS.as_bytes());
    let body_certificate = if release.body_certificate_from_other_leaf {
        leaf(fiction, release).0
    } else {
        cert.clone()
    };
    let body = json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": release.body_digest.clone().unwrap_or_else(|| hex::encode(digest))}},
            "signature": {
                "content": STANDARD.encode(&signature),
                "publicKey": {"content": STANDARD.encode(body_certificate.pem())},
            },
        },
    });
    let body = STANDARD.encode(serde_json::to_vec(&body).unwrap());
    let log_id = Sha256::digest(fiction.rekor_key.subject_public_key_info());
    let payload = format!(
        r#"{{"body":"{body}","integratedTime":{},"logID":"{}","logIndex":7}}"#,
        release.integrated_time,
        hex::encode(log_id)
    );
    let set = sign(&fiction.rekor_key, payload.as_bytes());
    serde_json::to_vec(&json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": STANDARD.encode(cert.der())},
            "tlogEntries": [{
                "logIndex": "7",
                "logId": {"keyId": STANDARD.encode(log_id)},
                "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                "integratedTime": release.integrated_time.to_string(),
                "inclusionPromise": {"signedEntryTimestamp": STANDARD.encode(set)},
                "canonicalizedBody": body,
            }],
        },
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256", "digest": STANDARD.encode(digest)},
            "signature": STANDARD.encode(signature),
        },
    }))
    .unwrap()
}

fn check(fiction: &Fiction, release: &Release) -> Result<(), ReleaseVerifyError> {
    let bundle = bundle(fiction, release);
    verify_release_with(
        &fiction.root,
        SUMS.as_bytes(),
        &bundle,
        TAG,
        FICTIONAL_REPOSITORY,
    )
    .map(|_| ())
}

#[test]
fn release_verify_accepts_a_fictional_release() {
    let fiction = fiction();
    check(&fiction, &Release::default()).unwrap();
    // The v1 issuer extension alone is enough.
    check(
        &fiction,
        &Release {
            v1_issuer: None,
            ..Release::default()
        },
    )
    .unwrap();
    // The fictional chain is not the pinned one.
    let bundle = bundle(&fiction, &Release::default());
    assert!(verify_release(SUMS.as_bytes(), &bundle, TAG, FICTIONAL_REPOSITORY).is_err());
}

#[test]
fn release_verify_rejects_another_workflow_file() {
    let fiction = fiction();
    for workflow in [
        "other.yml",
        "client-release.yml.evil",
        "../client-release.yml",
    ] {
        let release = Release {
            identity: format!(
                "https://github.com/{FICTIONAL_REPOSITORY}/.github/workflows/{workflow}@refs/tags/{TAG}"
            ),
            ..Release::default()
        };
        assert!(
            matches!(
                check(&fiction, &release),
                Err(ReleaseVerifyError::WrongIdentity { .. })
            ),
            "{workflow}"
        );
    }
    let branch = Release {
        identity: format!(
            "https://github.com/{FICTIONAL_REPOSITORY}/.github/workflows/client-release.yml@refs/heads/main"
        ),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &branch),
        Err(ReleaseVerifyError::WrongIdentity { .. })
    ));
}

#[test]
fn release_verify_rejects_another_issuer() {
    let fiction = fiction();
    let other = "https://issuer.example.org".to_owned();
    let v2 = Release {
        issuer: other.clone(),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &v2),
        Err(ReleaseVerifyError::WrongIssuer { .. })
    ));
    let v1 = Release {
        v1_issuer: Some(other.clone()),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &v1),
        Err(ReleaseVerifyError::WrongIssuer { .. })
    ));
    let none = Release {
        issuer: String::new(),
        v1_issuer: None,
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &none),
        Err(ReleaseVerifyError::WrongIssuer { .. })
    ));
}

#[test]
fn release_verify_rejects_a_certificate_that_was_not_valid_at_the_log_time() {
    let fiction = fiction();
    let expired = Release {
        leaf_valid: ((2026, 1, 1), (2026, 2, 1)),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &expired),
        Err(ReleaseVerifyError::CertificateNotValidAtLogTime { .. })
    ));
    let not_yet = Release {
        leaf_valid: ((2026, 7, 1), (2026, 8, 1)),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &not_yet),
        Err(ReleaseVerifyError::CertificateNotValidAtLogTime { .. })
    ));
}

#[test]
fn release_verify_rejects_an_authority_that_was_not_valid_at_the_log_time() {
    let fiction = fiction_with_intermediate_valid(Some(((2020, 1, 1), (2021, 1, 1))));
    assert!(matches!(
        check(&fiction, &Release::default()),
        Err(ReleaseVerifyError::CertificateNotValidAtLogTime { .. })
    ));
}

#[test]
fn release_verify_rejects_an_entry_it_does_not_read() {
    let fiction = fiction();
    let good = bundle(&fiction, &Release::default());
    let verify = |bundle: &[u8]| {
        verify_release_with(
            &fiction.root,
            SUMS.as_bytes(),
            bundle,
            TAG,
            FICTIONAL_REPOSITORY,
        )
    };
    let mut value: Value = serde_json::from_slice(&good).unwrap();
    let entry = value["verificationMaterial"]["tlogEntries"][0].clone();
    value["verificationMaterial"]["tlogEntries"] = json!([entry.clone(), entry.clone()]);
    assert_eq!(
        verify(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        ReleaseVerifyError::RekorEntryMissing
    );
    value["verificationMaterial"]["tlogEntries"] = json!([entry]);
    value["verificationMaterial"]["tlogEntries"][0]["kindVersion"]["kind"] = json!("dsse");
    assert!(matches!(
        verify(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        ReleaseVerifyError::UnsupportedBundle(_)
    ));
    let mut value: Value = serde_json::from_slice(&good).unwrap();
    value["messageSignature"]["messageDigest"]["algorithm"] = json!("SHA2_512");
    assert_eq!(
        verify(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        ReleaseVerifyError::DigestMismatch
    );
}

#[test]
fn release_verify_rejects_a_certificate_without_the_code_signing_purpose() {
    let fiction = fiction();
    let release = Release {
        code_signing: false,
        ..Release::default()
    };
    assert_eq!(
        check(&fiction, &release).unwrap_err(),
        ReleaseVerifyError::WrongPurpose
    );
}

#[test]
fn release_verify_rejects_a_signature_over_other_bytes() {
    let fiction = fiction();
    let release = Release {
        signed: b"other bytes".to_vec(),
        ..Release::default()
    };
    assert_eq!(
        check(&fiction, &release).unwrap_err(),
        ReleaseVerifyError::SignatureInvalid
    );
}

#[test]
fn release_verify_rejects_a_rekor_body_that_names_another_digest_or_certificate() {
    let fiction = fiction();
    let digest = Release {
        body_digest: Some("0".repeat(64)),
        ..Release::default()
    };
    assert_eq!(
        check(&fiction, &digest).unwrap_err(),
        ReleaseVerifyError::RekorEntryMismatch("digest")
    );
    let certificate = Release {
        body_certificate_from_other_leaf: true,
        ..Release::default()
    };
    assert_eq!(
        check(&fiction, &certificate).unwrap_err(),
        ReleaseVerifyError::RekorEntryMismatch("certificate")
    );
}

#[test]
fn release_verify_rejects_a_certificate_from_another_authority() {
    let fiction = fiction();
    let bundle = bundle(&fiction, &Release::default());
    // The log is the fictional one; the Fulcio chain is the real, pinned one.
    let mut root = TrustRoot::pinned();
    root.rekor_key = fiction.root.rekor_key.clone();
    assert_eq!(
        verify_release_with(&root, SUMS.as_bytes(), &bundle, TAG, FICTIONAL_REPOSITORY)
            .unwrap_err(),
        ReleaseVerifyError::UntrustedCertificate
    );
    // The right intermediate, another root.
    let other = self::fiction();
    let mut root = fiction.root.clone();
    root.fulcio_root = other.root.fulcio_root;
    assert_eq!(
        verify_release_with(&root, SUMS.as_bytes(), &bundle, TAG, FICTIONAL_REPOSITORY)
            .unwrap_err(),
        ReleaseVerifyError::UntrustedCertificate
    );
}

#[test]
fn release_verify_error_text_names_the_reason() {
    let text = real("v0.7.2", REPOSITORY).unwrap_err().to_string();
    assert!(text.contains("v0.7.1") && text.contains("v0.7.2"), "{text}");
    assert!(
        ReleaseVerifyError::DigestMismatch
            .to_string()
            .contains("SHA256SUMS")
    );
}
