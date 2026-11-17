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

const OID_SAN: &[u64] = &[2, 5, 29, 17];
const OID_FULCIO_V1_ISSUER: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];
const OID_FULCIO_ISSUER: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 8];
const OID_FULCIO_SOURCE_REPOSITORY: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 12];
const OID_FULCIO_SOURCE_REF: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 14];
const OID_UNKNOWN: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

struct Fiction {
    root: TrustRoot,
    intermediate_params: CertificateParams,
    intermediate_key: KeyPair,
    rekor_key: KeyPair,
}

fn fiction() -> Fiction {
    fiction_with(None, None)
}

/// A fictional chain. `root` and `intermediate` give the validity of each authority; None is broad.
fn fiction_with(root: Option<(Date, Date)>, intermediate: Option<(Date, Date)>) -> Fiction {
    let mut root_params = CertificateParams::new(vec![]).unwrap();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "fictional root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if let Some(((y1, m1, d1), (y2, m2, d2))) = root {
        root_params.not_before = date_time_ymd(y1, m1, d1);
        root_params.not_after = date_time_ymd(y2, m2, d2);
    }
    let root_key = KeyPair::generate().unwrap();
    let root_cert = root_params.clone().self_signed(&root_key).unwrap();

    let mut intermediate_params = CertificateParams::new(vec![]).unwrap();
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "fictional intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if let Some(((y1, m1, d1), (y2, m2, d2))) = intermediate {
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
    /// The subject alternative name: the workflow identity.
    identity: String,
    /// The v2 issuer extension; None leaves it out.
    issuer: Option<String>,
    /// The v1 issuer extension; None leaves it out.
    v1_issuer: Option<String>,
    /// The source repository extension (1.3.6.1.4.1.57264.1.12); None leaves it out.
    source_repository: Option<String>,
    /// The source ref extension (1.3.6.1.4.1.57264.1.14); None leaves it out.
    source_ref: Option<String>,
    key_usages: Vec<KeyUsagePurpose>,
    code_signing: bool,
    leaf_valid: (Date, Date),
    /// More leaf extensions: OID, critical flag, content.
    extra: Vec<(&'static [u64], bool, Vec<u8>)>,
    /// The leaf is signed by a key that carries the intermediate's name, not the pinned key.
    forged_intermediate: bool,
    integrated_time: i64,
    /// What the leaf key signs; the default is SUMS.
    signed: Vec<u8>,
    /// The digest that the Rekor body names; the default is the digest of SUMS.
    body_digest: Option<String>,
    /// A second certificate for the Rekor body.
    body_certificate_from_other_leaf: bool,
    /// Edits the Rekor body before the entry timestamp signs it.
    body_edit: Option<Change>,
}

impl Default for Release {
    fn default() -> Self {
        Self {
            identity: format!(
                "https://github.com/{FICTIONAL_REPOSITORY}/.github/workflows/client-release.yml@refs/tags/{TAG}"
            ),
            issuer: Some(ISSUER.to_owned()),
            v1_issuer: Some(ISSUER.to_owned()),
            source_repository: Some(format!("https://github.com/{FICTIONAL_REPOSITORY}")),
            source_ref: Some(format!("refs/tags/{TAG}")),
            key_usages: vec![KeyUsagePurpose::DigitalSignature],
            code_signing: true,
            leaf_valid: ((2026, 5, 31), (2026, 6, 2)),
            extra: Vec::new(),
            forged_intermediate: false,
            integrated_time: chrono_time(2026, 6, 1),
            signed: SUMS.as_bytes().to_vec(),
            body_digest: None,
            body_certificate_from_other_leaf: false,
            body_edit: None,
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

/// A DER UTF8String, the form of the v2 Fulcio extensions. Short form: the text is under 128 bytes.
fn der_utf8(text: &str) -> Vec<u8> {
    let mut out = vec![0x0c, u8::try_from(text.len()).unwrap()];
    out.extend_from_slice(text.as_bytes());
    out
}

/// A DER subjectAltName with one URI. Short form: the URI is under 128 bytes.
fn der_uri_san(uri: &str) -> Vec<u8> {
    let mut name = vec![0x86, u8::try_from(uri.len()).unwrap()];
    name.extend_from_slice(uri.as_bytes());
    let mut out = vec![0x30, u8::try_from(name.len()).unwrap()];
    out.extend(name);
    out
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
    params.key_usages = release.key_usages.clone();
    let ((y1, m1, d1), (y2, m2, d2)) = release.leaf_valid;
    params.not_before = date_time_ymd(y1, m1, d1);
    params.not_after = date_time_ymd(y2, m2, d2);
    if let Some(issuer) = &release.issuer {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                OID_FULCIO_ISSUER,
                der_utf8(issuer),
            ));
    }
    if let Some(v1) = &release.v1_issuer {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                OID_FULCIO_V1_ISSUER,
                v1.as_bytes().to_vec(),
            ));
    }
    if let Some(repository) = &release.source_repository {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                OID_FULCIO_SOURCE_REPOSITORY,
                der_utf8(repository),
            ));
    }
    if let Some(source_ref) = &release.source_ref {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                OID_FULCIO_SOURCE_REF,
                der_utf8(source_ref),
            ));
    }
    for (oid, critical, content) in &release.extra {
        let mut extension = CustomExtension::from_oid_content(oid, content.clone());
        extension.set_criticality(*critical);
        params.custom_extensions.push(extension);
    }
    let key = KeyPair::generate().unwrap();
    let forged;
    let signer = if release.forged_intermediate {
        forged = KeyPair::generate().unwrap();
        &forged
    } else {
        &fiction.intermediate_key
    };
    let cert = params
        .signed_by(
            &key,
            &Issuer::from_params(&fiction.intermediate_params, signer),
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
    let mut body = json!({
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
    if let Some(edit) = release.body_edit {
        edit(&mut body);
    }
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
    // The v2 issuer extension alone is enough.
    check(
        &fiction,
        &Release {
            v1_issuer: None,
            ..Release::default()
        },
    )
    .unwrap();
    // The v1 issuer extension alone is enough.
    check(
        &fiction,
        &Release {
            issuer: None,
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
fn release_verify_rejects_a_source_repository_or_ref_that_is_not_this_one() {
    let fiction = fiction();
    // A reusable workflow of another repository: the identity matches, the code ran elsewhere.
    let other_repository = Release {
        source_repository: Some("https://github.com/example-org/other-repo".to_owned()),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &other_repository),
        Err(ReleaseVerifyError::WrongSource {
            what: "repository",
            ..
        })
    ));
    // A branch run of the same workflow file, at a tag identity.
    let branch = Release {
        source_ref: Some("refs/heads/main".to_owned()),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &branch),
        Err(ReleaseVerifyError::WrongSource { what: "ref", .. })
    ));
}

#[test]
fn release_verify_rejects_a_missing_or_repeated_source_extension() {
    let fiction = fiction();
    let missing_repository = Release {
        source_repository: None,
        ..Release::default()
    };
    assert_eq!(
        check(&fiction, &missing_repository).unwrap_err(),
        ReleaseVerifyError::WrongSource {
            what: "repository",
            expected: format!("https://github.com/{FICTIONAL_REPOSITORY}"),
            found: vec![],
        }
    );
    let missing_ref = Release {
        source_ref: None,
        ..Release::default()
    };
    assert_eq!(
        check(&fiction, &missing_ref).unwrap_err(),
        ReleaseVerifyError::WrongSource {
            what: "ref",
            expected: format!("refs/tags/{TAG}"),
            found: vec![],
        }
    );
    let repeated_ref = Release {
        extra: vec![(
            OID_FULCIO_SOURCE_REF,
            false,
            der_utf8(&format!("refs/tags/{TAG}")),
        )],
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &repeated_ref),
        Err(ReleaseVerifyError::BadCertificate(_))
    ));
}

#[test]
fn release_verify_rejects_another_issuer() {
    let fiction = fiction();
    let other = "https://issuer.example.org".to_owned();
    let both_other = Release {
        issuer: Some(other.clone()),
        v1_issuer: Some(other.clone()),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &both_other),
        Err(ReleaseVerifyError::WrongIssuer { .. })
    ));
    let empty = Release {
        issuer: Some(String::new()),
        v1_issuer: None,
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &empty),
        Err(ReleaseVerifyError::WrongIssuer { .. })
    ));
}

#[test]
fn release_verify_rejects_issuer_extensions_that_disagree() {
    let fiction = fiction();
    let other = "https://issuer.example.org".to_owned();
    // The v2 extension names GitHub, the v1 extension another issuer.
    let v1_other = Release {
        v1_issuer: Some(other.clone()),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &v1_other),
        Err(ReleaseVerifyError::WrongIssuer { .. })
    ));
    // The v2 extension names another issuer, the v1 extension GitHub.
    let v2_other = Release {
        issuer: Some(other),
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &v2_other),
        Err(ReleaseVerifyError::WrongIssuer { .. })
    ));
}

#[test]
fn release_verify_rejects_a_leaf_without_an_issuer() {
    let fiction = fiction();
    let none = Release {
        issuer: None,
        v1_issuer: None,
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &none),
        Err(ReleaseVerifyError::WrongIssuer { .. })
    ));
}

#[test]
fn release_verify_rejects_a_duplicated_issuer_or_identity_extension() {
    let fiction = fiction();
    let duplicate_issuer = Release {
        extra: vec![(OID_FULCIO_ISSUER, false, der_utf8(ISSUER))],
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &duplicate_issuer),
        Err(ReleaseVerifyError::BadCertificate(_))
    ));
    let identity = Release::default().identity;
    let duplicate_san = Release {
        extra: vec![(OID_SAN, false, der_uri_san(&identity))],
        ..Release::default()
    };
    assert!(matches!(
        check(&fiction, &duplicate_san),
        Err(ReleaseVerifyError::BadCertificate(_))
    ));
}

#[test]
fn release_verify_rejects_a_certificate_without_a_digital_signature_key_usage() {
    let fiction = fiction();
    for key_usages in [vec![KeyUsagePurpose::KeyEncipherment], vec![]] {
        let release = Release {
            key_usages,
            ..Release::default()
        };
        assert_eq!(
            check(&fiction, &release).unwrap_err(),
            ReleaseVerifyError::WrongKeyUsage
        );
    }
}

#[test]
fn release_verify_rejects_an_unknown_critical_extension() {
    let fiction = fiction();
    let critical = Release {
        extra: vec![(OID_UNKNOWN, true, b"fictional".to_vec())],
        ..Release::default()
    };
    assert_eq!(
        check(&fiction, &critical).unwrap_err(),
        ReleaseVerifyError::UnknownCriticalExtension {
            oid: "1.3.6.1.4.1.99999.1".to_owned(),
        }
    );
    // The same extension, not critical, is ignored.
    let not_critical = Release {
        extra: vec![(OID_UNKNOWN, false, b"fictional".to_vec())],
        ..Release::default()
    };
    check(&fiction, &not_critical).unwrap();
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
    let fiction = fiction_with(None, Some(((2020, 1, 1), (2021, 1, 1))));
    assert!(matches!(
        check(&fiction, &Release::default()),
        Err(ReleaseVerifyError::CertificateNotValidAtLogTime { .. })
    ));
}

#[test]
fn release_verify_rejects_a_root_that_was_not_valid_at_the_log_time() {
    for root in [((2020, 1, 1), (2021, 1, 1)), ((2030, 1, 1), (2031, 1, 1))] {
        let fiction = fiction_with(Some(root), None);
        assert!(
            matches!(
                check(&fiction, &Release::default()),
                Err(ReleaseVerifyError::CertificateNotValidAtLogTime { .. })
            ),
            "{root:?}"
        );
    }
}

#[test]
fn release_verify_rejects_a_leaf_signed_by_a_key_that_is_not_the_intermediate() {
    let fiction = fiction();
    // The forged leaf names the pinned intermediate, and the other checks still pass.
    let forged = Release {
        forged_intermediate: true,
        ..Release::default()
    };
    assert_eq!(
        check(&fiction, &forged).unwrap_err(),
        ReleaseVerifyError::UntrustedCertificate
    );
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
    value["verificationMaterial"]["tlogEntries"][0]["kindVersion"]["version"] = json!("0.0.2");
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
fn release_verify_rejects_a_rekor_body_of_another_kind_version_or_hash_algorithm() {
    let fiction = fiction();
    // Each edit happens before the entry timestamp signs the body, so only the body check fails.
    let cases: [(&str, Change, ReleaseVerifyError); 3] = [
        (
            "kind",
            |body| body["kind"] = json!("dsse"),
            ReleaseVerifyError::RekorEntryMismatch("kind"),
        ),
        (
            "api version",
            |body| body["apiVersion"] = json!("0.0.2"),
            ReleaseVerifyError::RekorEntryMismatch("kind"),
        ),
        (
            "hash algorithm",
            |body| body["spec"]["data"]["hash"]["algorithm"] = json!("sha512"),
            ReleaseVerifyError::RekorEntryMismatch("digest"),
        ),
    ];
    for (name, edit, expected) in cases {
        let release = Release {
            body_edit: Some(edit),
            ..Release::default()
        };
        assert_eq!(check(&fiction, &release).unwrap_err(), expected, "{name}");
    }
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
