use anyhow::Context;
use open_pact_core::{SigningKey, dev_key};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use crate::seal::SealingKey;

pub struct Keys {
    pub manifest: SigningKey,
    pub log: SigningKey,
    pub ca: Ca,
}

pub struct Ca {
    pub cert_pem: String,
    pub fingerprint: String,
    issuer: Issuer<'static, KeyPair>,
}

const CLOCK_SKEW: Duration = Duration::minutes(5);

/// A row of `gateway_secrets`, sealed under the KEK. A row still in plaintext from before the
/// KEK is sealed in place; the `WHERE value = old` makes a second process doing the same a no-op.
/// A row that does not open is an error, never a reason to generate a new key.
async fn secret(
    db: &PgPool,
    kek: &SealingKey,
    name: &str,
    make: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let select = || {
        sqlx::query_scalar::<_, String>("SELECT value FROM gateway_secrets WHERE name = $1")
            .bind(name)
    };
    let stored = match select().fetch_optional(db).await? {
        Some(stored) => stored,
        None => {
            sqlx::query(
                "INSERT INTO gateway_secrets (name, value) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING",
            )
            .bind(name)
            .bind(kek.seal(name, make()?.as_bytes()))
            .execute(db)
            .await?;
            eprintln!("generated {name}");
            select().fetch_one(db).await?
        }
    };
    if SealingKey::is_sealed(&stored) {
        let plain = kek
            .open(name, &stored)
            .context("is GATEWAY_KEK the key this database was sealed with?")?;
        return String::from_utf8(plain).with_context(|| format!("{name} is not UTF-8"));
    }
    sqlx::query("UPDATE gateway_secrets SET value = $1 WHERE name = $2 AND value = $3")
        .bind(kek.seal(name, stored.as_bytes()))
        .bind(name)
        .bind(&stored)
        .execute(db)
        .await?;
    eprintln!("encrypted plaintext {name} in place with the KEK");
    Ok(stored)
}

impl Keys {
    pub async fn load_or_create(db: &PgPool, kek: &SealingKey) -> anyhow::Result<Keys> {
        let new_key = || Ok(dev_key::to_pem(&dev_key::generate()));
        let manifest = dev_key::from_pem(&secret(db, kek, "manifest_signing_key", new_key).await?)
            .context("manifest_signing_key")?;
        let log = dev_key::from_pem(&secret(db, kek, "log_signing_key", new_key).await?)
            .context("log_signing_key")?;
        let ca_key = secret(db, kek, "ca_key", || {
            Ok(KeyPair::generate()?.serialize_pem())
        })
        .await?;
        let ca_cert = secret(db, kek, "ca_cert", || {
            Ok(Ca::self_signed_pem(&KeyPair::from_pem(&ca_key)?)?)
        })
        .await?;
        Ok(Keys {
            manifest,
            log,
            ca: Ca::new(ca_cert, KeyPair::from_pem(&ca_key)?)?,
        })
    }
}

fn common_name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

impl Ca {
    fn self_signed_pem(key: &KeyPair) -> Result<String, rcgen::Error> {
        let mut params = CertificateParams::default();
        params.distinguished_name = common_name("open-pact demo CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + Duration::days(3650);
        params.serial_number = Some(random_serial());
        Ok(params.self_signed(key)?.pem())
    }

    pub fn new(cert_pem: String, key: KeyPair) -> anyhow::Result<Ca> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("ca_cert is not PEM: {e}"))?;
        let fingerprint = Sha256::digest(&pem.contents)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)?;
        Ok(Ca {
            cert_pem,
            fingerprint,
            issuer,
        })
    }

    pub fn issue(&self, csr_pem: &str, cn: &str, validity: Duration) -> Result<String, String> {
        bare_csr_der(csr_pem)?;
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| format!("csr_pem is not a valid signed certificate request: {e}"))?;
        let mut params = CertificateParams::default();
        params.distinguished_name = common_name(cn);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + validity;
        params.serial_number = Some(random_serial());
        let cert = params
            .signed_by(&csr.public_key, &self.issuer)
            .map_err(|e| format!("cannot issue certificate: {e}"))?;
        Ok(cert.pem())
    }
}

/// The DER of a certificate request that carries a P-256 public key and nothing else: canonical PEM
/// with no text around it, an empty subject, no attributes and so no extensions. Any other field
/// could carry text off the device, so the request must be exactly the info, the parameterless
/// ecdsa-with-SHA256 identifier and the signature. The signature is checked when the certificate
/// is issued.
pub fn bare_csr_der(csr_pem: &str) -> Result<Vec<u8>, String> {
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY};
    use x509_parser::prelude::FromDer;

    let bad = |why: &str| format!("csr_pem must be a bare certificate request: {why}");
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(csr_pem.as_bytes()).map_err(|_| bad("not PEM"))?;
    if pem.label != "CERTIFICATE REQUEST"
        || csr_pem.replace("\r\n", "\n") != canonical_pem(&pem.contents)
    {
        return Err(bad("only the PEM block, nothing around it"));
    }
    let (rest, csr) =
        X509CertificationRequest::from_der(&pem.contents).map_err(|_| bad("not PKCS #10"))?;
    let info = &csr.certification_request_info;
    if !rest.is_empty() {
        return Err(bad("trailing bytes"));
    }
    if info.subject.iter().next().is_some() {
        return Err(bad("the subject must be empty"));
    }
    if !info.attributes().is_empty() {
        return Err(bad("no attributes or extensions"));
    }
    let algorithm = &info.subject_pki.algorithm;
    let curve = algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok());
    if algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY || curve != Some(OID_EC_P256) {
        return Err(bad("the key must be P-256"));
    }
    if info.version.0 != 0 {
        return Err(bad("the version must be 1"));
    }
    if request_der(info.raw, &ECDSA_WITH_SHA256, &csr.signature_value) != pem.contents {
        return Err(bad(
            "the signature algorithm must be ecdsa-with-SHA256 without parameters",
        ));
    }
    Ok(pem.contents)
}

/// `sha256:<hex>` of a certificate's DER.
pub fn certificate_sha256(cert_pem: &str) -> anyhow::Result<String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(&pem.contents))
    ))
}

fn canonical_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE REQUEST-----\n");
    pem
}

/// ecdsa-with-SHA256 with its parameters absent, as RFC 5758 section 3.2 requires.
const ECDSA_WITH_SHA256: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

fn request_der(
    info: &[u8],
    algorithm: &[u8],
    signature: &x509_parser::der_parser::asn1_rs::BitString,
) -> Vec<u8> {
    let mut bits = vec![signature.unused_bits];
    bits.extend_from_slice(&signature.data);
    let mut body = info.to_vec();
    body.extend_from_slice(algorithm);
    body.extend(der_tlv(0x03, &bits));
    der_tlv(0x30, &body)
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn random_serial() -> SerialNumber {
    let mut bytes: [u8; 16] = rand::random();
    bytes[0] &= 0x7f;
    SerialNumber::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use rcgen::CertificateParams;
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;

    fn ca() -> Ca {
        let key = KeyPair::generate().unwrap();
        Ca::new(Ca::self_signed_pem(&key).unwrap(), key).unwrap()
    }

    fn csr(key: &KeyPair) -> String {
        bare_params().serialize_request(key).unwrap().pem().unwrap()
    }

    fn der(pem: &str) -> Vec<u8> {
        x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .unwrap()
            .1
            .contents
    }

    async fn stored(db: &PgPool) -> Vec<(String, String)> {
        sqlx::query_as("SELECT name, value FROM gateway_secrets ORDER BY name")
            .fetch_all(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn seals_new_and_plaintext_secrets_and_refuses_a_wrong_kek() {
        let db = crate::testdb::fresh().await;
        let kek = SealingKey::new(&[1; 32]);
        let first = Keys::load_or_create(&db, &kek).await.unwrap();
        let rows = stored(&db).await;
        assert_eq!(rows.len(), 4);
        assert!(
            rows.iter()
                .all(|(_, v)| SealingKey::is_sealed(v) && !v.contains("BEGIN"))
        );

        for (name, value) in &rows {
            let plain = String::from_utf8(kek.open(name, value).unwrap()).unwrap();
            sqlx::query("UPDATE gateway_secrets SET value = $1 WHERE name = $2")
                .bind(plain)
                .bind(name)
                .execute(&db)
                .await
                .unwrap();
        }
        let upgraded = Keys::load_or_create(&db, &kek).await.unwrap();
        assert_eq!(upgraded.ca.fingerprint, first.ca.fingerprint);
        assert_eq!(
            dev_key::to_pem(&upgraded.manifest),
            dev_key::to_pem(&first.manifest)
        );
        assert_eq!(dev_key::to_pem(&upgraded.log), dev_key::to_pem(&first.log));
        let resealed = stored(&db).await;
        assert!(resealed.iter().all(|(_, v)| SealingKey::is_sealed(v)));

        let wrong = Keys::load_or_create(&db, &SealingKey::new(&[2; 32])).await;
        assert!(
            wrong.is_err(),
            "a wrong KEK must not load or replace the keys"
        );
        assert_eq!(stored(&db).await, resealed);
    }

    #[test]
    fn issues_a_client_certificate_for_the_csr_key_signed_by_the_ca() {
        let ca = ca();
        let vpn_key = KeyPair::generate().unwrap();
        let issued = ca
            .issue(&csr(&vpn_key), "abc", Duration::hours(24))
            .unwrap();
        let (ca_der, cert_der) = (der(&ca.cert_pem), der(&issued));
        let (_, ca_cert) = X509Certificate::from_der(&ca_der).unwrap();
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

        assert!(ca_cert.is_ca());
        cert.verify_signature(Some(ca_cert.public_key())).unwrap();
        assert_eq!(cert.issuer(), ca_cert.subject());
        assert_eq!(cert.subject().to_string(), "CN=abc");
        assert_eq!(
            &*cert.public_key().subject_public_key.data,
            vpn_key.public_key_raw()
        );
        assert!(!cert.is_ca());
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth);
        let lifetime =
            cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
        assert_eq!(lifetime, (Duration::hours(24) + CLOCK_SKEW).whole_seconds());
    }

    #[test]
    fn issues_only_its_own_subject_and_extensions() {
        let csr = csr(&KeyPair::generate().unwrap());
        let issued = ca().issue(&csr, "abc", Duration::hours(1)).unwrap();
        let der = der(&issued);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        assert_eq!(cert.subject().to_string(), "CN=abc");
        let oids: Vec<String> = cert
            .extensions()
            .iter()
            .map(|e| e.oid.to_id_string())
            .collect();
        assert_eq!(
            oids,
            [
                "2.5.29.35", // authority key identifier
                "2.5.29.15", // key usage: digitalSignature
                "2.5.29.37", // extended key usage: clientAuth
            ]
        );
        assert!(!cert.is_ca());
        let ku = cert.key_usage().unwrap().unwrap().value;
        assert!(ku.digital_signature() && !ku.key_cert_sign());
    }

    fn bare_params() -> CertificateParams {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
    }

    #[test]
    fn rejects_a_csr_that_carries_more_than_its_key() {
        let key = KeyPair::generate().unwrap();
        let bare = bare_params()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        assert!(ca().issue(&bare, "abc", Duration::hours(1)).is_ok());

        let mut subject = bare_params();
        subject.distinguished_name = common_name("FICTIONAL private note");
        let mut san = CertificateParams::new(vec!["fictional.example.com".to_string()]).unwrap();
        san.distinguished_name = DistinguishedName::new();
        let challenge = rcgen::Attribute {
            oid: &[1, 2, 840, 113549, 1, 9, 7],
            values: vec![
                0x0c, 0x09, b'F', b'I', b'C', b'T', b'I', b'O', b'N', b'A', b'L',
            ],
        };
        let with_attribute = bare_params()
            .serialize_request_with_attributes(&key, vec![challenge])
            .unwrap()
            .pem()
            .unwrap();
        for (what, pem) in [
            (
                "subject",
                subject.serialize_request(&key).unwrap().pem().unwrap(),
            ),
            (
                "extension",
                san.serialize_request(&key).unwrap().pem().unwrap(),
            ),
            ("attribute", with_attribute),
            ("leading text", format!("FICTIONAL private note\n{bare}")),
            ("trailing text", format!("{bare}FICTIONAL private note\n")),
            ("not a CSR", "FICTIONAL_PRIVATE_NOT_A_CSR".to_string()),
        ] {
            assert!(
                ca().issue(&pem, "abc", Duration::hours(1)).is_err(),
                "{what} accepted"
            );
        }
    }

    fn rebuild_with_signature_algorithm(pem: &str, algorithm: &[u8]) -> String {
        use x509_parser::certification_request::X509CertificationRequest;
        let der = der(pem);
        let (_, csr) = X509CertificationRequest::from_der(&der).unwrap();
        canonical_pem(&request_der(
            csr.certification_request_info.raw,
            algorithm,
            &csr.signature_value,
        ))
    }

    #[test]
    fn rejects_extra_signature_algorithm_parameters() {
        let bare = csr(&KeyPair::generate().unwrap());
        assert_eq!(
            rebuild_with_signature_algorithm(&bare, &ECDSA_WITH_SHA256),
            bare
        );
        let oid = &ECDSA_WITH_SHA256[2..];
        let mut with_text = oid.to_vec();
        with_text.extend(der_tlv(0x0c, b"FICTIONAL extra parameter"));
        let mut with_null = oid.to_vec();
        with_null.extend([0x05, 0x00]);
        for (what, algorithm) in [
            ("text parameter", der_tlv(0x30, &with_text)),
            ("NULL parameter", der_tlv(0x30, &with_null)),
        ] {
            let pem = rebuild_with_signature_algorithm(&bare, &algorithm);
            assert!(
                ca().issue(&pem, "abc", Duration::hours(1)).is_err(),
                "{what} accepted"
            );
        }
        assert!(ca().issue(&bare, "abc", Duration::hours(1)).is_ok());
    }

    #[test]
    fn rejects_csr_with_a_broken_signature() {
        let pem = csr(&KeyPair::generate().unwrap());
        let mut lines: Vec<String> = pem.lines().map(str::to_string).collect();
        let last_body = lines.len() - 2;
        let flipped = if lines[last_body].starts_with('A') {
            "B"
        } else {
            "A"
        };
        lines[last_body].replace_range(0..1, flipped);
        let tampered = lines.join("\n") + "\n";
        assert_ne!(tampered.trim(), pem.trim());
        assert_eq!(
            ca().issue(&tampered, "abc", Duration::hours(1))
                .unwrap_err(),
            "csr_pem is not a valid signed certificate request: Invalid CSR signature"
        );
        assert!(ca().issue(&pem, "abc", Duration::hours(1)).is_ok());
    }
}
