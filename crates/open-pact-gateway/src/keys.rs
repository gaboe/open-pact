use anyhow::Context;
use open_pact_core::{SigningKey, dev_key};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

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

async fn secret(
    db: &PgPool,
    name: &str,
    make: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let select = || {
        sqlx::query_scalar::<_, String>("SELECT value FROM gateway_secrets WHERE name = $1")
            .bind(name)
    };
    if let Some(value) = select().fetch_optional(db).await? {
        return Ok(value);
    }
    sqlx::query(
        "INSERT INTO gateway_secrets (name, value) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .bind(make()?)
    .execute(db)
    .await?;
    eprintln!("generated {name}");
    Ok(select().fetch_one(db).await?)
}

impl Keys {
    pub async fn load_or_create(db: &PgPool) -> anyhow::Result<Keys> {
        let new_key = || Ok(dev_key::to_pem(&dev_key::generate()));
        let manifest = dev_key::from_pem(&secret(db, "manifest_signing_key", new_key).await?)
            .context("manifest_signing_key")?;
        let log = dev_key::from_pem(&secret(db, "log_signing_key", new_key).await?)
            .context("log_signing_key")?;
        let ca_key = secret(db, "ca_key", || Ok(KeyPair::generate()?.serialize_pem())).await?;
        let ca_cert = secret(db, "ca_cert", || {
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
        let mut params = CertificateParams::default();
        params.distinguished_name = common_name("requested-name");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.serialize_request(key).unwrap().pem().unwrap()
    }

    fn der(pem: &str) -> Vec<u8> {
        x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .unwrap()
            .1
            .contents
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
        let tampered = lines.join("\n");
        assert_ne!(tampered.trim(), pem.trim());
        assert_eq!(
            ca().issue(&tampered, "abc", Duration::hours(1))
                .unwrap_err(),
            "csr_pem is not a valid signed certificate request: Invalid CSR signature"
        );
        assert!(ca().issue(&pem, "abc", Duration::hours(1)).is_ok());
    }
}
