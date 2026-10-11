//! The enrolment request. The owner and the device both sign one statement that binds the manifest
//! hash, the invitation and both public keys. The device signature proves the sender holds the
//! device key, so nobody can enrol, or squat, a device key they do not hold. The owner signature
//! binds the device key to the owner who consented.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Error, InvitationCode, InvitationHash, Manifest, ManifestHash, PublicKey, Signature,
    SignedManifest, SigningKey,
};

/// The bytes both keys sign: RFC 8785 JSON with a `type` that no other signed object carries.
pub fn enrol_statement(
    manifest: &ManifestHash,
    invitation: &InvitationHash,
    owner: &PublicKey,
    device: &PublicKey,
) -> Vec<u8> {
    serde_jcs::to_vec(&json!({
        "type": "open-pact-enrol/v1",
        "manifest": manifest,
        "invitation": invitation,
        "owner_key": owner,
        "device_key": device,
    }))
    .expect("statement fields always serialize")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolRequest {
    pub signed_manifest: SignedManifest,
    pub device_key: PublicKey,
    pub invitation_code: InvitationCode,
    pub owner_signature: Signature,
    pub device_signature: Signature,
}

impl EnrolRequest {
    pub fn sign(
        signed_manifest: SignedManifest,
        invitation_code: InvitationCode,
        owner: &SigningKey,
        device: &SigningKey,
    ) -> Result<Self, Error> {
        Self::sign_with(
            signed_manifest,
            invitation_code,
            owner,
            &PublicKey::from(device),
            |statement| Ok::<_, Error>(Signature::sign(device, statement)),
        )
    }

    /// Signs with a device key held elsewhere, such as a Secure Enclave; `device_key` is the public
    /// half of `sign_device`.
    pub fn sign_with<E: From<Error>>(
        signed_manifest: SignedManifest,
        invitation_code: InvitationCode,
        owner: &SigningKey,
        device_key: &PublicKey,
        sign_device: impl FnOnce(&[u8]) -> Result<Signature, E>,
    ) -> Result<Self, E> {
        if signed_manifest.owner.key != PublicKey::from(owner) {
            return Err(Error::KeyMismatch.into());
        }
        let manifest = Manifest::parse(signed_manifest.toml.as_bytes())?;
        let statement = enrol_statement(
            manifest.hash(),
            &invitation_code.hash(),
            &signed_manifest.owner.key,
            device_key,
        );
        Ok(Self {
            owner_signature: Signature::sign(owner, &statement),
            device_signature: sign_device(&statement)?,
            signed_manifest,
            device_key: device_key.clone(),
            invitation_code,
        })
    }

    /// Checks the company and owner manifest signatures and both enrolment signatures. Callers
    /// must still pin the company key.
    pub fn verify(&self) -> Result<Manifest, Error> {
        let manifest = self.signed_manifest.verify()?;
        let statement = enrol_statement(
            manifest.hash(),
            &self.invitation_code.hash(),
            &self.signed_manifest.owner.key,
            &self.device_key,
        );
        if !self
            .signed_manifest
            .owner
            .key
            .verify(&statement, &self.owner_signature)
        {
            return Err(Error::BadSignature("owner enrolment signature"));
        }
        if !self.device_key.verify(&statement, &self.device_signature) {
            return Err(Error::BadSignature(
                "device enrolment signature: the sender does not hold the device key",
            ));
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Endorsement, dev_key};

    const DEMO: &str = include_str!("../../../examples/manifest.toml");

    fn request(owner: &SigningKey, device: &SigningKey) -> EnrolRequest {
        let hash = ManifestHash::of(DEMO.as_bytes());
        let signed = SignedManifest {
            toml: DEMO.into(),
            company: Endorsement::sign(&dev_key::generate(), &hash),
            owner: Endorsement::sign(owner, &hash),
        };
        EnrolRequest::sign(signed, InvitationCode::from_bytes([3; 32]), owner, device).unwrap()
    }

    #[test]
    fn a_signed_request_verifies_after_a_json_roundtrip() {
        let req = request(&dev_key::generate(), &dev_key::generate());
        let back: EnrolRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(
            back.verify().unwrap().hash(),
            &ManifestHash::of(DEMO.as_bytes())
        );
    }

    #[test]
    fn someone_elses_device_key_cannot_be_enrolled() {
        let (owner, device) = (dev_key::generate(), dev_key::generate());
        let mut req = request(&owner, &dev_key::generate());
        req.device_key = PublicKey::from(&device);
        assert!(matches!(
            req.verify(),
            Err(Error::BadSignature("owner enrolment signature"))
        ));
        let mut squat = request(&owner, &dev_key::generate());
        let stolen = enrol_statement(
            &ManifestHash::of(DEMO.as_bytes()),
            &squat.invitation_code.hash(),
            &squat.signed_manifest.owner.key,
            &PublicKey::from(&device),
        );
        squat.device_key = PublicKey::from(&device);
        squat.owner_signature = Signature::sign(&owner, &stolen);
        assert!(matches!(
            squat.verify(),
            Err(Error::BadSignature(m)) if m.starts_with("device enrolment signature")
        ));
    }

    #[test]
    fn signatures_bind_the_invitation() {
        let mut req = request(&dev_key::generate(), &dev_key::generate());
        req.invitation_code = InvitationCode::from_bytes([4; 32]);
        assert!(req.verify().is_err());
    }

    #[test]
    fn the_owner_key_must_match_the_manifest_endorsement() {
        let req = request(&dev_key::generate(), &dev_key::generate());
        assert!(matches!(
            EnrolRequest::sign(
                req.signed_manifest,
                req.invitation_code,
                &dev_key::generate(),
                &dev_key::generate()
            ),
            Err(Error::KeyMismatch)
        ));
    }
}
