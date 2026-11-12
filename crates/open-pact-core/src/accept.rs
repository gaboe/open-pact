//! The owner's acceptance of a changed manifest. An enrolled device moves from the manifest its
//! owner signed to the one the gateway enforces now, with no new invitation or approval. The owner
//! and the device both sign one statement that binds the pseudonym, both manifest hashes, both
//! keys and a fresh gateway nonce. Its `type` differs from every other signed statement, so a join
//! or device authentication signature cannot stand in for it.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Endorsement, Error, ManifestHash, Pseudonym, PublicKey, Signature, SigningKey};

pub fn accept_statement(
    device: &Pseudonym,
    nonce: &str,
    previous: &ManifestHash,
    manifest: &ManifestHash,
    owner: &PublicKey,
    device_key: &PublicKey,
) -> Vec<u8> {
    serde_jcs::to_vec(&json!({
        "type": "open-pact-accept/v1",
        "pseudonym": device,
        "nonce": nonce,
        "previous": previous,
        "manifest": manifest,
        "owner_key": owner,
        "device_key": device_key,
    }))
    .expect("statement fields always serialize")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptRequest {
    pub pseudonym: Pseudonym,
    pub device_key: PublicKey,
    pub nonce: String,
    /// The manifest the owner signed before.
    pub previous: ManifestHash,
    /// The manifest the owner accepts now.
    pub manifest: ManifestHash,
    /// The owner's signature on `manifest`, as `join` signs the manifest it enrols under.
    pub owner: Endorsement,
    pub owner_signature: Signature,
    pub device_signature: Signature,
}

impl AcceptRequest {
    /// Signs with a device key held elsewhere, such as a Secure Enclave; `device_key` is the public
    /// half of `sign_device`.
    pub fn sign_with<E: From<Error>>(
        previous: ManifestHash,
        manifest: ManifestHash,
        nonce: String,
        owner: &SigningKey,
        device_key: &PublicKey,
        sign_device: impl FnOnce(&[u8]) -> Result<Signature, E>,
    ) -> Result<Self, E> {
        let pseudonym = Pseudonym::of(device_key);
        let statement = accept_statement(
            &pseudonym,
            &nonce,
            &previous,
            &manifest,
            &PublicKey::from(owner),
            device_key,
        );
        Ok(Self {
            device_signature: sign_device(&statement)?,
            owner_signature: Signature::sign(owner, &statement),
            owner: Endorsement::sign(owner, &manifest),
            pseudonym,
            device_key: device_key.clone(),
            nonce,
            previous,
            manifest,
        })
    }

    /// Checks the pseudonym, the owner's manifest signature and both statement signatures. Callers
    /// must still compare `owner.key` with the key that enrolled the device.
    pub fn verify(&self) -> Result<(), Error> {
        if Pseudonym::of(&self.device_key) != self.pseudonym {
            return Err(Error::PseudonymMismatch);
        }
        if !self.owner.verify(&self.manifest) {
            return Err(Error::BadSignature("owner manifest signature"));
        }
        let statement = accept_statement(
            &self.pseudonym,
            &self.nonce,
            &self.previous,
            &self.manifest,
            &self.owner.key,
            &self.device_key,
        );
        if !self.owner.key.verify(&statement, &self.owner_signature) {
            return Err(Error::BadSignature("owner acceptance signature"));
        }
        if !self.device_key.verify(&statement, &self.device_signature) {
            return Err(Error::BadSignature(
                "device acceptance signature: the sender does not hold the device key",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceAuthPurpose, InvitationCode, dev_key, device_auth_statement, enrol_statement,
    };

    fn hash(text: &str) -> ManifestHash {
        ManifestHash::of(text.as_bytes())
    }

    fn request(owner: &SigningKey, device: &SigningKey) -> AcceptRequest {
        AcceptRequest::sign_with(
            hash("old"),
            hash("new"),
            "nonce".into(),
            owner,
            &PublicKey::from(device),
            |statement| Ok::<_, Error>(Signature::sign(device, statement)),
        )
        .unwrap()
    }

    #[test]
    fn a_signed_acceptance_verifies_after_a_json_roundtrip() {
        let req = request(&dev_key::generate(), &dev_key::generate());
        let back: AcceptRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        back.verify().unwrap();
    }

    #[test]
    fn the_signatures_bind_both_hashes_the_nonce_and_the_device() {
        let (owner, device) = (dev_key::generate(), dev_key::generate());
        let original = request(&owner, &device);
        let mut changed = original.clone();
        changed.previous = hash("other");
        assert!(changed.verify().is_err());
        let mut changed = original.clone();
        changed.nonce.push('x');
        assert!(changed.verify().is_err());
        let mut changed = original.clone();
        changed.manifest = hash("other");
        assert!(changed.verify().is_err());
        let mut changed = original.clone();
        changed.device_key = PublicKey::from(&dev_key::generate());
        assert!(matches!(changed.verify(), Err(Error::PseudonymMismatch)));
        let mut changed = original;
        changed.owner_signature = Signature::sign(&dev_key::generate(), b"x");
        assert!(changed.verify().is_err());
    }

    /// A signature the device made for join or for device authentication is not an acceptance.
    #[test]
    fn join_and_device_status_signatures_do_not_pass_as_an_acceptance() {
        let (owner, device) = (dev_key::generate(), dev_key::generate());
        let original = request(&owner, &device);
        let status = device_auth_statement(
            DeviceAuthPurpose::DeviceStatus,
            &original.pseudonym,
            &original.nonce,
        );
        let join = enrol_statement(
            &original.manifest,
            &InvitationCode::from_bytes([3; 32]).hash(),
            &original.owner.key,
            &original.device_key,
        );
        for statement in [status, join] {
            let mut forged = original.clone();
            forged.device_signature = Signature::sign(&device, &statement);
            assert!(
                matches!(forged.verify(), Err(Error::BadSignature(m)) if m.starts_with("device acceptance")),
                "a device signature over another statement passed"
            );
            let mut forged = original.clone();
            forged.owner_signature = Signature::sign(&owner, &statement);
            assert!(
                matches!(
                    forged.verify(),
                    Err(Error::BadSignature("owner acceptance signature"))
                ),
                "an owner signature over another statement passed"
            );
        }
    }
}
