use serde::{Deserialize, Serialize};

use crate::{Entry, Error, LogHash, Pseudonym, PublicKey, Signature};

#[derive(Debug, Clone, Copy)]
pub enum DeviceAuthPurpose {
    LogMine,
    DeviceStatus,
}

pub fn device_auth_statement(
    purpose: DeviceAuthPurpose,
    pseudonym: &Pseudonym,
    nonce: &str,
) -> Vec<u8> {
    let purpose = match purpose {
        DeviceAuthPurpose::LogMine => "log-mine",
        DeviceAuthPurpose::DeviceStatus => "device-status",
    };
    serde_jcs::to_vec(&serde_json::json!({
        "type": "open-pact-device-auth/v1", "purpose": purpose,
        "pseudonym": pseudonym, "nonce": nonce,
    }))
    .expect("device authentication fields serialize")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MyEntriesRequest {
    pub pseudonym: Pseudonym,
    pub nonce: String,
    pub device_key: PublicKey,
    pub signature: Signature,
}

impl MyEntriesRequest {
    pub fn verify(&self, purpose: DeviceAuthPurpose) -> Result<(), Error> {
        if Pseudonym::of(&self.device_key) != self.pseudonym {
            return Err(Error::PseudonymMismatch);
        }
        if !self.device_key.verify(
            &device_auth_statement(purpose, &self.pseudonym, &self.nonce),
            &self.signature,
        ) {
            return Err(Error::BadSignature("device authentication"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryWithProof {
    pub entry: Entry,
    pub proof: Vec<LogHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MyEntries {
    pub checkpoint: String,
    pub manifest: EntryWithProof,
    pub device: Vec<EntryWithProof>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Pending,
    Approved,
    Revoked,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_key;

    #[test]
    fn authentication_binds_the_purpose_nonce_and_enrolled_key() {
        let key = dev_key::generate();
        let device_key = PublicKey::from(&key);
        let pseudonym = Pseudonym::of(&device_key);
        let mut request = MyEntriesRequest {
            signature: Signature::sign(
                &key,
                &device_auth_statement(DeviceAuthPurpose::LogMine, &pseudonym, "nonce"),
            ),
            pseudonym,
            nonce: "nonce".into(),
            device_key,
        };
        request.verify(DeviceAuthPurpose::LogMine).unwrap();
        assert!(request.verify(DeviceAuthPurpose::DeviceStatus).is_err());
        request.nonce.push('x');
        assert!(request.verify(DeviceAuthPurpose::LogMine).is_err());
        request.nonce.pop();
        request.device_key = PublicKey::from(&dev_key::generate());
        assert!(request.verify(DeviceAuthPurpose::LogMine).is_err());
    }
}
