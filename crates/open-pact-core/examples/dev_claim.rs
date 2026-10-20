//! Prints a claim JWS with chosen results, for smoke tests. The key file is created if missing.
//! Usage: dev_claim <key.pem> <manifest.toml|sha256:...> <nonce> <os> [check=value ...]
//! With a manifest file, value types follow its output declaration. Unknown controls use text.
//! With only a hash, use check=s:text or check=i:30 for an explicit string or integer.
//! DEV_CLAIM_LOG_CHECKPOINT="<size> <base64 root>" adds a log checkpoint to the claim.

use std::collections::BTreeMap;

use open_pact_core::{
    Claim, ControlValue, LogCheckpoint, LogHash, Manifest, ManifestHash, Os, Output, Pseudonym,
    PublicKey, TrustLevel, Virtualized, dev_key, sign_claim,
};

fn log_checkpoint() -> Result<Option<LogCheckpoint>, Box<dyn std::error::Error>> {
    use base64::Engine;
    let Ok(value) = std::env::var("DEV_CLAIM_LOG_CHECKPOINT") else {
        return Ok(None);
    };
    let (size, root) = value
        .split_once(' ')
        .ok_or("expected <size> <base64 root>")?;
    let root = base64::engine::general_purpose::STANDARD.decode(root)?;
    Ok(Some(LogCheckpoint {
        size: size.parse()?,
        root: LogHash(root.try_into().map_err(|_| "root must be 32 bytes")?),
    }))
}

fn result_value(
    manifest: Option<&Manifest>,
    id: &str,
    value: &str,
) -> Result<ControlValue, Box<dyn std::error::Error>> {
    if let Some(manifest) = manifest {
        return match manifest.body().control(id).map(|c| &c.output) {
            Some(Output::Integer(_)) if value != "unknown" && value != "n/a" && value != "none" => {
                Ok(value.parse::<i32>()?.into())
            }
            _ => Ok(value.into()),
        };
    }
    if let Some(text) = value.strip_prefix("s:") {
        return Ok(text.into());
    }
    if let Some(number) = value.strip_prefix("i:") {
        return Ok(number.parse::<i32>()?.into());
    }
    Err("hash-only results need check=s:text or check=i:30".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [key, manifest, nonce, os, results @ ..] = args.as_slice() else {
        return Err(
            "usage: dev_claim <key.pem> <manifest.toml|sha256:...> <nonce> <os> [check=value ...]"
                .into(),
        );
    };
    let (manifest, parsed) = match ManifestHash::try_from(manifest.clone()) {
        Ok(hash) => (hash, None),
        Err(_) => {
            let parsed = Manifest::parse(&std::fs::read(manifest)?)?;
            (parsed.hash().clone(), Some(parsed))
        }
    };
    let os: Os = serde_json::from_value(os.as_str().into())?;
    let results = results
        .iter()
        .map(|kv| {
            let (id, value) = kv.split_once('=').ok_or("expected check=value")?;
            Ok((id.to_string(), result_value(parsed.as_ref(), id, value)?))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    let key = dev_key::load_or_create(std::path::Path::new(key))?;
    let device_key = PublicKey::from(&key);
    let claim = Claim {
        manifest,
        device: Pseudonym::of(&device_key),
        device_key,
        nonce: nonce.clone(),
        time: chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).ok_or("clock")?,
        client: concat!("open-pact-client ", env!("CARGO_PKG_VERSION")).into(),
        os,
        trust_level: TrustLevel::L0,
        virtualized: Some(Virtualized::No),
        results,
        csr_sha256: None,
        log_checkpoint: log_checkpoint()?,
    };
    println!("{}", sign_claim(&claim, &key)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_looking_enum_stays_text() {
        let text = include_str!("../../../examples/manifest.toml")
            .replace(
                "output = [\"on\", \"off\", \"unknown\"]",
                "output = [\"1\", \"0\", \"unknown\"]",
            )
            .replace(
                "macos = \"on\", windows = \"on\", linux = \"on\"",
                "macos = \"1\", windows = \"1\", linux = \"1\"",
            );
        let manifest = Manifest::parse(text.as_bytes()).unwrap();
        assert_eq!(
            result_value(Some(&manifest), "firewall", "1").unwrap(),
            ControlValue::Text("1".into())
        );
        assert_eq!(
            result_value(Some(&manifest), "os_patch_age_days", "14").unwrap(),
            ControlValue::Integer(14)
        );
    }
    #[test]
    fn hash_only_requires_explicit_type() {
        assert_eq!(
            result_value(None, "firewall", "s:1").unwrap(),
            ControlValue::Text("1".into())
        );
        assert_eq!(
            result_value(None, "os_patch_age_days", "i:30").unwrap(),
            ControlValue::Integer(30)
        );
        assert!(result_value(None, "firewall", "1").is_err());
    }
}
