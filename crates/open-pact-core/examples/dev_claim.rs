//! Prints a claim JWS with chosen results, for smoke tests. The key file is created if missing.
//! Usage: dev_claim <key.pem> <manifest.toml|sha256:...> <nonce> <os> [check=value ...]
//! DEV_CLAIM_LOG_CHECKPOINT="<size> <base64 root>" adds a log checkpoint to the claim.

use std::collections::BTreeMap;

use open_pact_core::{
    Claim, LogCheckpoint, LogHash, Manifest, ManifestHash, Os, Pseudonym, PublicKey, TrustLevel,
    Virtualized, dev_key, sign_claim,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [key, manifest, nonce, os, results @ ..] = args.as_slice() else {
        return Err(
            "usage: dev_claim <key.pem> <manifest.toml|sha256:...> <nonce> <os> [check=value ...]"
                .into(),
        );
    };
    let manifest = match ManifestHash::try_from(manifest.clone()) {
        Ok(hash) => hash,
        Err(_) => Manifest::parse(&std::fs::read(manifest)?)?.hash().clone(),
    };
    let os: Os = serde_json::from_value(os.as_str().into())?;
    let results = results
        .iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or("expected check=value")
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
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
