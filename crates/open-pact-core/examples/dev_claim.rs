//! Prints a claim JWS signed by a throwaway key, for smoke tests that need chosen results.
//! Usage: dev_claim <manifest.toml|sha256:...> <nonce> <os> [check=value ...]

use std::collections::BTreeMap;

use open_pact_core::{
    Claim, Manifest, ManifestHash, Os, Pseudonym, PublicKey, TrustLevel, Virtualized, dev_key,
    sign_claim,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [manifest, nonce, os, results @ ..] = args.as_slice() else {
        return Err(
            "usage: dev_claim <manifest.toml|sha256:...> <nonce> <os> [check=value ...]".into(),
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
    let key = dev_key::generate();
    let device_key = PublicKey::from(&key);
    let claim = Claim {
        manifest,
        device: Pseudonym::of(&device_key),
        device_key,
        nonce: nonce.clone(),
        time: chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).ok_or("clock")?,
        client: "dev_claim".into(),
        os,
        trust_level: TrustLevel::L0,
        virtualized: Virtualized::No,
        results,
        csr_pem: None,
    };
    println!("{}", sign_claim(&claim, &key)?);
    Ok(())
}
