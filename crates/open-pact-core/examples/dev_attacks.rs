//! Test fixtures that play a dishonest log for smoke.sh and demo.sh. Never use them elsewhere:
//! both keys come from public seeds.
//!
//! Usage: dev_attacks test-log-key        verifier key of the test log (WITNESS_LOG_KEYS in compose)
//!        dev_attacks add <old> <size>    add-checkpoint body for the honest test log, size <= 64
//!        dev_attacks fork <size>         add-checkpoint body from <size> to a checkpoint of the
//!                                        same size with another root, signed by the test log key
//!        dev_attacks stale <unix time>   reads a checkpoint note and replaces its cosignatures with
//!                                        one by the public demo witness key, dated <unix time>

use std::io::Read;

use open_pact_core::{
    AddCheckpoint, Checkpoint, LogHash, LogKey, Note, PublicKey, SigningKey, WitnessKey,
    consistency_proof, leaf_hash, root,
};
use sha2::{Digest, Sha256};

const TEST_LOG: &str = "log.example.org/witness-test";
const DEMO_WITNESS: &str = "witness.example.org/demo";

fn seed(phrase: &str) -> [u8; 32] {
    Sha256::digest(phrase.as_bytes()).into()
}

fn test_log() -> Result<(SigningKey, LogKey), Box<dyn std::error::Error>> {
    let signer = SigningKey::from_slice(&seed("open-pact witness test log, public seed"))?;
    let key = LogKey::new(TEST_LOG, &PublicKey::from(&signer));
    Ok((signer, key))
}

fn leaves(size: u64) -> Vec<LogHash> {
    (0..size).map(|i| leaf_hash(&i.to_be_bytes())).collect()
}

fn body(old: u64, size: u64, root: LogHash) -> Result<String, Box<dyn std::error::Error>> {
    if size > 64 || old > size {
        return Err("need old <= size <= 64".into());
    }
    let (signer, key) = test_log()?;
    let proof = if old == 0 || old == size {
        vec![]
    } else {
        consistency_proof(&leaves(size), old)?
    };
    let checkpoint = Checkpoint {
        origin: TEST_LOG.into(),
        size,
        root,
    };
    Ok(AddCheckpoint {
        old_size: old,
        proof,
        note: key.sign(&signer, &checkpoint),
    }
    .to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let number = |i: usize| -> Result<u64, Box<dyn std::error::Error>> {
        Ok(args.get(i).ok_or("missing number")?.parse()?)
    };
    match args.first().map(String::as_str) {
        Some("test-log-key") => println!("{}", test_log()?.1.vkey()),
        Some("add") => print!("{}", body(number(1)?, number(2)?, root(&leaves(number(2)?)))?),
        Some("fork") => {
            let size = number(1)?;
            let mut other = leaves(size);
            *other.last_mut().ok_or("size must be at least 1")? = leaf_hash(b"forked");
            print!("{}", body(size, size, root(&other))?);
        }
        Some("stale") => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            let mut note = Note::parse(&text)?;
            note.signatures.truncate(1);
            let checkpoint = Checkpoint::parse(&note.text)?;
            let signer = ed25519_dalek::SigningKey::from_bytes(&seed(
                "open-pact demo witness, public seed",
            ));
            let witness = WitnessKey::new(DEMO_WITNESS, signer.verifying_key());
            note.signatures
                .push(witness.cosign(&signer, &checkpoint, number(1)?));
            print!("{note}");
        }
        _ => return Err("usage: dev_attacks test-log-key | add <old> <size> | fork <size> | stale <unix time> < note".into()),
    }
    Ok(())
}
