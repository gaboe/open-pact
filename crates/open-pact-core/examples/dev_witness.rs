//! A demo witness with a fixed, public Ed25519 key. Never use it outside demos.
//! Usage: dev_witness vkey            prints the verifier key for WITNESS_KEYS
//!        dev_witness cosign < note   prints the note with a cosignature/v1 line appended
//!
//! A real witness (c2sp.org/tlog-witness) first checks a consistency proof from the last
//! checkpoint it cosigned. This one signs whatever checkpoint it is given.

use std::io::Read;

use open_pact_core::{Checkpoint, Note, WitnessKey};
use sha2::{Digest, Sha256};

const NAME: &str = "witness.example.org/demo";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed: [u8; 32] = Sha256::digest(b"open-pact demo witness, public seed").into();
    let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
    let key = WitnessKey::new(NAME, signer.verifying_key());
    match std::env::args().nth(1).as_deref() {
        Some("vkey") => println!("{}", key.vkey()),
        Some("cosign") => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            let mut note = Note::parse(&text)?;
            let checkpoint = Checkpoint::parse(&note.text)?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
            note.signatures
                .push(key.cosign(&signer, &checkpoint, now.as_secs()));
            print!("{note}");
        }
        _ => return Err("usage: dev_witness vkey | dev_witness cosign < checkpoint".into()),
    }
    Ok(())
}
