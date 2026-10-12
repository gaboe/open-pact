//! Witnessing, c2sp.org/tlog-witness: the add-checkpoint rules a witness enforces, and the
//! manifest's witness policy a client enforces before it trusts a checkpoint.

use std::collections::BTreeMap;
use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::{Checkpoint, Error, LogHash, LogKey, LogPolicy, Note, verify_consistency};

/// A cosignature may be this far in the future, for clock skew between witness and client.
pub const CLOCK_SKEW_SECS: u64 = 300;

/// The tlog-witness limit on consistency proof lines.
const MAX_PROOF: usize = 63;

/// The body of `POST <prefix>/add-checkpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddCheckpoint {
    pub old_size: u64,
    pub proof: Vec<LogHash>,
    pub note: Note,
}

impl fmt::Display for AddCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "old {}", self.old_size)?;
        for h in &self.proof {
            writeln!(f, "{}", STANDARD.encode(h.0))?;
        }
        writeln!(f)?;
        self.note.fmt(f)
    }
}

impl AddCheckpoint {
    pub fn parse(body: &str) -> Result<Self, Error> {
        let bad = |msg: &str| Error::Log(format!("add-checkpoint body: {msg}"));
        let (head, note) = body
            .split_once("\n\n")
            .ok_or_else(|| bad("no blank line before the checkpoint"))?;
        let mut lines = head.split('\n');
        let old = lines
            .next()
            .and_then(|l| l.strip_prefix("old "))
            .ok_or_else(|| bad("first line must be old <size>"))?;
        let old_size = old
            .parse::<u64>()
            .ok()
            .filter(|n| n.to_string() == old)
            .ok_or_else(|| bad("bad old size"))?;
        let proof = lines
            .map(|l| {
                STANDARD
                    .decode(l)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .map(LogHash)
                    .ok_or_else(|| bad("bad proof hash"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if proof.len() > MAX_PROOF {
            return Err(bad("more than 63 proof lines"));
        }
        Ok(AddCheckpoint {
            old_size,
            proof,
            note: Note::parse(note)?,
        })
    }
}

/// Why a witness refuses to cosign, one variant per tlog-witness status code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not signed by the log key: {0}")]
    Forbidden(String),
    #[error("unknown log {0:?}")]
    UnknownLog(String),
    /// The witness last cosigned this size for the log, not the request's old size.
    #[error("the witness last cosigned size {0}")]
    Conflict(u64),
    #[error("{0}")]
    Unprocessable(String),
}

impl Refusal {
    pub fn status(&self) -> u16 {
        match self {
            Refusal::BadRequest(_) => 400,
            Refusal::Forbidden(_) => 403,
            Refusal::UnknownLog(_) => 404,
            Refusal::Conflict(_) => 409,
            Refusal::Unprocessable(_) => 422,
        }
    }
}

/// The add-checkpoint decision. Returns the checkpoint to cosign; the caller must store it as the
/// latest for its origin in the same atomic step, so no fork or rollback can follow it.
pub fn add_checkpoint(
    logs: &[LogKey],
    latest: &BTreeMap<String, Checkpoint>,
    req: &AddCheckpoint,
) -> Result<Checkpoint, Refusal> {
    let origin = Checkpoint::parse(&req.note.text)
        .map_err(|e| Refusal::BadRequest(e.to_string()))?
        .origin;
    let key = logs
        .iter()
        .find(|k| k.origin() == origin)
        .ok_or_else(|| Refusal::UnknownLog(origin.clone()))?;
    let new = key
        .verify(&req.note)
        .map_err(|e| Refusal::Forbidden(e.to_string()))?;
    if req.old_size > new.size {
        return Err(Refusal::BadRequest(format!(
            "old size {} is larger than the checkpoint size {}",
            req.old_size, new.size
        )));
    }
    let stored = latest.get(&origin);
    if stored.map_or(0, |c| c.size) != req.old_size {
        return Err(Refusal::Conflict(stored.map_or(0, |c| c.size)));
    }
    // A stored empty tree has no history to extend, so it is checked like a first checkpoint.
    match stored.filter(|c| c.size > 0) {
        None if !req.proof.is_empty() => Err(Refusal::Unprocessable(
            "a proof from size 0 must be empty".into(),
        )),
        None if new.size == 0 && new.root != crate::root(&[]) => Err(Refusal::Unprocessable(
            "an empty tree must have the empty root".into(),
        )),
        None => Ok(new),
        Some(old) => verify_consistency(old.size, new.size, &old.root, &new.root, &req.proof)
            .map(|()| new)
            .map_err(|e| Refusal::Unprocessable(e.to_string())),
    }
}

/// Checks the manifest's witness policy: at least `witness_quorum` of the listed witnesses
/// cosigned `checkpoint`, each no longer than `checkpoint_max_age` ago. Returns the names that
/// count. `now` is Unix seconds.
pub fn verify_cosignatures<'p>(
    policy: Option<&'p LogPolicy>,
    checkpoint: &Checkpoint,
    note: &Note,
    now: u64,
) -> Result<Vec<&'p str>, Error> {
    let Some(policy) = policy else {
        return Ok(vec![]);
    };
    let max_age = policy
        .checkpoint_max_age
        .min_duration()
        .and_then(|d| u64::try_from(d.num_seconds()).ok())
        .unwrap_or(u64::MAX);
    let mut counted = vec![];
    let mut problems = vec![];
    for w in &policy.witnesses {
        let times: Vec<Result<u64, Error>> = note
            .signatures
            .iter()
            .filter_map(|s| w.key.verify(checkpoint, s))
            .collect();
        let fresh = times.iter().filter_map(|t| t.as_ref().ok()).find(|&&t| {
            t <= now.saturating_add(CLOCK_SKEW_SECS) && now.saturating_sub(t) <= max_age
        });
        match (fresh, times.as_slice()) {
            (Some(_), _) => counted.push(w.name.as_str()),
            (None, []) => problems.push(format!("{}: no cosignature", w.name)),
            (None, [.., Err(e)]) => problems.push(format!("{}: {e}", w.name)),
            (None, [.., Ok(t)]) if *t > now => {
                problems.push(format!("{}: cosigned {}s in the future", w.name, t - now))
            }
            (None, [.., Ok(t)]) => problems.push(format!(
                "{}: cosigned {}s ago, more than checkpoint_max_age {}",
                w.name,
                now - t,
                policy.checkpoint_max_age
            )),
        }
    }
    if counted.len() < policy.witness_quorum {
        return Err(Error::Log(format!(
            "checkpoint size {} has {} of the {} witness cosignatures the manifest requires: {}",
            checkpoint.size,
            counted.len(),
            policy.witness_quorum,
            problems.join("; ")
        )));
    }
    Ok(counted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PublicKey, Span, Witness, WitnessKey, consistency_proof, dev_key, leaf_hash, root,
    };

    const ORIGIN: &str = "pact.example.com/log";
    const NOW: u64 = 1_790_000_000;

    struct Fixture {
        signer: crate::SigningKey,
        key: LogKey,
        leaves: Vec<LogHash>,
    }

    impl Fixture {
        fn new() -> Self {
            let signer = dev_key::generate();
            let key = LogKey::new(ORIGIN, &PublicKey::from(&signer));
            let leaves = (0u8..10).map(|i| leaf_hash(&[i])).collect();
            Fixture {
                signer,
                key,
                leaves,
            }
        }

        fn checkpoint(&self, size: u64) -> Checkpoint {
            Checkpoint {
                origin: ORIGIN.into(),
                size,
                root: root(&self.leaves[..size as usize]),
            }
        }

        fn request(&self, old: u64, cp: &Checkpoint) -> AddCheckpoint {
            let proof = if old == 0 || old >= cp.size {
                vec![]
            } else {
                consistency_proof(&self.leaves[..cp.size as usize], old).unwrap()
            };
            AddCheckpoint {
                old_size: old,
                proof,
                note: self.key.sign(&self.signer, cp),
            }
        }
    }

    fn stored(cp: &Checkpoint) -> BTreeMap<String, Checkpoint> {
        BTreeMap::from([(cp.origin.clone(), cp.clone())])
    }

    #[test]
    fn request_body_roundtrips() {
        let f = Fixture::new();
        let req = f.request(3, &f.checkpoint(7));
        assert!(!req.proof.is_empty());
        assert_eq!(AddCheckpoint::parse(&req.to_string()).unwrap(), req);
        assert!(req.to_string().starts_with("old 3\n"));
        for bad in ["old 03\n\n", "old x\n\n", "3\n\n", "old 3\nnot-base64\n\n"] {
            assert!(AddCheckpoint::parse(&format!("{bad}{}", req.note)).is_err());
        }
    }

    #[test]
    fn witness_accepts_extensions_and_resubmissions() {
        let f = Fixture::new();
        let logs = [f.key.clone()];
        let first = f.checkpoint(4);
        assert_eq!(
            add_checkpoint(&logs, &BTreeMap::new(), &f.request(0, &first)),
            Ok(first.clone())
        );
        let next = f.checkpoint(9);
        assert_eq!(
            add_checkpoint(&logs, &stored(&first), &f.request(4, &next)),
            Ok(next.clone())
        );
        assert_eq!(
            add_checkpoint(&logs, &stored(&next), &f.request(9, &next)),
            Ok(next),
            "the same checkpoint again gets a fresh cosignature"
        );
    }

    #[test]
    fn an_accepted_empty_checkpoint_can_be_renewed_and_extended() {
        let f = Fixture::new();
        let logs = [f.key.clone()];
        let empty = f.checkpoint(0);
        assert_eq!(
            add_checkpoint(&logs, &BTreeMap::new(), &f.request(0, &empty)),
            Ok(empty.clone())
        );
        assert_eq!(
            add_checkpoint(&logs, &stored(&empty), &f.request(0, &empty)),
            Ok(empty.clone()),
            "renewal"
        );
        assert_eq!(
            add_checkpoint(&logs, &stored(&empty), &f.request(0, &f.checkpoint(1))),
            Ok(f.checkpoint(1)),
            "growth"
        );
        let other_empty = Checkpoint {
            root: LogHash([3; 32]),
            ..empty.clone()
        };
        let refusal =
            add_checkpoint(&logs, &stored(&empty), &f.request(0, &other_empty)).unwrap_err();
        assert_eq!(refusal.status(), 422, "an empty tree with another root");
        let mut with_proof = f.request(0, &f.checkpoint(2));
        with_proof.proof = vec![f.leaves[0]];
        let refusal = add_checkpoint(&logs, &stored(&empty), &with_proof).unwrap_err();
        assert_eq!(refusal.status(), 422, "a proof from size 0");
    }

    #[test]
    fn witness_refuses_forks_rollbacks_and_strangers() {
        let f = Fixture::new();
        let logs = [f.key.clone()];
        let seen = stored(&f.checkpoint(6));

        let fork = Checkpoint {
            root: LogHash([1; 32]),
            ..f.checkpoint(6)
        };
        let refusal = add_checkpoint(&logs, &seen, &f.request(6, &fork)).unwrap_err();
        assert_eq!(refusal.status(), 422, "same size, other root: {refusal}");

        let mut longer_fork = f.request(6, &f.checkpoint(8));
        let forked = Checkpoint {
            root: LogHash([2; 32]),
            ..f.checkpoint(8)
        };
        longer_fork.note = f.key.sign(&f.signer, &forked);
        assert_eq!(
            add_checkpoint(&logs, &seen, &longer_fork)
                .unwrap_err()
                .status(),
            422
        );

        assert_eq!(
            add_checkpoint(&logs, &seen, &f.request(6, &f.checkpoint(5))).unwrap_err(),
            Refusal::BadRequest("old size 6 is larger than the checkpoint size 5".into())
        );
        assert_eq!(
            add_checkpoint(&logs, &seen, &f.request(3, &f.checkpoint(8))).unwrap_err(),
            Refusal::Conflict(6)
        );
        assert_eq!(
            add_checkpoint(&logs, &seen, &f.request(0, &f.checkpoint(8))).unwrap_err(),
            Refusal::Conflict(6)
        );

        let mut proof_from_zero = f.request(0, &f.checkpoint(8));
        proof_from_zero.proof = vec![LogHash([0; 32])];
        assert_eq!(
            add_checkpoint(&logs, &BTreeMap::new(), &proof_from_zero)
                .unwrap_err()
                .status(),
            422
        );

        let other = dev_key::generate();
        let impostor = LogKey::new(ORIGIN, &PublicKey::from(&other));
        let mut forged = f.request(6, &f.checkpoint(8));
        forged.note = impostor.sign(&other, &f.checkpoint(8));
        assert_eq!(
            add_checkpoint(&logs, &seen, &forged).unwrap_err().status(),
            403
        );

        let unknown = LogKey::new("other.example.org/log", &PublicKey::from(&f.signer));
        let mut stranger = f.request(0, &f.checkpoint(2));
        stranger.note = unknown.sign(
            &f.signer,
            &Checkpoint {
                origin: "other.example.org/log".into(),
                ..f.checkpoint(2)
            },
        );
        assert_eq!(
            add_checkpoint(&logs, &seen, &stranger)
                .unwrap_err()
                .status(),
            404
        );
    }

    fn witness(seed: u8) -> (ed25519_dalek::SigningKey, Witness) {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let name = format!("witness.example.org/w{seed}");
        let key = WitnessKey::new(&name, signer.verifying_key());
        (signer, Witness { name, key })
    }

    fn policy(quorum: usize, witnesses: &[&Witness]) -> LogPolicy {
        LogPolicy {
            witnesses: witnesses.iter().map(|w| (*w).clone()).collect(),
            allow_split_views: false,
            witness_quorum: quorum,
            checkpoint_max_age: Span::try_from("1h".to_string()).unwrap(),
        }
    }

    #[test]
    fn client_requires_a_quorum_of_fresh_cosignatures() {
        let f = Fixture::new();
        let cp = f.checkpoint(5);
        let (s1, w1) = witness(1);
        let (s2, w2) = witness(2);
        let (s3, w3) = witness(3);
        let two_of_three = policy(2, &[&w1, &w2, &w3]);
        let mut note = f.key.sign(&f.signer, &cp);
        note.signatures.push(w1.key.cosign(&s1, &cp, NOW - 60));
        note.signatures.push(w1.key.cosign(&s1, &cp, NOW - 30));

        let err = verify_cosignatures(Some(&two_of_three), &cp, &note, NOW).unwrap_err();
        assert!(
            err.to_string().contains("has 1 of the 2"),
            "one witness counts once however often it signs: {err}"
        );

        note.signatures.push(w2.key.cosign(&s2, &cp, NOW - 3601));
        let err = verify_cosignatures(Some(&two_of_three), &cp, &note, NOW).unwrap_err();
        assert!(err.to_string().contains("w2: cosigned 3601s ago"), "{err}");

        note.signatures.push(w3.key.cosign(&s3, &cp, NOW + 3600));
        let err = verify_cosignatures(Some(&two_of_three), &cp, &note, NOW).unwrap_err();
        assert!(
            err.to_string().contains("w3: cosigned 3600s in the future"),
            "{err}"
        );

        note.signatures.push(w3.key.cosign(&s3, &cp, NOW + 10));
        assert_eq!(
            verify_cosignatures(Some(&two_of_three), &cp, &note, NOW).unwrap(),
            vec!["witness.example.org/w1", "witness.example.org/w3"]
        );

        let other = Checkpoint {
            root: LogHash([9; 32]),
            ..cp.clone()
        };
        let err = verify_cosignatures(Some(&policy(1, &[&w1])), &other, &note, NOW).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn foreign_cosignatures_do_not_count_and_no_policy_requires_none() {
        let f = Fixture::new();
        let cp = f.checkpoint(5);
        let (_, w1) = witness(1);
        let (s9, w9) = witness(9);
        let mut note = f.key.sign(&f.signer, &cp);
        note.signatures.push(w9.key.cosign(&s9, &cp, NOW));
        assert!(verify_cosignatures(Some(&policy(1, &[&w1])), &cp, &note, NOW).is_err());
        assert_eq!(
            verify_cosignatures(Some(&policy(0, &[&w1])), &cp, &note, NOW).unwrap(),
            Vec::<&str>::new()
        );
        assert_eq!(
            verify_cosignatures(None, &cp, &note, NOW).unwrap(),
            Vec::<&str>::new()
        );
    }
}
