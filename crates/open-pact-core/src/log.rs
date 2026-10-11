//! Transparency log as an RFC 9162 (Certificate Transparency 2.0) Merkle tree, section 2.1.
//!
//! A leaf is `JCS({"kind", "data"})`. The index is not part of the leaf: the tree position fixes it.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LogHash(pub [u8; 32]);

impl TryFrom<String> for LogHash {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let mut bytes = [0; 32];
        match hex::decode_to_slice(&s, &mut bytes) {
            Ok(()) if s.bytes().all(|b| !b.is_ascii_uppercase()) => Ok(Self(bytes)),
            _ => Err(format!("expected 64 lowercase hex, got {s:?}")),
        }
    }
}

impl From<LogHash> for String {
    fn from(h: LogHash) -> String {
        h.to_string()
    }
}

impl fmt::Display for LogHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    ManifestPublished,
    DeviceEnrolled,
    DeviceApproved,
    DeviceRevoked,
    RetentionPurge,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryKind::ManifestPublished => "manifest_published",
            EntryKind::DeviceEnrolled => "device_enrolled",
            EntryKind::DeviceApproved => "device_approved",
            EntryKind::DeviceRevoked => "device_revoked",
            EntryKind::RetentionPurge => "retention_purge",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub index: u64,
    pub kind: EntryKind,
    pub data: Value,
}

impl Entry {
    pub fn leaf_bytes(&self) -> Vec<u8> {
        serde_jcs::to_vec(&json!({"kind": self.kind, "data": self.data}))
            .expect("entry body always serializes")
    }

    pub fn leaf_hash(&self) -> LogHash {
        leaf_hash(&self.leaf_bytes())
    }
}

pub fn leaf_hash(leaf: &[u8]) -> LogHash {
    LogHash(
        Sha256::new()
            .chain_update([0x00])
            .chain_update(leaf)
            .finalize()
            .into(),
    )
}

fn node_hash(left: &LogHash, right: &LogHash) -> LogHash {
    LogHash(
        Sha256::new()
            .chain_update([0x01])
            .chain_update(left.0)
            .chain_update(right.0)
            .finalize()
            .into(),
    )
}

/// The largest power of two strictly less than `n`, for `n >= 2`.
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// MTH(D[n]), RFC 9162 section 2.1.1.
pub fn root(leaves: &[LogHash]) -> LogHash {
    match leaves.len() {
        0 => LogHash(Sha256::digest([]).into()),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

fn broken(msg: impl Into<String>) -> Error {
    Error::Log(msg.into())
}

/// PATH(m, D[n]), RFC 9162 section 2.1.3.1.
pub fn inclusion_proof(leaves: &[LogHash], m: u64) -> Result<Vec<LogHash>, Error> {
    fn path(m: usize, d: &[LogHash]) -> Vec<LogHash> {
        if d.len() <= 1 {
            return vec![];
        }
        let k = split(d.len());
        let (mut p, sibling) = if m < k {
            (path(m, &d[..k]), root(&d[k..]))
        } else {
            (path(m - k, &d[k..]), root(&d[..k]))
        };
        p.push(sibling);
        p
    }
    match usize::try_from(m) {
        Ok(m) if m < leaves.len() => Ok(path(m, leaves)),
        _ => Err(broken(format!(
            "index {m} is outside a tree of size {}",
            leaves.len()
        ))),
    }
}

/// PROOF(m, D[n]) with n = `leaves.len()`, RFC 9162 section 2.1.4.1. Empty when m = n.
pub fn consistency_proof(leaves: &[LogHash], m: u64) -> Result<Vec<LogHash>, Error> {
    fn subproof(m: usize, d: &[LogHash], complete: bool) -> Vec<LogHash> {
        if m == d.len() {
            return if complete { vec![] } else { vec![root(d)] };
        }
        let k = split(d.len());
        let (mut p, sibling) = if m <= k {
            (subproof(m, &d[..k], complete), root(&d[k..]))
        } else {
            (subproof(m - k, &d[k..], false), root(&d[..k]))
        };
        p.push(sibling);
        p
    }
    match usize::try_from(m) {
        Ok(m) if 0 < m && m <= leaves.len() => Ok(subproof(m, leaves, true)),
        _ => Err(broken(format!(
            "no consistency proof from size {m} to size {}",
            leaves.len()
        ))),
    }
}

fn lsb(x: u64) -> bool {
    x & 1 == 1
}

/// RFC 9162 section 2.1.3.2.
pub fn verify_inclusion(
    leaf: &LogHash,
    index: u64,
    size: u64,
    proof: &[LogHash],
    root: &LogHash,
) -> Result<(), Error> {
    if index >= size {
        return Err(broken(format!(
            "index {index} is outside a tree of size {size}"
        )));
    }
    let (mut f, mut s, mut r) = (index, size - 1, *leaf);
    for p in proof {
        if s == 0 {
            return Err(broken("inclusion proof is too long"));
        }
        if lsb(f) || f == s {
            r = node_hash(p, &r);
            while !lsb(f) && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    if s == 0 && r == *root {
        Ok(())
    } else {
        Err(broken(format!(
            "entry {index} is not in the tree of size {size} with root {root}"
        )))
    }
}

/// RFC 9162 section 2.1.4.2. Equal sizes need an empty proof and equal roots.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &LogHash,
    new_root: &LogHash,
    proof: &[LogHash],
) -> Result<(), Error> {
    let fail = || {
        Err(broken(format!(
            "tree of size {new_size} with root {new_root} does not extend the tree of size {old_size} with root {old_root}"
        )))
    };
    if old_size == 0 || old_size > new_size {
        return fail();
    }
    if old_size == new_size {
        return if proof.is_empty() && old_root == new_root {
            Ok(())
        } else {
            fail()
        };
    }
    if proof.is_empty() {
        return fail();
    }
    let mut path = proof.to_vec();
    if old_size.is_power_of_two() {
        path.insert(0, *old_root);
    }
    let (mut f, mut s) = (old_size - 1, new_size - 1);
    while lsb(f) {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if s == 0 {
            return fail();
        }
        if lsb(f) || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while !lsb(f) && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    if fr == *old_root && sr == *new_root && s == 0 {
        Ok(())
    } else {
        fail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> LogHash {
        LogHash::try_from(s.to_string()).unwrap()
    }

    /// Leaf inputs and roots from transparency-dev/merkle `testonly/constants.go`
    /// (the RFC 6962 reference test data, unchanged by RFC 9162).
    fn reference_leaves() -> Vec<LogHash> {
        [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ]
        .iter()
        .map(|x| leaf_hash(&hex::decode(x).unwrap()))
        .collect()
    }

    const REFERENCE_ROOTS: [&str; 9] = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    #[test]
    fn roots_match_reference_vectors() {
        let leaves = reference_leaves();
        for (n, want) in REFERENCE_ROOTS.iter().enumerate() {
            assert_eq!(root(&leaves[..n]), h(want), "size {n}");
        }
    }

    /// Vectors from transparency-dev/merkle `cmd/proofgen/main.go`. That file numbers leaves from 1;
    /// here they are converted to 0-based indexes.
    #[test]
    fn inclusion_proofs_match_reference_vectors() {
        let leaves = reference_leaves();
        let vectors: [(u64, usize, &[&str]); 5] = [
            (0, 1, &[]),
            (
                0,
                8,
                &[
                    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
                ],
            ),
            (
                5,
                8,
                &[
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
            (
                2,
                3,
                &["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
            ),
            (
                1,
                5,
                &[
                    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                ],
            ),
        ];
        for (index, size, want) in vectors {
            let want: Vec<LogHash> = want.iter().map(|x| h(x)).collect();
            assert_eq!(inclusion_proof(&leaves[..size], index).unwrap(), want);
            let r = h(REFERENCE_ROOTS[size]);
            verify_inclusion(&leaves[index as usize], index, size as u64, &want, &r).unwrap();
        }
    }

    #[test]
    fn consistency_proofs_match_reference_vectors() {
        let leaves = reference_leaves();
        let vectors: [(u64, usize, &[&str]); 5] = [
            (1, 1, &[]),
            (
                1,
                8,
                &[
                    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
                ],
            ),
            (
                6,
                8,
                &[
                    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
            (
                2,
                5,
                &[
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                ],
            ),
            (
                6,
                7,
                &[
                    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                    "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
        ];
        for (m, n, want) in vectors {
            let want: Vec<LogHash> = want.iter().map(|x| h(x)).collect();
            assert_eq!(consistency_proof(&leaves[..n], m).unwrap(), want);
            let (r1, r2) = (h(REFERENCE_ROOTS[m as usize]), h(REFERENCE_ROOTS[n]));
            verify_consistency(m, n as u64, &r1, &r2, &want).unwrap();
        }
    }

    fn flip(x: &LogHash, bit: usize) -> LogHash {
        let mut y = *x;
        y.0[bit / 8] ^= 1 << (bit % 8);
        y
    }

    fn tree(n: usize) -> Vec<LogHash> {
        (0..n)
            .map(|i| leaf_hash(format!("leaf {i}").as_bytes()))
            .collect()
    }

    /// Every bit of a hash for small trees; one bit per hash, varied by position, for larger ones.
    fn bits(n: usize, salt: usize) -> Vec<usize> {
        if n <= 9 {
            (0..256).collect()
        } else {
            vec![(salt * 37 + n * 11) % 256]
        }
    }

    #[test]
    fn every_inclusion_proof_verifies_and_any_flipped_bit_fails() {
        let leaves = tree(64);
        for n in 1..=64usize {
            let d = &leaves[..n];
            let r = root(d);
            let size = n as u64;
            for m in 0..n {
                let i = m as u64;
                let proof = inclusion_proof(d, i).unwrap();
                verify_inclusion(&d[m], i, size, &proof, &r).unwrap();
                for bit in bits(n, m) {
                    assert!(verify_inclusion(&flip(&d[m], bit), i, size, &proof, &r).is_err());
                    assert!(verify_inclusion(&d[m], i, size, &proof, &flip(&r, bit)).is_err());
                    for j in 0..proof.len() {
                        let mut bad = proof.clone();
                        bad[j] = flip(&bad[j], bit);
                        assert!(verify_inclusion(&d[m], i, size, &bad, &r).is_err());
                    }
                }
                let mut longer = proof.clone();
                longer.push(r);
                assert!(verify_inclusion(&d[m], i, size, &longer, &r).is_err());
                if !proof.is_empty() {
                    assert!(
                        verify_inclusion(&d[m], i, size, &proof[..proof.len() - 1], &r).is_err()
                    );
                }
                for other in (0..n as u64).filter(|&o| o != i) {
                    assert!(verify_inclusion(&d[m], other, size, &proof, &r).is_err());
                }
                assert!(verify_inclusion(&d[m], size, size, &proof, &r).is_err());
            }
            assert!(inclusion_proof(d, size).is_err());
        }
    }

    #[test]
    fn every_consistency_proof_verifies_and_any_flipped_bit_fails() {
        let leaves = tree(64);
        let roots: Vec<LogHash> = (0..=64).map(|n| root(&leaves[..n])).collect();
        for n in 1..=64usize {
            for m in 1..=n {
                let (old, new) = (m as u64, n as u64);
                let proof = consistency_proof(&leaves[..n], old).unwrap();
                verify_consistency(old, new, &roots[m], &roots[n], &proof).unwrap();
                for bit in bits(n, m) {
                    let r1 = flip(&roots[m], bit);
                    let r2 = flip(&roots[n], bit);
                    assert!(verify_consistency(old, new, &r1, &roots[n], &proof).is_err());
                    assert!(verify_consistency(old, new, &roots[m], &r2, &proof).is_err());
                    for j in 0..proof.len() {
                        let mut bad = proof.clone();
                        bad[j] = flip(&bad[j], bit);
                        assert!(verify_consistency(old, new, &roots[m], &roots[n], &bad).is_err());
                    }
                }
                let mut longer = proof.clone();
                longer.push(roots[n]);
                assert!(verify_consistency(old, new, &roots[m], &roots[n], &longer).is_err());
                if !proof.is_empty() {
                    let shorter = &proof[..proof.len() - 1];
                    assert!(verify_consistency(old, new, &roots[m], &roots[n], shorter).is_err());
                }
                if m < n {
                    assert!(verify_consistency(new, old, &roots[n], &roots[m], &proof).is_err());
                }
            }
            assert!(consistency_proof(&leaves[..n], 0).is_err());
            assert!(consistency_proof(&leaves[..n], n as u64 + 1).is_err());
            assert!(verify_consistency(0, n as u64, &roots[0], &roots[n], &[]).is_err());
        }
    }

    #[test]
    fn a_rewritten_entry_breaks_consistency_with_the_old_root() {
        let honest = tree(7);
        let mut forged = tree(9);
        forged[2] = leaf_hash(b"forged");
        let proof = consistency_proof(&forged, 7).unwrap();
        assert!(verify_consistency(7, 9, &root(&honest), &root(&forged), &proof).is_err());
    }

    #[test]
    fn leaf_is_jcs_of_kind_and_data_without_index() {
        let e = Entry {
            index: 4,
            kind: EntryKind::ManifestPublished,
            data: json!({"manifest": "m"}),
        };
        assert_eq!(
            e.leaf_bytes(),
            br#"{"data":{"manifest":"m"},"kind":"manifest_published"}"#
        );
        let mut want = Sha256::new();
        want.update([0u8]);
        want.update(e.leaf_bytes());
        assert_eq!(e.leaf_hash().0, <[u8; 32]>::from(want.finalize()));
        let moved = Entry {
            index: 9,
            ..e.clone()
        };
        assert_eq!(moved.leaf_hash(), e.leaf_hash());
    }
}
