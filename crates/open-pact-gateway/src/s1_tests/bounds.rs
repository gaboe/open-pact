//! S1: the work a reader does after its last read stays inside the deadline plus one candidate.

use open_pact_core::{Entry, Span, Witness, root};

use super::*;

/// The stated cost of one candidate at 1,000,000 leaves (plan, Request path), in milliseconds.
const ONE_CANDIDATE_MS: u64 = 100;

/// One uncached candidate in memory: the O(size) root, the 80 stored lines of 40 witnesses, the
/// log signature and the response text. Run it with
/// `cargo test --release -p open-pact-gateway one_candidate_cost -- --ignored --nocapture`.
#[test]
#[ignore = "benchmark; needs no database"]
fn one_candidate_cost() {
    const LEAVES: u64 = 1_000_000;
    const W: usize = 40;
    let leaves: Vec<LogHash> = (0..LEAVES)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            LogHash(bytes)
        })
        .collect();
    let signers: Vec<ed25519_dalek::SigningKey> = (0..W)
        .map(|i| ed25519_dalek::SigningKey::from_bytes(&[u8::try_from(i + 1).unwrap(); 32]))
        .collect();
    let keys: Vec<WitnessKey> = signers
        .iter()
        .enumerate()
        .map(|(i, s)| WitnessKey::new(&format!("witness.example.org/w{i}"), s.verifying_key()))
        .collect();
    let policy = LogPolicy {
        allow_split_views: false,
        witnesses: keys
            .iter()
            .map(|key| Witness {
                name: key.name().to_string(),
                key: key.clone(),
            })
            .collect(),
        witness_quorum: 21,
        checkpoint_max_age: Span::try_from("1h".to_string()).unwrap(),
    };
    policy.validate().unwrap();
    let log_signer = p256_key();
    let log = LogKey::new("log.example.org/test", &PublicKey::from(&log_signer));
    let size = usize::try_from(LEAVES - 100).unwrap();
    let mut totals = vec![];
    let mut roots = vec![];
    for _ in 0..5 {
        let hooks = hooks::Hooks::default();
        let started = Instant::now();
        let hash = root(&leaves[..size]);
        let root_time = started.elapsed();
        let cp = Checkpoint {
            origin: log.origin().to_string(),
            size: size as u64,
            root: hash,
        };
        let now = now_secs();
        // The 80 rows the filtered SQL returns: a full-key and a bare-name line per witness.
        let lines: Vec<NoteSignature> = keys
            .iter()
            .zip(&signers)
            .flat_map(|(key, signer)| {
                [
                    key.cosign(signer, &cp, now),
                    key.cosign(signer, &cp, now - 5),
                ]
            })
            .collect();
        let rest = Instant::now();
        let note = log.sign(&log_signer, &cp);
        let (note, count, kept) =
            served::assemble(&log, Some(&policy), &cp, note, &lines, now, &hooks);
        assert_eq!(count, W);
        assert!(served::usable(
            &log,
            Some(&policy),
            &note,
            &kept,
            now,
            &hooks
        ));
        let text = note.to_string();
        assert!(text.lines().count() > W);
        let rest = rest.elapsed();
        assert_eq!(
            hooks.count("verify_ed25519"),
            80,
            "every line is checked once"
        );
        assert_eq!(hooks.count("verify_p256"), 1);
        eprintln!("one candidate: root {root_time:?}, rest {rest:?}");
        totals.push(root_time + rest);
        roots.push(root_time);
    }
    let max = totals.iter().max().unwrap();
    eprintln!(
        "one candidate, 5 runs: min {:?}, max {max:?}; root max {:?}",
        totals.iter().min().unwrap(),
        roots.iter().max().unwrap()
    );
    let _ = Entry::leaf_hash;
    assert!(
        *max <= Duration::from_millis(ONE_CANDIDATE_MS),
        "one candidate took {max:?}, the stated bound is {ONE_CANDIDATE_MS} ms"
    );
}

/// Where a case's rows lie, relative to the size S the reader starts at and T = S + 5,000.
#[derive(Clone, Copy)]
enum At {
    Start(u64),
    Top(u64),
}

struct Seeded {
    at: At,
    /// The witnesses whose lines are valid at that size.
    valid: Vec<usize>,
}

const GROWTH: u64 = 5_000;

impl Fixture {
    /// Valid rows (a full-key and a bare-name line per witness) and 25 rejected rows at `size`.
    fn rows_at(
        &self,
        size: u64,
        root: LogHash,
        valid: &[usize],
    ) -> Vec<(u64, LogHash, String, String)> {
        let cp = |root: LogHash| Checkpoint {
            origin: self.log.origin().to_string(),
            size,
            root,
        };
        let now = now_secs();
        let mut rows = vec![];
        for &i in valid {
            let key = &self.policy.witnesses[i].key;
            rows.push((
                size,
                root,
                key.vkey(),
                self.witnesses[i].cosign(&cp(root), now).to_string(),
            ));
            rows.push((
                size,
                root,
                key.name().to_string(),
                self.witnesses[i].cosign(&cp(root), now - 5).to_string(),
            ));
        }
        // Rejected: three rows of other roots per policy witness, ten rows of keys outside the policy.
        for (i, witness) in self.witnesses.iter().enumerate() {
            for k in 1..=3u8 {
                let other = LogHash([k; 32]);
                rows.push((
                    size,
                    other,
                    self.policy.witnesses[i].key.vkey(),
                    witness.cosign(&cp(other), now).to_string(),
                ));
            }
        }
        for j in 0..10u8 {
            let signer = ed25519_dalek::SigningKey::from_bytes(&[100 + j; 32]);
            let key = WitnessKey::new(&format!("other.example.org/x{j}"), signer.verifying_key());
            rows.push((
                size,
                root,
                key.vkey(),
                key.cosign(&signer, &cp(root), now).to_string(),
            ));
        }
        rows
    }
}

struct Run {
    reply: Got,
    /// Counter differences over the request.
    uncached_roots: usize,
    candidates: usize,
    candidate_rows: usize,
    ed25519: usize,
    p256: usize,
    signatures: usize,
    /// The counters read 30 ms after the deadline, and at the answer.
    after_deadline: (usize, usize, usize),
    at_answer: (usize, usize, usize),
    reads: usize,
    /// Row groups the walk of the candidates looked at.
    group_scans: usize,
    size: u64,
}

/// One reader that starts at the cached size S with no row, waits, and sees the log at S + 5,000
/// with the case's rows.
async fn case(f: &Fixture, query: String, seeded: &[Seeded], hold: bool) -> Run {
    let hooks = f.app.owners.hooks();
    let wait = f.app.wait;
    let base = f.app.tree().await.unwrap();
    let (s, t) = (base.size(), base.size() + GROWTH);
    let mut leaves = base.view.cache.leaves().to_vec();
    for g in s..t {
        leaves.push(
            Entry {
                index: g,
                kind: EntryKind::RetentionPurge,
                data: json!({ "fixture": i64::try_from(g).unwrap() }),
            }
            .leaf_hash(),
        );
    }
    let mut rows = vec![];
    for case in seeded {
        let size = match case.at {
            At::Start(k) => s + k,
            At::Top(k) => t - k,
        };
        rows.extend(f.rows_at(
            size,
            root(&leaves[..usize::try_from(size).unwrap()]),
            &case.valid,
        ));
    }
    let early: i64 = sqlx::query_scalar("SELECT count(*) FROM log_cosignatures WHERE size >= $1")
        .bind(i64::try_from(s).unwrap())
        .fetch_one(&f.direct)
        .await
        .unwrap();
    assert_eq!(early, 0, "no row at any size the case requests");
    if !rows.is_empty() {
        f.seed(rows).await;
    }
    let before = |name| hooks.count(name);
    let counters = [
        before("uncached_root"),
        before("candidate_started"),
        before("candidate_rows"),
        before("verify_ed25519"),
        before("verify_p256"),
        before("served_signatures"),
        before("read_calls"),
        before("group_scan"),
    ];
    let waiting = hooks.count("reader_waiting");
    let begin = Instant::now();
    let (router, query_text) = (f.router.clone(), query);
    let task = tokio::spawn(async move { Fixture::get_with(router, Some(query_text)).await });
    let watch = {
        let hooks = hooks.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                begin + wait + Duration::from_millis(30),
            ))
            .await;
            (
                hooks.count("read_calls"),
                hooks.count("served_tree_reads"),
                hooks.count("kick_calls"),
            )
        })
    };
    until("the reader waits", Duration::from_secs(10), || {
        hooks.count("reader_waiting") > waiting
    })
    .await;
    f.append_bulk(i64::try_from(GROWTH).unwrap()).await;
    if hold {
        hooks.arm_past_deadline("candidate_started", Duration::from_millis(1));
    }
    f.app.owners.notify_changed();
    let reply = task.await.unwrap();
    let after_deadline = watch.await.unwrap();
    let at_answer = (
        hooks.count("read_calls"),
        hooks.count("served_tree_reads"),
        hooks.count("kick_calls"),
    );
    let delta = |name, was: usize| hooks.count(name) - was;
    Run {
        reply,
        uncached_roots: delta("uncached_root", counters[0]),
        candidates: delta("candidate_started", counters[1]),
        candidate_rows: delta("candidate_rows", counters[2]),
        ed25519: delta("verify_ed25519", counters[3]),
        p256: delta("verify_p256", counters[4]),
        signatures: delta("served_signatures", counters[5]),
        reads: delta("read_calls", counters[6]),
        group_scans: delta("group_scan", counters[7]),
        after_deadline,
        at_answer,
        size: t,
    }
}

impl Run {
    fn within(&self, wait: Duration) {
        let bound = wait + Duration::from_millis(ONE_CANDIDATE_MS + 50);
        assert!(
            self.reply.elapsed <= bound,
            "answered after {:?}, bound {bound:?}",
            self.reply.elapsed
        );
        assert_eq!(
            self.after_deadline, self.at_answer,
            "work started after the deadline"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn served_bounds_the_work_after_the_last_read() {
    const F: i64 = 995_000;
    let mut options = Options::new(5, 3);
    options.wait_ms = 2000;
    options.pool = 64;
    options.read_pool = 64;
    let f = Fixture::build(options).await;
    let hooks = f.app.owners.hooks();
    // No owner reads, sends or stores during the fixture, so none adds a candidate.
    hooks.set_hold_retries(true);
    let start = i64::try_from(f.size().await).unwrap();
    f.append_bulk(F - start).await;
    let wait = f.app.wait;
    // Case 1: rows at a cached size (T - 10).
    let one = case(
        &f,
        f.query.clone(),
        &[Seeded {
            at: At::Top(10),
            valid: vec![0, 1, 2, 3, 4],
        }],
        true,
    )
    .await;
    assert_eq!(one.reply.status, StatusCode::OK, "{}", one.reply.body);
    let cp = f.verifies(&one.reply.body, &f.policy);
    assert_eq!(cp.size, one.size - 10);
    assert_eq!(one.uncached_roots, 0);
    assert!(one.candidates >= 1, "the reader reached the candidate");
    assert!(
        one.candidate_rows <= 10,
        "{} rows decoded",
        one.candidate_rows
    );
    assert_eq!((one.ed25519, one.p256), (10, 1));
    assert_eq!(one.signatures, 1, "one log signature for one candidate");
    one.within(wait);
    // The leaves the test computed are the log's: the cached root at T matches.
    let tree = f.app.tree().await.unwrap();
    assert_eq!(tree.size(), one.size);
    // Case 2: rows at one uncached size (S + 100): one O(size) root.
    let two = case(
        &f,
        f.query.clone(),
        &[Seeded {
            at: At::Start(100),
            valid: vec![0, 1, 2, 3, 4],
        }],
        true,
    )
    .await;
    assert_eq!(two.reply.status, StatusCode::OK, "{}", two.reply.body);
    let cp = f.verifies(&two.reply.body, &f.policy);
    assert_eq!(cp.size, two.size - GROWTH + 100);
    assert_eq!(two.uncached_roots, 1);
    assert!(two.candidate_rows <= 10 && two.ed25519 <= 10 && two.p256 <= 1);
    two.within(wait);
    // Case 3: two uncached sizes; the larger has only two witnesses (below quorum 3).
    let three = case(
        &f,
        f.query.clone(),
        &[
            Seeded {
                at: At::Start(200),
                valid: vec![0, 1],
            },
            Seeded {
                at: At::Start(100),
                valid: vec![0, 1, 2, 3, 4],
            },
        ],
        true,
    )
    .await;
    expect_unavailable(
        &three.reply,
        wait + Duration::from_millis(ONE_CANDIDATE_MS + 50),
    );
    assert_eq!(three.uncached_roots, 1, "the smaller size is never read");
    assert!(three.candidates >= 1 && three.candidate_rows <= 10);
    assert_eq!(
        three.after_deadline, three.at_answer,
        "work started after the deadline"
    );
    // Case 3b: two cached sizes; the larger is below quorum and ends after the deadline. The walk
    // must not look at the next group.
    let three_b = case(
        &f,
        f.query.clone(),
        &[
            Seeded {
                at: At::Top(10),
                valid: vec![0, 1],
            },
            Seeded {
                at: At::Top(20),
                valid: vec![0, 1, 2, 3, 4],
            },
        ],
        true,
    )
    .await;
    expect_unavailable(
        &three_b.reply,
        wait + Duration::from_millis(ONE_CANDIDATE_MS + 50),
    );
    assert_eq!(three_b.candidates, 1, "one candidate started");
    assert_eq!(
        three_b.group_scans, 1,
        "the walk looked at the next group after the deadline"
    );
    // Case 4: no rows.
    let four = case(&f, f.query.clone(), &[], false).await;
    expect_unavailable(
        &four.reply,
        wait + Duration::from_millis(ONE_CANDIDATE_MS + 50),
    );
    assert_eq!(
        four.after_deadline, four.at_answer,
        "work started after the deadline"
    );
    assert_eq!(
        four.reads, 3,
        "the first read, the reread and the final read"
    );
    // Case 5: a policy without witnesses is signed at once.
    let free = LogPolicy {
        witnesses: vec![],
        witness_quorum: 0,
        allow_split_views: true,
        ..f.policy.clone()
    };
    let before = hooks.count("served_signatures");
    let five = f.get(Some(&encode(&free))).await;
    assert_eq!(five.status, StatusCode::OK, "{}", five.body);
    assert_eq!(hooks.count("served_signatures") - before, 1);
    // Case 5b: the tree result is held past the deadline; the answer is 503 with no signature.
    let hold = hooks.arm("served_tree_returned");
    let before = hooks.count("served_signatures");
    let begin = Instant::now();
    let (router, query) = (f.router.clone(), encode(&free));
    let late = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    hold.reached().await;
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        begin + wait + Duration::from_millis(1),
    ))
    .await;
    hold.release();
    let late = late.await.unwrap();
    expect_unavailable(&late, wait + Duration::from_millis(ONE_CANDIDATE_MS + 50));
    assert_eq!(
        hooks.count("served_signatures"),
        before,
        "no signature after the deadline"
    );
    // Case 6: the first read is held after its last check until the deadline has passed; no row
    // step starts.
    let steps = hooks.count("row_step_start");
    hooks.arm_past_deadline("row_step_prepare", Duration::from_millis(1));
    let six = f.get(Some(&f.query)).await;
    expect_unavailable(&six, wait + Duration::from_millis(ONE_CANDIDATE_MS + 50));
    // A step that was spawned would reach its first statement within moments.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hooks.count("row_step_start"),
        steps,
        "a row step started after the deadline"
    );
    f.assert_no_fork_line().await;
}
