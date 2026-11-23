//! S1: what the owners do when an answer is unknown, a manifest reloads, a key changes its meaning,
//! a candidate is short or an owner has nothing to do. Each test runs a gateway against fake
//! witnesses; the ones with a claim use the real client.

use std::sync::atomic::Ordering;

use open_pact_core::WitnessKey;

use super::real::spawn_claim;
use super::*;

/// A claim captured at N, a log at N+1, and a reader whose push of N+1 is in flight at the witness
/// when the claim is released. `behave` sets what the witness does with that first push.
async fn unknown_case(case: u8) {
    let f = Fixture::real().await;
    let live = f.live().await;
    let devices = f.enrolled(&live, 1).await;
    let hooks = f.app.owners.hooks();
    let committed = hooks.arm("claim_committed");
    let claim = spawn_claim(&devices[0]);
    committed.reached().await;
    f.append(1).await;
    let n = f.size().await;
    let read = hooks.arm("checkpoint_tree_read");
    committed.release();
    read.reached().await;
    f.append(1).await;
    let arrivals = f.witnesses[0].arrivals();
    match case {
        1 => {
            // The witness stores N+1 and drops its answer, after the claim's Push is queued.
            f.witnesses[0].set(Behaviour::StoreThenFail);
            f.witnesses[0].gate();
        }
        2 => f.witnesses[0].set(Behaviour::DelayAnswer(Duration::from_millis(800), 500)),
        _ => {
            f.witnesses[0].detach_decisions();
            f.witnesses[0].set(Behaviour::Delay(Duration::from_secs(7)));
        }
    }
    let (router, query) = (f.router.clone(), f.query.clone());
    let reader = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    until("the reader's push arrived", Duration::from_secs(5), || {
        f.witnesses[0].arrivals() == arrivals + 1
    })
    .await;
    f.witnesses[0].set(Behaviour::Healthy);
    let fanouts = f.app.owners.fanouts.load(Ordering::SeqCst);
    // Released while that attempt is in flight: the claim's Push of N queues behind it.
    read.release();
    until("the claim's Push is queued", Duration::from_secs(5), || {
        f.app.owners.fanouts.load(Ordering::SeqCst) == fanouts + 1
    })
    .await;
    if case == 1 {
        f.witnesses[0].open_gate();
    }
    claim.await.unwrap();
    let reader = reader.await.unwrap();
    // The reader may see the claim's later store, or time out first.
    assert!(
        matches!(
            reader.status,
            StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
        ),
        "{}",
        reader.body
    );
    let size = n + 1;
    if case == 3 {
        let started = Instant::now();
        while f.witnesses[0]
            .received()
            .iter()
            .filter(|r| r.size == size)
            .count()
            < 2
        {
            let record: Vec<(u64, u64, u16)> = f.witnesses[0]
                .received()
                .iter()
                .map(|r| (r.size, r.old_size, r.status))
                .collect();
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "no late decision at {size}: {record:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    f.sizes_are_non_decreasing();
    assert!(
        f.witnesses[0].sizes().iter().all(|s| *s != n),
        "the claim's size was never sent: {:?}",
        f.witnesses[0].sizes()
    );
    let statuses: Vec<u16> = f.witnesses[0]
        .received()
        .iter()
        .filter(|r| r.size == size)
        .map(|r| r.status)
        .collect();
    match case {
        1 => assert_eq!(statuses, [500, 409, 200], "{statuses:?}"),
        2 => assert_eq!(statuses, [500, 200], "{statuses:?}"),
        // The second dispatch is decided first; the timed-out one is decided late and gets a 409
        // that no waiter reads.
        _ => assert_eq!(statuses, [200, 409], "{statuses:?}"),
    }
    assert!(
        devices[0].installed(),
        "the client installs its certificate"
    );
    let note = devices[0].reply_note().unwrap();
    assert_eq!(f.verifies(&note, &f.policy).size, size);
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn an_unknown_witness_answer_is_never_a_fork() {
    for case in 1..=3 {
        unknown_case(case).await;
    }
}

/// New lists another key of the one witness; its entry is already in the log, so a reload appends
/// nothing.
async fn rotated(f: &Fixture) -> (String, LogPolicy, (ed25519_dalek::SigningKey, WitnessKey)) {
    let key = f.witnesses[0].rotated([77; 32]);
    let toml = f.manifest_of(&[&key.1], 1);
    let policy = f.policy_in(&toml);
    publish_manifest(&f.db, &Manifest::parse(toml.as_bytes()).unwrap())
        .await
        .unwrap();
    (toml, policy, key)
}

/// The reload without waiting for the owners, so a test can hold it at its pause point.
fn reload(f: &Fixture, toml: &str) -> tokio::task::JoinHandle<()> {
    let (app, db, toml) = (f.app.clone(), f.db.clone(), toml.to_string());
    tokio::spawn(async move {
        manifests::set_for_test(&db, &app.keys, &toml).await;
        reload_manifest(&app).await.unwrap();
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_request_policy_survives_a_reload() {
    let f = Fixture::real().await;
    let (toml, _, _) = rotated(&f).await;
    let gate = f.witnesses[0].gate();
    drop(gate);
    let (router, query) = (f.router.clone(), f.query.clone());
    let read = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    until("the push arrived", Duration::from_secs(5), || {
        f.witnesses[0].arrivals() == 1
    })
    .await;
    reload(&f, &toml).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    f.witnesses[0].open_gate();
    let reply = read.await.unwrap();
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    f.verifies(&reply.body, &f.policy);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_reload_resets_owner_reuse() {
    let f = Fixture::real().await;
    let (toml, new_policy, new_key) = rotated(&f).await;
    let first = f.get(Some(&f.query)).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let n = f.size().await;
    f.witnesses[0].script(vec![new_key]);
    f.enforce(&toml).await;
    assert_eq!(f.size().await, n, "the reload appended nothing");
    let second = f.get(Some(&encode(&new_policy))).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    assert_eq!(f.verifies(&second.body, &new_policy).size, n);
    assert_eq!(
        f.witnesses[0].sizes(),
        [n, n],
        "a push at N under the new key"
    );
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_reload_during_a_push_does_not_mark_the_size_done() {
    let f = Fixture::real().await;
    let hooks = f.app.owners.hooks();
    let (toml, new_policy, new_key) = rotated(&f).await;
    let first = f.get(Some(&f.query)).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let n = f.size().await;
    // A refresh push of N waits at the witness's gate.
    let gate = f.witnesses[0].gate();
    drop(gate);
    f.app.owners.refresh_all();
    until("the refresh push arrived", Duration::from_secs(5), || {
        f.witnesses[0].arrivals() == 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let published = hooks.arm("reload_published");
    let drained = hooks.count("reload_drained");
    let reload = reload(&f, &toml);
    published.reached().await;
    // The snapshot is New; only now does the witness answer the gated push, with an Old-key line.
    f.witnesses[0].open_gate();
    until("the gated push was decided", Duration::from_secs(5), || {
        f.witnesses[0].received().len() == 2
    })
    .await;
    f.witnesses[0].script(vec![new_key]);
    published.release();
    reload.await.unwrap();
    until(
        "the owner drained the reload",
        Duration::from_secs(10),
        || hooks.count("reload_drained") > drained,
    )
    .await;
    let reply = f.get(Some(&encode(&new_policy))).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(f.verifies(&reply.body, &new_policy).size, n);
    assert_eq!(f.size().await, n, "the tree stayed at N");
    assert_eq!(
        f.witnesses[0].sizes(),
        [n, n, n],
        "a second push after the reload"
    );
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_push_started_before_the_snapshot_swap_is_not_reused() {
    let f = Fixture::real().await;
    let hooks = f.app.owners.hooks();
    let (toml, new_policy, new_key) = rotated(&f).await;
    let first = f.get(Some(&f.query)).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let m = f.size().await;
    f.append(1).await;
    let n = f.size().await;
    // Owner 1 reads the tree at N on the Old snapshot, and is held before its dispatch.
    let captured = hooks.arm("owner_tree_captured");
    f.app.owners.refresh_all();
    captured.reached().await;
    let published = hooks.arm("reload_published");
    let drained = hooks.count("reload_drained");
    let reload = reload(&f, &toml);
    published.reached().await;
    captured.release();
    until("the Old push was decided", Duration::from_secs(5), || {
        f.witnesses[0].sizes() == [m, n]
    })
    .await;
    f.witnesses[0].script(vec![new_key]);
    // The Reload job is still held: the owner does not trust the first attempt.
    let reply = f.get(Some(&encode(&new_policy))).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(f.verifies(&reply.body, &new_policy).size, n);
    assert_eq!(
        hooks.count("reload_drained"),
        drained,
        "the reload is still held"
    );
    assert_eq!(f.witnesses[0].sizes(), [m, n, n]);
    published.release();
    reload.await.unwrap();
    f.assert_no_fork_line().await;
}

/// Two witnesses with one name and different keys that share a 4-byte key ID (seeds found once by a
/// search over seeds `i, 0, 0, .., 0xC0`).
fn colliding_seeds() -> Vec<[u8; 32]> {
    [9373u32, 14032]
        .iter()
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            seed[31] = 0xC0;
            seed
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_same_name_key_change_keeps_both_keys() {
    let mut options = Options::new(2, 1);
    options.seeds = Some(colliding_seeds());
    options.same_name = true;
    options.listed = Some(vec![0]);
    options.real_client = true;
    let f = Fixture::build(options).await;
    let ids: Vec<String> = f
        .witnesses
        .iter()
        .map(|w| w.inner.key.vkey().split('+').nth(1).unwrap().to_string())
        .collect();
    assert_eq!(ids[0], ids[1], "the two keys share their key ID");
    assert_ne!(
        f.witnesses[0].inner.key.vkey(),
        f.witnesses[1].inner.key.vkey()
    );
    let old = f.policy.clone();
    let toml = f.manifest_of(&[&f.witnesses[1].inner.key], 1);
    let new = f.policy_in(&toml);
    let first = f.get(Some(&f.query)).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    f.enforce(&toml).await;
    f.append(1).await;
    let under_new = f.get(Some(&encode(&new))).await;
    assert_eq!(under_new.status, StatusCode::OK, "{}", under_new.body);
    let size = f.verifies(&under_new.body, &new).size;
    let under_old = f.get(Some(&encode(&old))).await;
    assert_eq!(under_old.status, StatusCode::OK, "{}", under_old.body);
    assert_eq!(f.verifies(&under_old.body, &old).size, size);
    until("both keys have a row", Duration::from_secs(10), || {
        // Checked below with a query; this only paces the loop.
        true
    })
    .await;
    let started = Instant::now();
    loop {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT witness FROM log_cosignatures WHERE size = $1 ORDER BY witness",
        )
        .bind(i64::try_from(size).unwrap())
        .fetch_all(&f.direct)
        .await
        .unwrap();
        if rows.len() == 2 {
            assert_ne!(rows[0], rows[1]);
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "rows: {rows:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    f.assert_no_fork_line().await;
}

/// Waits until every owner is idle and has tried at least `size`.
async fn owners_tried(f: &Fixture, size: u64) {
    until(
        "every owner tried the size",
        Duration::from_secs(10),
        || {
            f.app
                .owners
                .views()
                .iter()
                .all(|v| v.idle && v.tried >= size)
        },
    )
    .await;
}

/// The three counters whose rise after the deadline would be work started too late.
fn counters(hooks: &hooks::Hooks) -> (usize, usize, usize) {
    (
        hooks.count("read_calls"),
        hooks.count("served_tree_reads"),
        hooks.count("kick_calls"),
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_failed_candidate_past_the_deadline_starts_no_read() {
    const WAIT: u64 = 2000;
    let bound = Duration::from_millis(WAIT + 100 + 100 + 50);
    for case in 1..=2 {
        let mut options = Options::new(2, 2);
        options.wait_ms = WAIT;
        let f = Fixture::build(options).await;
        let hooks = f.app.owners.hooks();
        let n = f.size().await;
        if case == 1 {
            // All views exhausted: w2 holds a size above N, so its push of N is a 409.
            f.witnesses[1].hold(Checkpoint {
                origin: f.log.origin().to_string(),
                size: n + 5,
                root: LogHash([3; 32]),
            });
        } else {
            f.witnesses[1].set(Behaviour::Answer(500));
        }
        // The first GET leaves w1's line at N (a short candidate) and w2 without one.
        let first = f.get(Some(&f.query)).await;
        assert_eq!(first.status, StatusCode::SERVICE_UNAVAILABLE);
        owners_tried(&f, n).await;
        // No ordinary retry may store a w2 line or change a view from here on.
        hooks.set_hold_retries(true);
        if case == 2 {
            until("w2 left its cooldown", Duration::from_secs(5), || {
                let views = f.app.owners.views();
                views[1].idle && !views[1].cooling() && views[1].failures >= 1
            })
            .await;
        }
        let pushes = f.witnesses[1].arrivals();
        // The held run: the candidate at N is held until 100 ms after the deadline.
        hooks.arm_relative_to_deadline("candidate_started", 100);
        let before = counters(&hooks);
        let (router, query) = (f.router.clone(), f.query.clone());
        let held = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
        if case == 2 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            f.app.owners.notify_changed();
        }
        expect_unavailable(&held.await.unwrap(), bound);
        let after = counters(&hooks);
        assert_eq!(
            (after.0 - before.0, after.1 - before.1, after.2 - before.2),
            (1, 1, 0),
            "case {case}: one read and one tree read, no kick after the deadline"
        );
        // The control run releases the hold 500 ms before the deadline.
        hooks.arm_relative_to_deadline("candidate_started", -500);
        let before = counters(&hooks);
        let (router, query) = (f.router.clone(), f.query.clone());
        let control = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
        if case == 2 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            f.app.owners.notify_changed();
        }
        let control = control.await.unwrap();
        assert_eq!(control.status, StatusCode::SERVICE_UNAVAILABLE);
        let after = counters(&hooks);
        let (reads, trees, kicks) = (after.0 - before.0, after.1 - before.1, after.2 - before.2);
        if case == 1 {
            // Exhausted exit: exactly one final read, and it does not wait for the deadline.
            assert_eq!((reads, trees, kicks), (2, 1, 1), "case 1 control");
            assert!(
                control.elapsed < Duration::from_millis(WAIT),
                "{:?}",
                control.elapsed
            );
        } else {
            // Not exhausted: the bump makes the reader reread the tree, and the wait ends at NotYet.
            assert_eq!(trees, 2, "case 2 control rereads the tree after the bump");
            assert!(reads >= 3 && kicks >= 1, "{reads} {kicks}");
        }
        assert_eq!(
            f.witnesses[1].arrivals(),
            pushes,
            "w2 got no push after the first GET"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn an_idle_owner_does_not_wake_on_an_expired_timer() {
    // Case 1: a failed push leaves an expired cooldown timer.
    let f = Fixture::new(1, 1).await;
    let hooks = f.app.owners.hooks();
    let first = f.get(Some(&f.query)).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    f.append(1).await;
    let n = f.size().await;
    f.witnesses[0].set(Behaviour::Answer(500));
    let (note, _) = f.app.checkpoint(Mode::Enroll).await.unwrap();
    assert_eq!(f.log.verify(&note).unwrap().size, n);
    owners_tried(&f, n).await;
    let (loops, arrivals) = (hooks.count("owner_loop"), f.witnesses[0].arrivals());
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        hooks.count("owner_loop") - loops <= 1,
        "the idle owner woke {} times",
        hooks.count("owner_loop") - loops
    );
    assert_eq!(f.witnesses[0].arrivals(), arrivals, "no push while idle");
    f.witnesses[0].set(Behaviour::Healthy);
    let next = f.get(Some(&f.query)).await;
    assert_eq!(next.status, StatusCode::OK, "{}", next.body);
    assert_eq!(f.verifies(&next.body, &f.policy).size, n);
    assert_eq!(
        f.witnesses[0].arrivals(),
        arrivals + 1,
        "the push went out at once"
    );
    // Case 2: a witness above this log leaves a recheck timer.
    let f = Fixture::new(1, 1).await;
    let hooks = f.app.owners.hooks();
    let l = f.size().await;
    f.witnesses[0].hold(Checkpoint {
        origin: f.log.origin().to_string(),
        size: l + 5,
        root: LogHash([3; 32]),
    });
    let one = f.get(Some(&f.query)).await;
    assert_eq!(one.status, StatusCode::SERVICE_UNAVAILABLE);
    f.append(1).await;
    let trees = hooks.count("owner_tree_captured");
    let two = f.get(Some(&f.query)).await;
    assert_eq!(two.status, StatusCode::SERVICE_UNAVAILABLE);
    until(
        "the owner read the tree once",
        Duration::from_secs(5),
        || hooks.count("owner_tree_captured") == trees + 1,
    )
    .await;
    until("the owner is idle", Duration::from_secs(5), || {
        f.app.owners.views().iter().all(|v| v.idle)
    })
    .await;
    let (loops, trees) = (
        hooks.count("owner_loop"),
        hooks.count("owner_tree_captured"),
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        hooks.count("owner_loop") - loops <= 1,
        "the idle owner woke"
    );
    assert_eq!(
        hooks.count("owner_tree_captured"),
        trees,
        "no tree read while idle"
    );
    assert_eq!(f.witnesses[0].arrivals(), 1);
}

/// The setup of `a_claim_behind_a_reader_push_advances_once` with a real client claim; `fault`
/// installs the fault after the claim's first read and its post-push read of the lines at N.
async fn failed_advance(case: u8) {
    let f = Fixture::real().await;
    let live = f.live().await;
    let devices = f.enrolled(&live, 1).await;
    let hooks = f.app.owners.hooks();
    let committed = hooks.arm("claim_committed");
    let claim = spawn_claim(&devices[0]);
    committed.reached().await;
    f.append(1).await;
    let n = f.size().await;
    let read = hooks.arm("checkpoint_tree_read");
    committed.release();
    read.reached().await;
    f.append(1).await;
    let reader = f.get(Some(&f.query)).await;
    assert_eq!(reader.status, StatusCode::OK, "{}", reader.body);
    let reads = hooks.count("stored_lines_read");
    if case == 3 {
        hooks.fail_after_reads(2);
    } else {
        hooks.fail_writes_after_reads(2);
    }
    let answered = hooks.arm("claim_checkpointed");
    read.release();
    answered.reached().await;
    // The claim's own steps failed; the client's later reads are not part of the check.
    hooks.clear_fault();
    answered.release();
    claim.await.unwrap();
    assert_eq!(
        hooks.count("stored_lines_read"),
        reads + 2,
        "the first read and the post-push read, no fallback read"
    );
    assert!(
        !devices[0].installed(),
        "the size-N note has no witness line"
    );
    let note = devices[0].reply_note().expect("the client kept the reply");
    assert_eq!(f.log.verify(&Note::parse(&note).unwrap()).unwrap().size, n);
    assert_eq!(devices[0].reply_lines(f.log.origin()), (0, true), "{note}");
    assert_eq!(
        f.witnesses[0]
            .sizes()
            .iter()
            .filter(|s| **s == n + 1)
            .count(),
        1,
        "no second send of N+1: {:?}",
        f.witnesses[0].sizes()
    );
    assert!(
        f.witnesses[0].sizes().iter().all(|s| *s != n),
        "N was never sent"
    );
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_failed_claim_advance_answers_the_short_note_with_a_real_client() {
    // Case 3: the advance's tree read fails. Case 4: the advance's write fails.
    failed_advance(3).await;
    failed_advance(4).await;
}
