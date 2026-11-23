//! S1: no reader waits on CPU or memory work that holds a thread. The holds are std blocking
//! pauses on the blocking pool (`Hooks::block`), each bounded by 10 s, so a regression fails an
//! assertion and does not hang the run.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{Receiver, channel};

use super::real::Live;
use super::*;

/// One answer of the raw client below.
struct Raw {
    status: u16,
    retry_after: Option<String>,
    elapsed: Duration,
    body: String,
}

/// A GET sent from its own OS thread over a plain socket, so a stopped async worker cannot stop
/// the client. The answer comes on a channel; the thread gives up after 5 s.
fn raw_get(addr: SocketAddr, query: String) -> Receiver<Option<Raw>> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        let answer = (|| {
            let mut stream = TcpStream::connect(addr).ok()?;
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
            write!(
                stream,
                "GET /v1/log/checkpoint?{query} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            .ok()?;
            let mut text = String::new();
            stream.read_to_string(&mut text).ok()?;
            let status = text.split_whitespace().nth(1)?.parse().ok()?;
            let retry_after = text
                .lines()
                .find_map(|l| l.strip_prefix("retry-after: "))
                .map(|v| v.trim().to_string());
            let body = text
                .split_once("\r\n\r\n")
                .map_or(String::new(), |(_, b)| b.to_string());
            Some(Raw {
                status,
                retry_after,
                elapsed: started.elapsed(),
                body,
            })
        })();
        let _ = tx.send(answer);
    });
    rx
}

fn addr_of(live: &Live) -> SocketAddr {
    live.url.trim_start_matches("http://").parse().unwrap()
}

/// Waits for a raw answer without blocking the async worker.
async fn answer(rx: &Receiver<Option<Raw>>) -> Raw {
    let started = Instant::now();
    loop {
        if let Ok(got) = rx.try_recv() {
            return got.expect("the raw client got no answer within 5 s");
        }
        assert!(started.elapsed() < Duration::from_secs(8), "no answer");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

impl Fixture {
    /// `count` entries in one statement, as a log that already holds them.
    pub(super) async fn append_bulk(&self, count: i64) {
        let start = i64::try_from(self.size().await).unwrap();
        sqlx::query(
            "INSERT INTO log_entries (idx, kind, data) \
             SELECT g, $3, jsonb_build_object('fixture', g) FROM generate_series($1::bigint, $2::bigint) g",
        )
        .bind(start)
        .bind(start + count - 1)
        .bind(EntryKind::RetentionPurge.as_str())
        .execute(&self.db)
        .await
        .unwrap();
    }

    pub(super) async fn blocking_fixture() -> Fixture {
        let mut options = Options::new(1, 1);
        options.wait_ms = 1000;
        options.pool = 64;
        Fixture::build(options).await
    }
}

const BOUND: Duration = Duration::from_millis(1000 + 500 + 50);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_reader_does_not_wait_on_a_cache_catch_up() {
    let f = Fixture::blocking_fixture().await;
    let warm = f.get(Some(&f.query)).await;
    assert_eq!(warm.status, StatusCode::OK, "{}", warm.body);
    f.append(1).await;
    // The decision for the new size is gated: reader R has no row and no candidate.
    f.witnesses[0].gate();
    let hooks = f.app.owners.hooks();
    let (router, query) = (f.router.clone(), f.query.clone());
    let reader = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    until("R waits", Duration::from_secs(5), || {
        hooks.count("reader_waiting") >= 1
    })
    .await;
    f.append_bulk(5000).await;
    let hold = hooks.arm_block("cache_catch_up");
    let (router, query) = (f.router.clone(), f.query.clone());
    let catcher = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    hold.reached().await;
    // Case 1: R stays in its wait and runs its final read during the hold.
    let reply = reader.await.unwrap();
    expect_unavailable(&reply, BOUND);
    assert!(hold.holding(), "R answered only after the hold");
    // Case 2: 32 more readers; each waits for the held catch-up and answers 503 inside the bound.
    let readers = futures_util::future::join_all(
        (0..32).map(|_| Fixture::get_with(f.router.clone(), Some(f.query.clone()))),
    )
    .await;
    for reply in &readers {
        expect_unavailable(reply, BOUND);
    }
    assert!(hold.holding(), "the readers answered only after the hold");
    let catcher_reply = catcher.await.unwrap();
    expect_unavailable(&catcher_reply, BOUND);
    assert_eq!(hold.hits(), 1, "one catch-up held");
    hold.release();
    f.witnesses[0].open_gate();
    let size = f.size().await;
    let started = Instant::now();
    loop {
        let reply = f.get(Some(&f.query)).await;
        if reply.status == StatusCode::OK {
            assert_eq!(f.verifies(&reply.body, &f.policy).size, size);
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "no verified note after the release"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_catch_up_does_not_stop_the_one_async_worker() {
    let f = Fixture::blocking_fixture().await;
    let live = f.live().await;
    let warm = f.get(Some(&f.query)).await;
    assert_eq!(warm.status, StatusCode::OK, "{}", warm.body);
    f.append(1).await;
    f.witnesses[0].gate();
    let hooks = f.app.owners.hooks();
    let first = raw_get(addr_of(&live), f.query.clone());
    until("R waits", Duration::from_secs(5), || {
        hooks.count("reader_waiting") >= 1
    })
    .await;
    // R captured its tree and waits; now the catch-up of 5000 entries holds its thread.
    f.append_bulk(5000).await;
    let hold = hooks.arm_block("cache_catch_up");
    let second = raw_get(addr_of(&live), f.query.clone());
    hold.reached().await;
    let got = answer(&first).await;
    // The hold is released only below, so a set flag means R answered during it.
    assert_eq!((got.status, got.retry_after.as_deref()), (503, Some("5")));
    assert!(got.elapsed <= BOUND, "R answered after {:?}", got.elapsed);
    assert!(hold.holding(), "R answered only after the hold");
    hold.release();
    let late = answer(&second).await;
    assert_eq!(late.status, 503);
    f.witnesses[0].open_gate();
    let started = Instant::now();
    loop {
        let reply = f.get(Some(&f.query)).await;
        if reply.status == StatusCode::OK {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "no verified note after the release"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_witness_proof_does_not_hold_a_reader() {
    let f = Fixture::blocking_fixture().await;
    let live = f.live().await;
    let warm = f.get(Some(&f.query)).await;
    assert_eq!(warm.status, StatusCode::OK, "{}", warm.body);
    f.append(1).await;
    let hooks = f.app.owners.hooks();
    let hold = hooks.arm_block("push_proof");
    // R has no row at the new size and no candidate; its kick makes the owner build a proof.
    let reader = raw_get(addr_of(&live), f.query.clone());
    hold.reached().await;
    let got = answer(&reader).await;
    assert_eq!((got.status, got.retry_after.as_deref()), (503, Some("5")));
    assert!(got.elapsed <= BOUND, "R answered after {:?}", got.elapsed);
    assert!(hold.holding(), "R answered only after the hold");
    hold.release();
    let size = f.size().await;
    let started = Instant::now();
    loop {
        let reply = f.get(Some(&f.query)).await;
        if reply.status == StatusCode::OK {
            assert_eq!(f.verifies(&reply.body, &f.policy).size, size);
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "no verified note after the release"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    f.assert_no_fork_line().await;
}

const DROP_WAIT_MS: u64 = 2000;

async fn drop_fixture(wait_ms: u64) -> Fixture {
    let mut options = Options::new(5, 3);
    options.wait_ms = wait_ms;
    options.pool = 64;
    let f = Fixture::build(options).await;
    // No owner stores a line, so only the rows the test seeds exist.
    f.app.owners.hooks().set_hold_retries(true);
    f
}

/// Valid full-key rows of the first three witnesses (the quorum) at every size from `from`.
async fn seed_quorum(f: &Fixture, tree: &Tree, from: u64) -> usize {
    let now = now_secs();
    let mut rows = vec![];
    for size in from..=tree.size() {
        let cp = Checkpoint {
            origin: f.log.origin().to_string(),
            size,
            root: open_pact_core::root(tree.prefix(size)),
        };
        for i in 0..3 {
            rows.push((
                size,
                cp.root,
                f.policy.witnesses[i].key.vkey(),
                f.witnesses[i].cosign(&cp, now).to_string(),
            ));
        }
    }
    let count = rows.len();
    f.seed(rows).await;
    count
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_row_batch_is_dropped_off_the_worker() {
    let bound = Duration::from_millis(DROP_WAIT_MS + 500 + 50);
    // Case 1: a found candidate leaves a tail of 199 groups, and its drop holds.
    let f = drop_fixture(DROP_WAIT_MS).await;
    let live = f.live().await;
    let hooks = f.app.owners.hooks();
    let start = f.app.tree().await.unwrap().size();
    let first = raw_get(addr_of(&live), f.query.clone());
    until("A waits", Duration::from_secs(5), || {
        hooks.count("reader_waiting") >= 1
    })
    .await;
    f.append(199).await;
    let tree = f.app.tree().await.unwrap();
    assert_eq!(tree.size(), start + 199);
    let groups = hooks.count("row_groups");
    let freed = hooks.count("freed_rows");
    let seeded = seed_quorum(&f, &tree, start).await;
    let hold = hooks.arm_block("row_batch_drop");
    f.app.owners.notify_changed();
    hold.reached().await;
    // The batch of 200 groups is being freed on the blocking pool; A and B answer meanwhile.
    let a = answer(&first).await;
    assert_eq!(
        (a.status, a.elapsed <= bound),
        (200, true),
        "{} {:?}",
        a.body,
        a.elapsed
    );
    assert_eq!(f.verifies(&a.body, &f.policy).size, tree.size());
    assert_eq!(
        hooks.count("row_groups") - groups,
        200,
        "the SQL returned 200 groups"
    );
    assert_eq!(hold.hits(), 1);
    let second = raw_get(addr_of(&live), f.query.clone());
    let b = answer(&second).await;
    assert_eq!(b.status, 200, "{}", b.body);
    assert!(b.elapsed <= bound, "B answered after {:?}", b.elapsed);
    assert!(hold.holding(), "B answered only after the hold");
    hold.release();
    until("the batch is freed", Duration::from_secs(5), || {
        hooks.count("freed_rows") - freed >= seeded + 3
    })
    .await;
    // A's whole batch (the 200 groups) and B's (the 3 rows of size N).
    assert_eq!(
        hooks.count("freed_rows") - freed,
        seeded + 3,
        "every row was freed"
    );
    drop(live);
    // Case 2: a step that completes with no waiter frees its batch off the worker too.
    let f = drop_fixture(1000).await;
    let live = f.live().await;
    let hooks = f.app.owners.hooks();
    let tree = f.app.tree().await.unwrap();
    let seeded = seed_quorum(&f, &tree, tree.size()).await;
    let step = hooks.arm("row_step_returned");
    let hold = hooks.arm_block("row_batch_drop");
    let abandoned = raw_get(addr_of(&live), f.query.clone());
    step.reached().await;
    let a = answer(&abandoned).await;
    assert_eq!((a.status, a.retry_after.as_deref()), (503, Some("5")));
    // A has answered; the step now completes with nobody waiting for it.
    step.release();
    hold.reached().await;
    assert_eq!(hold.hits(), 1);
    let second = raw_get(addr_of(&live), f.query.clone());
    let b = answer(&second).await;
    assert_eq!(b.status, 200, "{}", b.body);
    assert!(
        b.elapsed <= Duration::from_millis(1000 + 500 + 50),
        "{:?}",
        b.elapsed
    );
    assert!(hold.holding(), "B answered only after the hold");
    hold.release();
    until("the batch is freed", Duration::from_secs(5), || {
        hooks.count("freed_rows") >= seeded
    })
    .await;
}
