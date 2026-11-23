//! S1 review round 1: a queued Push beside a stalled renewal tree, the diagnostic log, the mine
//! route's enrolment check, the deadline checks before row work, and a second 409.

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

async fn post_mine(router: &Router, request: &Value) -> (StatusCode, Option<String>, Instant) {
    let mut request = Request::post("/v1/log/mine")
        .header("content-type", "application/json")
        .body(Body::from(request.to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 40000))));
    let response = router.clone().oneshot(request).await.unwrap();
    (
        response.status(),
        response
            .headers()
            .get(header::RETRY_AFTER)
            .map(|v| v.to_str().unwrap().to_string()),
        Instant::now(),
    )
}

/// How many statements wait on a table lock of the log.
async fn waiting_on_log_entries(db: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
         AND query ILIKE '%log_entries%' AND query NOT ILIKE '%pg_stat_activity%'",
    )
    .fetch_one(db)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_queued_push_does_not_wait_for_a_renewal_tree_read() {
    let mut options = Options::new(1, 1);
    options.pool = 30;
    let f = Fixture::build(options).await;
    let hooks = f.app.owners.hooks();
    // A fresh checkpoint holds its tree and has not queued its Push yet.
    let read = hooks.arm("checkpoint_tree_read");
    let app = f.app.clone();
    let claim = tokio::spawn(async move { app.checkpoint(Mode::Enroll).await.is_ok() });
    read.reached().await;
    // An unrelated base read takes `grow` and waits on the table lock, which has no deadline.
    let mut lock = f.direct.begin().await.unwrap();
    sqlx::query("LOCK TABLE log_entries IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let app = f.app.clone();
    let base = tokio::spawn(async move { app.tree().await.is_ok() });
    until(
        "the base read waits on the lock",
        Duration::from_secs(5),
        || !base.is_finished(),
    )
    .await;
    let started = Instant::now();
    while waiting_on_log_entries(&f.direct).await == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no SELECT waits on the lock"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // A renewal reaches its tree step and queues behind that read.
    let steps = hooks.count("tree_start_captured");
    f.app.owners.refresh_all();
    until(
        "the renewal reached its tree step",
        Duration::from_secs(10),
        || hooks.count("tree_start_captured") > steps,
    )
    .await;
    let arrivals = f.witnesses[0].arrivals();
    read.release();
    until(
        "the claim's push reached the witness",
        Duration::from_secs(5),
        || f.witnesses[0].arrivals() > arrivals,
    )
    .await;
    assert!(!base.is_finished(), "the base read still waits");
    lock.rollback().await.unwrap();
    assert!(claim.await.unwrap(), "the checkpoint was served");
    assert!(base.await.unwrap());
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_held_log_sink_never_delays_a_503() {
    let mut options = Options::new(1, 1);
    options.wait_ms = 300;
    let f = Fixture::build(options).await;
    f.witnesses[0].set(Behaviour::Delay(Duration::from_secs(6)));
    f.append(1).await;
    // The log writer holds on its first line; no request path may wait for it.
    let (release, held) = std::sync::mpsc::channel::<()>();
    let held = StdMutex::new(held);
    let written = Arc::new(AtomicUsize::new(0));
    let count = written.clone();
    f.app.owners.diag().set_sink(move |_| {
        let _ = held.lock().unwrap().recv_timeout(Duration::from_secs(30));
        count.fetch_add(1, Ordering::SeqCst);
    });
    let bound = Duration::from_millis(300 + ONE_CANDIDATE_BOUND_MS + 700);
    let replies = futures_util::future::join_all(
        (0..300).map(|_| Fixture::get_with(f.router.clone(), Some(f.query.clone()))),
    )
    .await;
    for reply in &replies {
        expect_unavailable(reply, bound);
    }
    assert!(
        f.app.owners.diag().dropped() > 0,
        "300 lines found room in a queue of 256 behind a held writer"
    );
    let manifest = f.app.manifest.hash().as_str().to_string();
    let mut requests = vec![];
    for _ in 0..8 {
        requests.push(mine_request(&f.router, &f.db, &manifest).await);
    }
    let started = Instant::now();
    let answers = futures_util::future::join_all(
        requests.iter().map(|request| post_mine(&f.router, request)),
    )
    .await;
    for (status, retry, at) in answers {
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry.as_deref(), Some("5"));
        assert!(
            at.duration_since(started) <= bound,
            "a mine answered after {:?}",
            at.duration_since(started)
        );
    }
    assert_eq!(
        written.load(Ordering::SeqCst),
        0,
        "the writer still holds its first line"
    );
    for _ in 0..400 {
        let _ = release.send(());
    }
    until(
        "the writer drained its queue",
        Duration::from_secs(10),
        || written.load(Ordering::SeqCst) >= 257,
    )
    .await;
}

const ONE_CANDIDATE_BOUND_MS: u64 = 150;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_pending_device_gets_the_base_403_when_no_checkpoint_is_ready() {
    let mut options = Options::new(1, 1);
    options.wait_ms = 500;
    let f = Fixture::build(options).await;
    // No witness cosigns, so no size has a quorum.
    f.witnesses[0].set(Behaviour::Answer(500));
    f.append(1).await;
    let manifest = f.app.manifest.hash().as_str().to_string();
    for state in ["pending", "revoked"] {
        let request = mine_request_as(&f.router, &f.db, &manifest, state).await;
        let (status, retry, _) = post_mine(&f.router, &request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a {state} device");
        assert_eq!(retry, None);
    }
    // The same setup for an approved device is a 503, and its lookup connection is back in the
    // pool while it waits for the witnesses.
    let request = mine_request(&f.router, &f.db, &manifest).await;
    let hooks = f.app.owners.hooks();
    let entered = hooks.arm("served_entered");
    let router = f.router.clone();
    let answer = tokio::spawn(async move { post_mine(&router, &request).await });
    entered.reached().await;
    // A released connection takes a moment to return; a held one does not return.
    until(
        "the mine route released its connection",
        Duration::from_secs(2),
        || usize::try_from(f.db.size()).unwrap() == f.db.num_idle(),
    )
    .await;
    entered.release();
    let (status, retry, _) = answer.await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(retry.as_deref(), Some("5"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn no_row_step_starts_when_the_bind_arrays_end_past_the_deadline() {
    let mut options = Options::new(1, 1);
    options.wait_ms = 500;
    let f = Fixture::build(options).await;
    let hooks = f.app.owners.hooks();
    hooks.set_hold_retries(true);
    let before = hooks.count("row_step_start");
    // The first read is held after its last check, until the deadline has passed.
    hooks.arm_past_deadline("row_step_prepare", Duration::from_millis(1));
    let reply = f.get(Some(&f.query)).await;
    expect_unavailable(&reply, Duration::from_millis(500 + 500));
    assert_eq!(hooks.count("row_step_prepare"), 1);
    // A step that was spawned would reach its first statement within moments.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hooks.count("row_step_start"),
        before,
        "a row step started after the deadline"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_second_409_keeps_the_latest_witness_size() {
    let f = Fixture::new(1, 1).await;
    f.append(9).await;
    let size = f.size().await;
    assert!(size > 6);
    // The first push is told 3, its retry 5; the next push must start from 5.
    f.witnesses[0].set(Behaviour::Conflicts(vec![3, 5]));
    f.app.owners.refresh_all();
    until("the push and its retry", Duration::from_secs(10), || {
        f.witnesses[0].received().len() >= 2
    })
    .await;
    f.app.owners.refresh_all();
    until("the next push", Duration::from_secs(10), || {
        f.witnesses[0].received().len() >= 3
    })
    .await;
    let seen: Vec<(u64, u64, u16)> = f.witnesses[0]
        .received()
        .iter()
        .map(|r| (r.size, r.old_size, r.status))
        .collect();
    assert_eq!(seen[0], (size, 0, 409));
    assert_eq!(seen[1], (size, 3, 409));
    assert_eq!(
        seen[2].1, 5,
        "the next push starts from the latest size: {seen:?}"
    );
    f.assert_no_fork_line().await;
}
