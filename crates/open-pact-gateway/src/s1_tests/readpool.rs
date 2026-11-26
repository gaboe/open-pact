//! The read routes keep their own database pool: a write path that stalls PostgreSQL does not
//! starve them, and the writes stay on the main pool.

use super::*;

/// Takes every connection of `pool` and runs a statement on each that does not return, as a
/// writer does while PostgreSQL waits for the WAL.
fn stall(pool: &PgPool) -> impl Future<Output = Vec<tokio::task::JoinHandle<()>>> + use<> {
    let pool = pool.clone();
    async move {
        let mut tasks = vec![];
        for _ in 0..pool.options().get_max_connections() {
            let mut conn = pool.acquire().await.unwrap();
            tasks.push(tokio::spawn(async move {
                let _ = sqlx::query("SELECT pg_sleep(30)").execute(&mut *conn).await;
            }));
        }
        tasks
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_read_answers_while_every_main_connection_is_held_by_a_stalled_writer() {
    let mut options = Options::new(1, 1);
    options.pool = 3;
    options.wait_ms = 1000;
    let f = Fixture::build(options).await;
    // A first read stores the witness line, as a gateway that ran before the stall did.
    let warm = f.get(Some(&f.query)).await;
    assert_eq!(warm.status, StatusCode::OK, "{}", warm.body);
    let stalled = stall(&f.db).await;
    assert_eq!(f.db.num_idle(), 0, "the writers hold every main connection");
    let reply = f.get(Some(&f.query)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    f.verifies(&reply.body, &f.policy);
    assert!(
        reply.elapsed < Duration::from_millis(900),
        "the read waited {:?}",
        reply.elapsed
    );
    for task in stalled {
        task.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_witness_cosignature_is_stored_while_every_read_connection_is_held() {
    let f = Fixture::build(Options::new(1, 1)).await;
    let store = f.app.owners.hooks().arm("store_step");
    let (router, query) = (f.router.clone(), f.query.clone());
    let reader = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    // The owner got its cosignature and runs its upsert on a main connection.
    store.reached().await;
    let mut held = vec![];
    for _ in 0..f.app.read_db.options().get_max_connections() {
        held.push(f.app.read_db.acquire().await.unwrap());
    }
    assert_eq!(f.app.read_db.num_idle(), 0, "every read connection is held");
    store.release();
    until_stored(&f).await;
    drop(held);
    let _ = reader.await;
}

async fn until_stored(f: &Fixture) {
    let started = Instant::now();
    while stored_rows(&f.direct).await == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the cosignature was not stored while the read pool was held"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
