//! S1: a database that stops answering. A relay sits between the gateway's pool and Postgres; the
//! test tells it to lose the reply of the next statement a connection sends.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use sqlx::postgres::PgConnectOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

struct Control {
    /// The next client-to-server bytes on any connection start a stall on that connection.
    armed: AtomicBool,
    /// How many bytes of the next reply still pass before the stall.
    keep: AtomicUsize,
    /// How many client chunks the target connection sends before the one that stalls.
    skip: AtomicUsize,
}

pub(super) struct Relay {
    port: u16,
    control: Arc<Control>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relay {
    pub async fn start(upstream: &PgConnectOptions) -> Relay {
        let target = format!("{}:{}", upstream.get_host(), upstream.get_port());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let control = Arc::new(Control {
            armed: AtomicBool::new(false),
            keep: AtomicUsize::new(0),
            skip: AtomicUsize::new(0),
        });
        let shared = control.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                let Ok(server) = TcpStream::connect(&target).await else {
                    continue;
                };
                tokio::spawn(pipe(client, server, shared.clone()));
            }
        });
        Relay {
            port,
            control,
            task,
        }
    }

    pub fn options(&self, upstream: &PgConnectOptions) -> PgConnectOptions {
        upstream.clone().host("127.0.0.1").port(self.port)
    }

    /// The next statement any connection sends gets `keep` bytes of its reply, then silence. The
    /// statement itself reaches the server and runs.
    /// A statement that sqlx has not prepared on its connection takes two client chunks (parse,
    /// then bind and execute), so `skip` 1 lets the parse pass and stalls the execute.
    pub fn stall_next(&self, skip: usize, keep: usize) {
        self.control.keep.store(keep, Ordering::SeqCst);
        self.control.skip.store(skip, Ordering::SeqCst);
        self.control.armed.store(true, Ordering::SeqCst);
    }
}

async fn pipe(client: TcpStream, server: TcpStream, control: Arc<Control>) {
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    let stalled = Arc::new(AtomicBool::new(false));
    let target = Arc::new(AtomicUsize::new(usize::MAX));
    let passed = Arc::new(AtomicUsize::new(0));
    let up = {
        let (control, stalled, passed, target) = (
            control.clone(),
            stalled.clone(),
            passed.clone(),
            target.clone(),
        );
        async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match cr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if target.load(Ordering::SeqCst) == usize::MAX
                    && control.armed.swap(false, Ordering::SeqCst)
                {
                    target.store(control.skip.load(Ordering::SeqCst), Ordering::SeqCst);
                }
                let left = target.load(Ordering::SeqCst);
                if left != usize::MAX && !stalled.load(Ordering::SeqCst) {
                    if left == 0 {
                        passed.store(control.keep.load(Ordering::SeqCst), Ordering::SeqCst);
                        stalled.store(true, Ordering::SeqCst);
                    } else {
                        target.store(left - 1, Ordering::SeqCst);
                    }
                }
                if sw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = sw.shutdown().await;
        }
    };
    let down = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match sr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let allowed = if stalled.load(Ordering::SeqCst) {
                let left = passed.load(Ordering::SeqCst);
                let now = left.min(n);
                passed.store(left - now, Ordering::SeqCst);
                now
            } else {
                n
            };
            if allowed > 0 && cw.write_all(&buf[..allowed]).await.is_err() {
                break;
            }
        }
        let _ = cw.shutdown().await;
    };
    tokio::join!(up, down);
}

async fn relayed(pool: u32) -> Fixture {
    let mut options = Options::new(1, 1);
    options.relay = true;
    options.pool = pool;
    Fixture::build(options).await
}

fn line_time(f: &Fixture, size: u64, root: LogHash, line: &str) -> u64 {
    let cp = Checkpoint {
        origin: f.log.origin().to_string(),
        size,
        root,
    };
    let line = NoteSignature::parse(line).unwrap();
    match f.policy.witnesses[0].key.verify(&cp, &line) {
        Some(Ok(time)) => time,
        other => panic!("the stored line does not verify: {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_lost_database_reply_ends_the_attempt() {
    let f = relayed(10).await;
    let relay = f.relay.as_ref().unwrap();
    let hooks = f.app.owners.hooks();
    let size = f.size().await;
    let root = f.app.tree().await.unwrap().root();
    let store = hooks.arm("store_step");
    let (router, query) = (f.router.clone(), f.query.clone());
    let reader = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    store.reached().await;
    // The step has its connection and its limit; the upsert runs, its reply is lost.
    relay.stall_next(1, 0);
    let released = Instant::now();
    store.release();
    until(
        "the owner is idle again",
        Duration::from_millis(2500),
        || {
            f.app.owners.views().iter().all(|v| v.idle)
                && released.elapsed() > Duration::from_millis(100)
        },
    )
    .await;
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT witness, signature FROM log_cosignatures WHERE size = $1")
            .bind(i64::try_from(size).unwrap())
            .fetch_all(&f.direct)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1, "the lost reply still committed L1");
    let first = line_time(&f, size, root, &rows[0].1);
    let _ = reader.await.unwrap();
    until("the cooldown passed", Duration::from_secs(5), || {
        f.app.owners.views().iter().all(|v| !v.cooling())
    })
    .await;
    // The witness signs with a new time (whole seconds), so L2 differs from L1.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    f.app.owners.refresh_all();
    let started = Instant::now();
    loop {
        let row: Vec<String> =
            sqlx::query_scalar("SELECT signature FROM log_cosignatures WHERE size = $1")
                .bind(i64::try_from(size).unwrap())
                .fetch_all(&f.direct)
                .await
                .unwrap();
        assert_eq!(row.len(), 1, "exactly one row for the key");
        if line_time(&f, size, root, &row[0]) > first {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "L2 never replaced L1"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    f.assert_no_fork_line().await;
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_dropped_reader_releases_its_connection() {
    let f = relayed(10).await;
    let relay = f.relay.as_ref().unwrap();
    let hooks = f.app.owners.hooks();
    // Warm the cache first, so the stalled statement is the reader's row SELECT.
    f.app.tree().await.unwrap();
    let start = hooks.arm("row_step_start");
    let (router, query) = (f.router.clone(), f.query.clone());
    let client = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(500),
            Fixture::get_with(router, Some(query)),
        )
        .await
    });
    start.reached().await;
    relay.stall_next(1, 1);
    start.release();
    // The SELECT reached the server and got its first reply byte; the rest is withheld.
    let pid = loop {
        let pids: Vec<i32> = sqlx::query_scalar(
            "SELECT pid FROM pg_stat_activity WHERE query LIKE 'SELECT size, witness, signature FROM log_cosignatures%' \
             AND pid <> pg_backend_pid()",
        )
        .fetch_all(&f.direct)
        .await
        .unwrap();
        if let Some(pid) = pids.first() {
            break *pid;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        client.await.unwrap().is_err(),
        "the client gave up after 500 ms"
    );
    let started = Instant::now();
    loop {
        let alive: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE pid = $1")
            .bind(pid)
            .fetch_one(&f.direct)
            .await
            .unwrap();
        if alive == 0 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(7),
            "the reader's backend {pid} is still there"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Every connection of the pool can be taken at once.
    let conns = futures_util::future::join_all(
        (0..10).map(|_| tokio::time::timeout(Duration::from_secs(5), f.db.acquire())),
    )
    .await;
    assert!(
        conns.iter().all(|c| matches!(c, Ok(Ok(_)))),
        "a connection is stranded"
    );
    drop(conns);
    let reply = f.get(Some(&f.query)).await;
    assert!(
        reply.elapsed <= Duration::from_millis(3500),
        "{:?}",
        reply.elapsed
    );
}
