//! S1: the owners, the read routes and their policy. Each test runs a gateway against fake witnesses
//! that apply the real add-checkpoint rules. They need TEST_DATABASE_URL and LOG_ORIGIN.

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Request;
use base64::Engine;
use open_pact_core::{LogKey, LogPolicy, verify_cosignatures};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::served::now_secs;
use crate::testwitness::{Behaviour, FakeWitness};

const DEMO: &str = include_str!("../../../examples/manifest.toml");
const KEK: [u8; 32] = [5; 32];

struct Got {
    status: StatusCode,
    retry_after: Option<String>,
    body: String,
    elapsed: Duration,
}

struct Fixture {
    app: App,
    router: Router,
    db: PgPool,
    /// A pool that skips the relay (the same pool when there is none).
    direct: PgPool,
    relay: Option<relay::Relay>,
    witnesses: Vec<FakeWitness>,
    log: LogKey,
    policy: LogPolicy,
    query: String,
    /// The registry, when the options turn observation on.
    metrics: Option<Arc<metrics::Metrics>>,
    events: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<witness::WitnessEvent>>,
}

struct Options {
    count: usize,
    quorum: usize,
    wait_ms: u64,
    pool: u32,
    /// Connections of the read pool. Few, so the suite stays under the 100 connections of a default PostgreSQL.
    read_pool: u32,
    /// Lists each witness URL twice, the second time with a trailing slash.
    duplicate_urls: bool,
    /// Approves every enrolment and drops the manifest controls, so a real client claim is accepted.
    real_client: bool,
    /// No witness and `allow_split_views = true` (needs count 0).
    split_views: bool,
    /// The witnesses the manifest lists, by index (default: all).
    listed: Option<Vec<usize>>,
    /// The database pool reaches Postgres through a relay the test controls.
    relay: bool,
    /// Seeds of the witness keys (default: one per index) and whether all share one name.
    seeds: Option<Vec<[u8; 32]>>,
    same_name: bool,
    /// Turns the metrics and the slow-request log on, logging requests slower than this.
    slow_ms: Option<u64>,
}

impl Options {
    fn new(count: usize, quorum: usize) -> Options {
        Options {
            count,
            quorum,
            wait_ms: 3000,
            pool: 20,
            read_pool: 2,
            duplicate_urls: false,
            real_client: false,
            split_views: false,
            listed: None,
            relay: false,
            seeds: None,
            same_name: false,
            slow_ms: None,
        }
    }
}

fn encode(policy: &LogPolicy) -> String {
    format!(
        "policy={}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(policy).unwrap())
    )
}

fn witness_seed(index: usize) -> [u8; 32] {
    [u8::try_from(index + 1).unwrap(); 32]
}

/// The demo manifest with this witness list ("{ name = .., key = .. }" entries) and quorum.
/// `split_views`: no witness and `allow_split_views`. `real_client`: one control every host passes.
fn manifest_text(listed: &[String], quorum: usize, split_views: bool, real_client: bool) -> String {
    let start = DEMO.find("witnesses = [").unwrap();
    let end =
        DEMO[start..].find("witness_quorum = 1").unwrap() + start + "witness_quorum = 1".len();
    let toml = if split_views {
        format!(
            "{}witnesses = []\nwitness_quorum = 0\nallow_split_views = true{}",
            &DEMO[..start],
            &DEMO[end..]
        )
    } else {
        format!(
            "{}witnesses = [{}]\nwitness_quorum = {}{}",
            &DEMO[..start],
            listed.join(", "),
            quorum,
            &DEMO[end..]
        )
    };
    if !real_client {
        return toml;
    }
    // One control that only reports a value, so every host passes it.
    let from = toml.find("[[control]]").unwrap();
    let keep = toml
        .find("[[control]]\nid = \"managed_repos_total\"")
        .unwrap();
    let keep_end = keep + 1 + toml[keep + 1..].find("[[control]]").unwrap();
    let to = toml.find("[log]").unwrap();
    format!("{}{}{}", &toml[..from], &toml[keep..keep_end], &toml[to..])
}

fn listed_entry(key: &open_pact_core::WitnessKey) -> String {
    format!("{{ name = \"{}\", key = \"{}\" }}", key.name(), key.vkey())
}

impl Fixture {
    async fn new(count: usize, quorum: usize) -> Fixture {
        Fixture::build(Options::new(count, quorum)).await
    }

    async fn build(options: Options) -> Fixture {
        let direct = testdb::fresh_with_max_connections(options.pool).await;
        let (db, relay) = if options.relay {
            let relay = relay::Relay::start(direct.connect_options().as_ref()).await;
            let through = relay.options(direct.connect_options().as_ref());
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(options.pool)
                .connect_with(through)
                .await
                .unwrap();
            (pool, Some(relay))
        } else {
            (direct.clone(), None)
        };
        let kek = SealingKey::new(&KEK);
        let keys = Keys::load_or_create(&db, &kek).await.unwrap();
        let log = log_key(&keys).unwrap();
        let mut witnesses = vec![];
        for index in 0..options.count {
            let name = if options.same_name {
                "witness.example.org/w0".to_string()
            } else {
                format!("witness.example.org/w{index}")
            };
            let seed = options
                .seeds
                .as_ref()
                .map_or_else(|| witness_seed(index), |s| s[index]);
            witnesses.push(FakeWitness::with_seed(&name, seed, &log).await);
        }
        let listed: Vec<String> = witnesses
            .iter()
            .enumerate()
            .filter(|(i, _)| options.listed.as_ref().is_none_or(|l| l.contains(i)))
            .map(|(_, w)| listed_entry(&w.inner.key))
            .collect();
        let toml = manifest_text(
            &listed,
            options.quorum,
            options.split_views,
            options.real_client,
        );
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let policy = manifest.body().log.clone().unwrap();
        let log_state = Log::new(keys.log.clone(), log.clone(), Witnesses::new(Some(&policy)));
        let enforced = Arc::new(Enforced {
            siem: None,
            company: Endorsement::sign(&keys.manifest, manifest.hash()),
            manifest: Arc::new(manifest.clone()),
            toml: toml.as_str().into(),
            log: Arc::new(log_state),
            version: None,
            revision: 0,
        });
        let current = Arc::new(RwLock::new(enforced.clone()));
        let mut urls: Vec<String> = witnesses.iter().map(|w| w.url.clone()).collect();
        if options.duplicate_urls {
            urls = urls
                .into_iter()
                .flat_map(|url| [url.clone(), format!("{url}/")])
                .collect();
        }
        let urls = witness::normalize_urls(urls);
        let metrics = options.slow_ms.map(|_| Arc::new(metrics::Metrics::new()));
        let observe = metrics::Observation::new(metrics.clone(), options.slow_ms);
        let read_db = testdb::read_pool(&db, options.read_pool);
        let owners = Owners::start(
            urls,
            enforced.log.witnesses.keys().to_vec(),
            current.clone(),
            db.clone(),
            read_db.clone(),
            observe.clone(),
        )
        .unwrap();
        let app = App {
            db: db.clone(),
            read_db,
            enforced,
            current,
            keys: Arc::new(keys),
            auto_approve: options.real_client,
            limiter: Arc::new(Limiter::new(100, Duration::from_secs(60), 100)),
            nonce_limiter: Arc::new(Limiter::new(
                if options.real_client { 100_000 } else { 100 },
                Duration::from_secs(60),
                if options.real_client { 100_000 } else { 100 },
            )),
            max_nonces: 10_000,
            kek: Arc::new(kek),
            observe,
            owners: Arc::new(owners),
            wait: Duration::from_millis(options.wait_ms),
        };
        publish_manifest(&db, &manifest).await.unwrap();
        let query = encode(&policy);
        let events = tokio::sync::Mutex::new(app.owners.events());
        Fixture {
            events,
            router: router(app.clone()),
            app,
            db,
            direct,
            relay,
            witnesses,
            log,
            policy,
            query,
            metrics,
        }
    }

    async fn append(&self, count: usize) {
        for i in 0..count {
            let mut tx = self.db.begin().await.unwrap();
            translog::append(&mut tx, EntryKind::RetentionPurge, json!({ "fixture": i }))
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    }

    async fn size(&self) -> u64 {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM log_entries")
            .fetch_one(&self.db)
            .await
            .unwrap();
        u64::try_from(count).unwrap()
    }

    async fn get_with(router: Router, query: Option<String>) -> Got {
        let uri = match query {
            Some(query) => format!("/v1/log/checkpoint?{query}"),
            None => "/v1/log/checkpoint".to_string(),
        };
        let started = Instant::now();
        let response = router
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        Got {
            status,
            retry_after,
            body: String::from_utf8_lossy(&bytes).into_owned(),
            elapsed: started.elapsed(),
        }
    }

    async fn get(&self, query: Option<&str>) -> Got {
        Fixture::get_with(self.router.clone(), query.map(str::to_string)).await
    }

    /// Both checks a client runs: the log signature and the policy's cosignatures.
    fn verifies(&self, body: &str, policy: &LogPolicy) -> Checkpoint {
        let note = Note::parse(body).unwrap_or_else(|e| panic!("{e}: {body}"));
        let cp = self.log.verify(&note).unwrap();
        verify_cosignatures(Some(policy), &cp, &note, now_secs())
            .unwrap_or_else(|e| panic!("{e}: {body}"));
        cp
    }

    fn policy_of(&self, indexes: &[usize], quorum: usize) -> LogPolicy {
        LogPolicy {
            witnesses: indexes
                .iter()
                .map(|i| self.policy.witnesses[*i].clone())
                .collect(),
            witness_quorum: quorum,
            ..self.policy.clone()
        }
    }

    /// Every event so far. A refused consistency proof is the only fork diagnostic.
    async fn events(&self) -> Vec<witness::WitnessEvent> {
        let mut events = self.events.lock().await;
        let mut seen = vec![];
        while let Ok(event) = events.try_recv() {
            seen.push(event);
        }
        seen
    }

    async fn assert_no_fork_line(&self) {
        for event in self.events().await {
            assert!(
                !matches!(event, witness::WitnessEvent::Refused { .. }),
                "a fork line: {event:?}"
            );
        }
    }

    /// Stores one line per (size, witness) with one statement: `(size, root, witness, line)`.
    async fn seed(&self, rows: Vec<(u64, LogHash, String, String)>) {
        sqlx::query(
            "INSERT INTO log_cosignatures (size, root, witness, signature) \
             SELECT * FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[]) \
             ON CONFLICT (size, root, witness) DO NOTHING",
        )
        .bind(
            rows.iter()
                .map(|r| i64::try_from(r.0).unwrap())
                .collect::<Vec<_>>(),
        )
        .bind(rows.iter().map(|r| r.1.to_string()).collect::<Vec<_>>())
        .bind(rows.iter().map(|r| r.2.clone()).collect::<Vec<_>>())
        .bind(
            rows.iter()
                .map(|r| r.3.trim_end().to_string())
                .collect::<Vec<_>>(),
        )
        .execute(&self.direct)
        .await
        .unwrap();
    }

    fn sizes_are_non_decreasing(&self) {
        for witness in &self.witnesses {
            let sizes = witness.sizes();
            assert!(sizes.is_sorted(), "sizes the witness received: {sizes:?}");
        }
    }
}

fn expect_unavailable(reply: &Got, within: Duration) {
    assert_eq!(
        reply.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        reply.body
    );
    assert_eq!(reply.retry_after.as_deref(), Some("5"));
    assert!(
        reply.elapsed <= within,
        "answered after {:?}",
        reply.elapsed
    );
}

async fn until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < limit, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn stored_rows(db: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM log_cosignatures")
        .fetch_one(db)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_reader_gets_a_witnessed_note() {
    let f = Fixture::new(1, 1).await;
    let reply = f.get(Some(&f.query)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let cp = f.verifies(&reply.body, &f.policy);
    assert_eq!(f.witnesses[0].sizes(), [cp.size]);
    // A second read of the same size needs no push.
    let again = f.get(Some(&f.query)).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(f.witnesses[0].sizes(), [cp.size]);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_bare_request_uses_the_enforced_policy() {
    let f = Fixture::new(2, 2).await;
    let reply = f.get(None).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    f.verifies(&reply.body, &f.policy);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn an_invalid_policy_is_refused() {
    let f = Fixture::new(4, 3).await;
    let base = serde_json::to_value(&f.policy).unwrap();
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut value = base.clone();
        edit(&mut value);
        let bytes = serde_json::to_vec(&value).unwrap();
        format!(
            "policy={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        )
    };
    let url_safe = |text: &str| {
        format!(
            "policy={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text)
        )
    };
    let queries = [
        ("not base64", "policy=%%%".to_string()),
        ("not JSON", url_safe("hello")),
        ("unknown field", with(&|v| v["surprise"] = json!(1))),
        (
            "key named otherwise",
            with(&|v| v["witnesses"][0]["name"] = json!("witness.example.org/other")),
        ),
        (
            "duplicate witness",
            with(&|v| {
                let first = v["witnesses"][0].clone();
                v["witnesses"][1] = first;
            }),
        ),
        ("two of four", with(&|v| v["witness_quorum"] = json!(2))),
        ("above the count", with(&|v| v["witness_quorum"] = json!(5))),
        ("u64 max", with(&|v| v["witness_quorum"] = json!(u64::MAX))),
        (
            "split views with witnesses",
            with(&|v| v["allow_split_views"] = json!(true)),
        ),
        (
            "no witnesses",
            with(&|v| {
                v["witnesses"] = json!([]);
                v["witness_quorum"] = json!(0);
            }),
        ),
        (
            "quorum without witnesses",
            with(&|v| {
                v["witnesses"] = json!([]);
                v["allow_split_views"] = json!(true);
                v["witness_quorum"] = json!(1);
            }),
        ),
        ("zero age", with(&|v| v["checkpoint_max_age"] = json!("0h"))),
        ("two values", format!("{}&{}", f.query, f.query)),
    ];
    for (name, query) in queries {
        let reply = f.get(Some(&query)).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            reply.body
        );
        assert!(
            reply.body.contains("invalid policy"),
            "{name}: {}",
            reply.body
        );
    }
    // A policy without witnesses that the manifest rules allow is served the log-signed note.
    let open = with(&|v| {
        v["witnesses"] = json!([]);
        v["allow_split_views"] = json!(true);
        v["witness_quorum"] = json!(0);
    });
    let reply = f.get(Some(&open)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn each_reader_gets_a_note_its_policy_accepts() {
    // The gateway enforces both witnesses. A reader whose policy lists one gets a note with that
    // witness's line; a reader whose policy lists the gated one waits and then gets 503.
    let f = Fixture::new(2, 2).await;
    f.witnesses[1].gate();
    let a = f.policy_of(&[0], 1);
    let b = f.policy_of(&[1], 1);
    let reply = f.get(Some(&encode(&a))).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    f.verifies(&reply.body, &a);
    let early = f.get(Some(&encode(&b))).await;
    expect_unavailable(&early, Duration::from_millis(3500));
    let bare = f.get(None).await;
    assert_eq!(
        bare.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        bare.body
    );
    f.witnesses[1].open_gate();
    until(
        "the second witness stored its line",
        Duration::from_secs(5),
        || f.witnesses[1].sizes().len() == 1,
    )
    .await;
    let late = f.get(Some(&encode(&b))).await;
    assert_eq!(late.status, StatusCode::OK, "{}", late.body);
    f.verifies(&late.body, &b);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_policy_this_process_never_enforced_gets_503() {
    let f = Fixture::new(1, 1).await;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
    let name = "witness.example.org/other";
    let key = WitnessKey::new(name, signer.verifying_key());
    let foreign = LogPolicy {
        witnesses: vec![open_pact_core::Witness {
            name: name.into(),
            key,
        }],
        witness_quorum: 1,
        ..f.policy.clone()
    };
    let reply = f.get(Some(&encode(&foreign))).await;
    expect_unavailable(&reply, Duration::from_millis(3500));
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_timed_out_witness_bounds_the_wait() {
    let mut options = Options::new(1, 1);
    options.wait_ms = 1000;
    let f = Fixture::build(options).await;
    f.witnesses[0].set(Behaviour::Delay(Duration::from_secs(7)));
    let replies = futures_util::future::join_all(
        (0..8).map(|_| Fixture::get_with(f.router.clone(), Some(f.query.clone()))),
    )
    .await;
    for reply in &replies {
        expect_unavailable(reply, Duration::from_millis(1500));
    }
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn an_exhausted_pool_answers_503() {
    let mut options = Options::new(1, 1);
    options.pool = 2;
    options.wait_ms = 1000;
    let f = Fixture::build(options).await;
    let mut held = vec![];
    for _ in 0..f.app.read_db.options().get_max_connections() {
        held.push(f.app.read_db.acquire().await.unwrap());
    }
    let reply = f.get(Some(&f.query)).await;
    expect_unavailable(&reply, Duration::from_millis(1500));
    assert_eq!(reply.body, "the log could not be read in time; retry\n");
    drop(held);
    let reply = f.get(Some(&f.query)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_failed_owner_retries_at_the_same_size() {
    let f = Fixture::new(1, 1).await;
    f.witnesses[0].set(Behaviour::Answer(500));
    let first = f.get(Some(&f.query)).await;
    expect_unavailable(&first, Duration::from_millis(3500));
    f.witnesses[0].set(Behaviour::Healthy);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = f.get(Some(&f.query)).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    f.verifies(&second.body, &f.policy);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn failed_rounds_cool_down_while_the_log_grows() {
    let f = Fixture::new(1, 1).await;
    f.witnesses[0].set(Behaviour::Answer(500));
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(3500) {
        f.append(1).await;
        let reply = f.get(Some(&f.query)).await;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reply.retry_after.as_deref(), Some("5"));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pushes = f.witnesses[0].received();
    assert_eq!(pushes.len(), 3, "{pushes:?}");
    let gap = |i: usize| pushes[i].arrived - pushes[i - 1].arrived;
    assert!(
        gap(1) >= Duration::from_secs(1) && gap(1) <= Duration::from_millis(1300),
        "{:?}",
        gap(1)
    );
    assert!(
        gap(2) >= Duration::from_secs(2) && gap(2) <= Duration::from_millis(2300),
        "{:?}",
        gap(2)
    );
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_slow_failure_cools_down_from_its_end() {
    let f = Fixture::new(1, 1).await;
    f.witnesses[0].set(Behaviour::DelayAnswer(Duration::from_millis(1500), 500));
    let started = Instant::now();
    while f.witnesses[0].received().len() < 3 {
        assert!(
            started.elapsed() < Duration::from_secs(9),
            "{:?}",
            f.witnesses[0].received()
        );
        let reply = f.get(Some(&f.query)).await;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pushes = f.witnesses[0].received();
    let after = |i: usize| pushes[i].arrived - pushes[i - 1].at;
    assert!(
        after(1) >= Duration::from_secs(1) && after(1) <= Duration::from_millis(1300),
        "{:?}",
        after(1)
    );
    assert!(
        after(2) >= Duration::from_secs(2) && after(2) <= Duration::from_millis(2300),
        "{:?}",
        after(2)
    );
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_slow_extra_witness_does_not_hold_the_next_size() {
    let f = Fixture::new(3, 2).await;
    let first = f.get(Some(&f.query)).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    until("w3 accepted the first size", Duration::from_secs(5), || {
        f.witnesses[2].sizes().len() == 1
    })
    .await;
    f.witnesses[2].set(Behaviour::Delay(Duration::from_secs(8)));
    f.append(1).await;
    let next = f.get(Some(&f.query)).await;
    assert_eq!(next.status, StatusCode::OK, "{}", next.body);
    assert!(next.elapsed < Duration::from_secs(1), "{:?}", next.elapsed);
    f.verifies(&next.body, &f.policy);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_cancelled_request_does_not_cancel_the_push() {
    let f = Fixture::new(1, 1).await;
    let gate = f.witnesses[0].gate();
    drop(gate);
    let router = f.router.clone();
    let query = f.query.clone();
    let request = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    until("the push arrived", Duration::from_secs(5), || {
        f.witnesses[0].arrivals() == 1
    })
    .await;
    request.abort();
    let _ = request.await;
    f.witnesses[0].open_gate();
    let started = Instant::now();
    while stored_rows(&f.db).await == 0 {
        assert!(started.elapsed() < Duration::from_secs(5), "no row stored");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let reply = f.get(Some(&f.query)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(
        f.witnesses[0].arrivals(),
        1,
        "the second read made a witness call"
    );
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_repeated_witness_url_gets_one_owner() {
    let mut options = Options::new(1, 1);
    options.duplicate_urls = true;
    let f = Fixture::build(options).await;
    f.append(1).await;
    let reply = f.get(Some(&f.query)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    f.append(1).await;
    let reply = f.get(Some(&f.query)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let sizes = f.witnesses[0].sizes();
    let mut unique = sizes.clone();
    unique.dedup();
    assert_eq!(sizes, unique, "one push per size: {sizes:?}");
    assert_eq!(
        witness::normalize_urls(vec!["http://w1/".into(), "http://w1".into()]),
        ["http://w1"]
    );
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_large_valid_policy_is_accepted() {
    let f = Fixture::new(40, 21).await;
    // Its query is over 4 KiB: the client sends none then, and the gateway answers 400 to one.
    assert!(f.query.len() > "policy=".len() + 4096);
    let refused = f.get(Some(&f.query)).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    // With no query the gateway uses the policy of the manifest it enforces: this one.
    let reply = f.get(None).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    f.verifies(&reply.body, &f.policy);
    f.append(1).await;
    let size = f.size().await;
    let (note, _) = f.app.checkpoint(Mode::Enroll).await.unwrap();
    let cp = f.log.verify(&note).unwrap();
    assert_eq!(cp.size, size);
    assert!(
        note.signatures.len() > 21,
        "{} lines",
        note.signatures.len()
    );
    verify_cosignatures(Some(&f.policy), &cp, &note, now_secs()).unwrap();
    for witness in &f.witnesses {
        let at_size = witness.sizes().iter().filter(|s| **s == size).count();
        assert_eq!(at_size, 1, "{:?}", witness.sizes());
    }
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_reader_push_waits_for_an_enrolment_push() {
    let f = Fixture::new(1, 1).await;
    f.append(1).await;
    let size = f.size().await;
    let gate = f.witnesses[0].gate();
    drop(gate);
    let app = f.app.clone();
    let enrolment = tokio::spawn(async move { app.checkpoint(Mode::Enroll).await });
    until("the enrolment push arrived", Duration::from_secs(5), || {
        f.witnesses[0].arrivals() == 1
    })
    .await;
    f.append(1).await;
    let router = f.router.clone();
    let query = f.query.clone();
    let read = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        f.witnesses[0].arrivals(),
        1,
        "a push went out before the enrolment's decision"
    );
    f.witnesses[0].open_gate();
    let (note, _) = enrolment.await.unwrap().unwrap();
    assert_eq!(f.log.verify(&note).unwrap().size, size);
    let reply = read.await.unwrap();
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    f.verifies(&reply.body, &f.policy);
    assert_eq!(f.witnesses[0].sizes(), [size, size + 1]);
    assert!(f.witnesses[0].received().iter().all(|r| r.status == 200));
    f.assert_no_fork_line().await;
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_lower_push_queued_at_the_commit_goes_first() {
    let f = Fixture::new(1, 1).await;
    f.append(1).await;
    let hooks = f.app.owners.hooks();
    let tree_read = hooks.arm("checkpoint_tree_read");
    let first = f.app.clone();
    let e1 = tokio::spawn(async move { first.checkpoint(Mode::Enroll).await });
    tree_read.reached().await;
    let size = f.size().await;
    f.append(1).await;
    let commit = hooks.arm("dispatch_commit_entered");
    let second = f.app.clone();
    let e2 = tokio::spawn(async move { second.checkpoint(Mode::Enroll).await });
    commit.reached().await;
    tree_read.release();
    until("the second fan-out", Duration::from_secs(5), || {
        f.app
            .owners
            .fanouts
            .load(std::sync::atomic::Ordering::SeqCst)
            == 2
    })
    .await;
    commit.release();
    let (n1, _) = e1.await.unwrap().unwrap();
    let (n2, _) = e2.await.unwrap().unwrap();
    assert_eq!(f.log.verify(&n1).unwrap().size, size);
    assert_eq!(f.log.verify(&n2).unwrap().size, size + 1);
    assert_eq!(f.witnesses[0].sizes(), [size, size + 1]);
    assert!(f.witnesses[0].received().iter().all(|r| r.status == 200));
    f.assert_no_fork_line().await;
}

/// A held enrolment or claim at size N while the log grows to N+1 and a reader's push of N+1 runs.
async fn held_at_n(
    f: &Fixture,
    mode_claim: bool,
) -> (
    u64,
    tokio::task::JoinHandle<Result<(Note, metrics::Served), Reply>>,
    Arc<hooks_point::Point>,
) {
    f.append(1).await;
    let size = f.size().await;
    let tree_read = f.app.owners.hooks().arm("checkpoint_tree_read");
    let app = f.app.clone();
    let policy = f.policy.clone();
    let task = tokio::spawn(async move {
        if mode_claim {
            app.checkpoint(Mode::Claim {
                policy: Some(&policy),
            })
            .await
        } else {
            app.checkpoint(Mode::Enroll).await
        }
    });
    tree_read.reached().await;
    f.append(1).await;
    (size, task, tree_read)
}

mod hooks_point {
    pub use crate::hooks::Point;
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn an_enrolment_signs_its_own_size() {
    let f = Fixture::new(1, 1).await;
    let (size, task, release) = held_at_n(&f, false).await;
    let reader = f.get(Some(&f.query)).await;
    assert_eq!(reader.status, StatusCode::OK, "{}", reader.body);
    release.release();
    let (note, _) = task.await.unwrap().unwrap();
    assert_eq!(
        f.log.verify(&note).unwrap().size,
        size,
        "no advance for an enrolment"
    );
    assert_eq!(f.witnesses[0].sizes(), [size + 1]);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_failed_push_raises_the_floor() {
    let f = Fixture::new(1, 1).await;
    let (size, task, release) = held_at_n(&f, false).await;
    f.witnesses[0].set(Behaviour::Answer(500));
    let reader = f.get(Some(&f.query)).await;
    assert_eq!(reader.status, StatusCode::SERVICE_UNAVAILABLE);
    f.witnesses[0].set(Behaviour::Healthy);
    release.release();
    let (note, _) = task.await.unwrap().unwrap();
    assert_eq!(f.log.verify(&note).unwrap().size, size);
    f.sizes_are_non_decreasing();
    assert_eq!(
        f.witnesses[0].sizes(),
        [size + 1],
        "no send below the floor"
    );
    f.assert_no_fork_line().await;
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_claim_behind_a_reader_push_advances_once() {
    let f = Fixture::new(1, 1).await;
    let (size, task, release) = held_at_n(&f, true).await;
    let reader = f.get(Some(&f.query)).await;
    assert_eq!(reader.status, StatusCode::OK, "{}", reader.body);
    release.release();
    let (note, served) = task.await.unwrap().unwrap();
    let cp = f.log.verify(&note).unwrap();
    assert_eq!(cp.size, size + 1);
    verify_cosignatures(Some(&f.policy), &cp, &note, now_secs()).unwrap();
    assert!(matches!(served, metrics::Served::Witnessed));
    assert_eq!(
        f.witnesses[0].sizes(),
        [size + 1],
        "nothing below the floor was sent"
    );
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_failed_claim_advance_answers_the_short_note() {
    let f = Fixture::new(1, 1).await;
    let (size, task, release) = held_at_n(&f, true).await;
    f.witnesses[0].set(Behaviour::Answer(500));
    let reader = f.get(Some(&f.query)).await;
    assert_eq!(reader.status, StatusCode::SERVICE_UNAVAILABLE);
    release.release();
    let (note, served) = task.await.unwrap().unwrap();
    let cp = f.log.verify(&note).unwrap();
    assert_eq!(cp.size, size, "the note of the size the claim read");
    assert_eq!(note.signatures.len(), 1, "the log line alone");
    assert!(matches!(served, metrics::Served::NotYet));
    f.sizes_are_non_decreasing();
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn cosignatures_are_renewed_at_a_stable_size() {
    let f = Fixture::new(1, 1).await;
    let size = f.size().await;
    let tree = f.app.tree().await.unwrap();
    let cp = Checkpoint {
        origin: f.log.origin().to_string(),
        size,
        root: tree.root(),
    };
    // A line that is 3301 s old: stored, but past the age the gateway still counts.
    let stale = f.witnesses[0].cosign(&cp, now_secs() - 3301);
    sqlx::query(witness::UPSERT)
        .bind(i64::try_from(size).unwrap())
        .bind(cp.root.to_string())
        .bind(f.policy.witnesses[0].key.vkey())
        .bind(stale.to_string().trim_end())
        .execute(&f.db)
        .await
        .unwrap();
    f.witnesses[0].gate();
    let first = f.get(Some(&f.query)).await;
    expect_unavailable(&first, Duration::from_millis(3500));
    f.witnesses[0].open_gate();
    until("the renewal arrived", Duration::from_secs(5), || {
        f.witnesses[0].sizes() == [size]
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = f.get(Some(&f.query)).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    f.verifies(&second.body, &f.policy);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_cold_burst_fetches_one_batch() {
    let f = Fixture::new(1, 1).await;
    f.append(2000).await;
    let snap = f.app.enforced.clone();
    let before = snap.log.fetches.load(Ordering::SeqCst);
    let hooks = f.app.owners.hooks();
    let barrier = hooks.arm_always("tree_start_captured");
    let steps: Vec<_> = (0..40)
        .map(|_| {
            tree_step(
                f.app.read_db.clone(),
                snap.clone(),
                TreeSql::Step,
                hooks.clone(),
            )
        })
        .collect();
    until(
        "every step captured its start",
        Duration::from_secs(10),
        || barrier.hits() == 40,
    )
    .await;
    barrier.disarm();
    let mut size = 0;
    for step in steps {
        size = step.await.unwrap().unwrap().size();
    }
    assert_eq!(size, f.size().await);
    assert_eq!(
        snap.log.fetches.load(Ordering::SeqCst) - before,
        1,
        "one SQL fetch served all 40 steps"
    );
}

#[test]
fn the_uncached_query_stays_inside_the_tree() {
    // (a) T = 10,000 captured, then 4,098 appends move the oldest windowed size to 10,003.
    assert_eq!(served::uncached_bound(5_000, 10_000, 10_003), Some(10_000));
    // (b) the oldest windowed size is 6,000.
    assert_eq!(served::uncached_bound(5_000, 10_000, 6_000), Some(5_999));
    // (c) the floor is at or above the oldest windowed size.
    assert_eq!(served::uncached_bound(7_000, 10_000, 6_000), None);
}

#[test]
fn assemble_prefers_a_timely_line() {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let key = WitnessKey::new("witness.example.org/w0", signer.verifying_key());
    let policy = LogPolicy {
        allow_split_views: false,
        witnesses: vec![open_pact_core::Witness {
            name: "witness.example.org/w0".into(),
            key: key.clone(),
        }],
        witness_quorum: 1,
        checkpoint_max_age: open_pact_core::Span::try_from("1h".to_string()).unwrap(),
    };
    let log_signer = p256_key();
    let log = LogKey::new("log.example.org/test", &PublicKey::from(&log_signer));
    let cp = Checkpoint {
        origin: "log.example.org/test".into(),
        size: 5,
        root: LogHash([7; 32]),
    };
    let note = log.sign(&log_signer, &cp);
    let now = 1_790_000_000;
    // The full-key line is past the future edge, the bare-name line is timely: the bare one wins.
    let future = key.cosign(&signer, &cp, now + 400);
    let timely = key.cosign(&signer, &cp, now - 10);
    let (reply, count, kept) = served::assemble(
        &log,
        Some(&policy),
        &cp,
        note.clone(),
        &[future.clone(), timely.clone()],
        now,
        &hooks::Hooks::default(),
    );
    assert_eq!(count, 1);
    assert_eq!(reply.signatures.len(), 2);
    assert_eq!(kept[0].time, now - 10);
    verify_cosignatures(Some(&policy), &cp, &reply, now).unwrap();
    // Both timely: the newer line wins, and one key counts once.
    let older = key.cosign(&signer, &cp, now - 20);
    let (_, count, kept) = served::assemble(
        &log,
        Some(&policy),
        &cp,
        note,
        &[older, timely],
        now,
        &hooks::Hooks::default(),
    );
    assert_eq!((count, kept[0].time), (1, now - 10));
}

fn p256_key() -> SigningKey {
    open_pact_core::dev_key::generate()
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_lost_witness_answer_is_recovered() {
    let f = Fixture::new(1, 1).await;
    let size = f.size().await;
    f.witnesses[0].set(Behaviour::StoreThenFail);
    let first = f.get(Some(&f.query)).await;
    assert_eq!(first.status, StatusCode::SERVICE_UNAVAILABLE);
    f.witnesses[0].set(Behaviour::Healthy);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = f.get(Some(&f.query)).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    f.verifies(&second.body, &f.policy);
    // The witness stored the size and lost the answer: the next push is a 409 that names it, and
    // the single retry starts from that size.
    let record: Vec<(u64, u64, u16)> = f.witnesses[0]
        .received()
        .iter()
        .map(|r| (r.size, r.old_size, r.status))
        .collect();
    assert_eq!(record, [(size, 0, 500), (size, 0, 409), (size, size, 200)]);
    f.assert_no_fork_line().await;
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_witness_above_this_log_is_not_a_fork() {
    let f = Fixture::new(1, 1).await;
    let size = f.size().await;
    f.witnesses[0].hold(Checkpoint {
        origin: f.log.origin().to_string(),
        size: size + 5,
        root: LogHash([3; 32]),
    });
    for _ in 0..2 {
        let reply = f.get(Some(&f.query)).await;
        expect_unavailable(&reply, Duration::from_millis(3500));
    }
    assert_eq!(
        f.witnesses[0].sizes(),
        [size],
        "one push, answered 409 with the larger size"
    );
    assert_eq!(f.witnesses[0].latest(f.log.origin()), size + 5);
    let events = f.events().await;
    let ahead = events
        .iter()
        .filter(
            |e| matches!(e, witness::WitnessEvent::Ahead { witness, .. } if *witness == size + 5),
        )
        .count();
    assert_eq!(ahead, 1, "the neutral line prints once: {events:?}");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, witness::WitnessEvent::Refused { .. })),
        "{events:?}"
    );
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_stalled_store_releases_the_owner() {
    let f = Fixture::new(1, 1).await;
    let size = f.size().await;
    let tree = f.app.tree().await.unwrap();
    let cp = Checkpoint {
        origin: f.log.origin().to_string(),
        size,
        root: tree.root(),
    };
    // An uncommitted insert of the full-key row holds the owner's upsert on a row lock.
    let line = f.witnesses[0].cosign(&cp, now_secs());
    let mut held = f.db.begin().await.unwrap();
    sqlx::query(witness::UPSERT)
        .bind(i64::try_from(size).unwrap())
        .bind(cp.root.to_string())
        .bind(f.policy.witnesses[0].key.vkey())
        .bind(line.to_string().trim_end())
        .execute(&mut *held)
        .await
        .unwrap();
    let reply = f.get(Some(&f.query)).await;
    expect_unavailable(&reply, Duration::from_millis(3500));
    until(
        "the owner is idle again",
        Duration::from_millis(2500),
        || f.app.owners.views().iter().all(|v| v.idle),
    )
    .await;
    // No pooled connection keeps the 2 s session limit, and none is stranded on the lock.
    let mut conns = vec![];
    for _ in 0..19 {
        conns.push(f.db.acquire().await.unwrap());
    }
    for conn in &mut conns {
        let limit: String = sqlx::query_scalar("SHOW statement_timeout")
            .fetch_one(&mut **conn)
            .await
            .unwrap();
        assert_eq!(limit, "0");
    }
    drop(conns);
    held.rollback().await.unwrap();
    until(
        "the owner left its cooldown",
        Duration::from_secs(5),
        || f.app.owners.views().iter().all(|v| !v.cooling()),
    )
    .await;
    let reply = f.get(Some(&f.query)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    f.verifies(&reply.body, &f.policy);
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_held_row_released_in_time_lets_the_store_commit() {
    let f = Fixture::new(1, 1).await;
    let size = f.size().await;
    let tree = f.app.tree().await.unwrap();
    let cp = Checkpoint {
        origin: f.log.origin().to_string(),
        size,
        root: tree.root(),
    };
    let line = f.witnesses[0].cosign(&cp, now_secs());
    let mut held = f.db.begin().await.unwrap();
    sqlx::query(witness::UPSERT)
        .bind(i64::try_from(size).unwrap())
        .bind(cp.root.to_string())
        .bind(f.policy.witnesses[0].key.vkey())
        .bind(line.to_string().trim_end())
        .execute(&mut *held)
        .await
        .unwrap();
    let (router, query) = (f.router.clone(), f.query.clone());
    let reader = tokio::spawn(async move { Fixture::get_with(router, Some(query)).await });
    // Release the row as soon as the owner's upsert waits on it: it can still commit in its 2 s step.
    let started = Instant::now();
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
             AND query ILIKE '%log_cosignatures%'",
        )
        .fetch_one(&f.db)
        .await
        .unwrap();
        if waiting > 0 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the upsert never waited"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    held.rollback().await.unwrap();
    let reply = reader.await.unwrap();
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply.elapsed <= Duration::from_millis(3500),
        "{:?}",
        reply.elapsed
    );
    f.verifies(&reply.body, &f.policy);
}

mod real;

mod blocking;

mod bounds;

mod fix1;

mod order;

mod relay;

mod readpool;

/// A device that is approved in the database, and a mine request it signs with a fresh nonce.
async fn mine_request(router: &Router, db: &PgPool, manifest: &str) -> Value {
    mine_request_as(router, db, manifest, "approved").await
}

/// The same for a device whose enrolment is in the given state.
async fn mine_request_as(router: &Router, db: &PgPool, manifest: &str, state: &str) -> Value {
    let key = open_pact_core::dev_key::generate();
    let device_key = PublicKey::from(&key);
    let pseudonym = Pseudonym::of(&device_key);
    testdb::device_in_state(db, pseudonym.as_str(), manifest, state).await;
    let mut request = Request::post("/v1/nonce")
        .header("content-type", "application/json")
        .body(Body::from("null"))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 40000))));
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let nonce: Value = serde_json::from_slice(&bytes).unwrap();
    let nonce = nonce["nonce"].as_str().unwrap().to_string();
    let statement =
        open_pact_core::device_auth_statement(DeviceAuthPurpose::LogMine, &pseudonym, &nonce);
    serde_json::to_value(MyEntriesRequest {
        pseudonym,
        nonce,
        device_key,
        signature: open_pact_core::Signature::sign(&key, &statement),
    })
    .unwrap()
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_timed_out_witness_bounds_the_mine_route() {
    let mut options = Options::new(1, 1);
    options.wait_ms = 1000;
    let f = Fixture::build(options).await;
    f.witnesses[0].set(Behaviour::Delay(Duration::from_secs(6)));
    f.append(1).await;
    let manifest = f.app.manifest.hash().as_str().to_string();
    let mut requests = vec![];
    for _ in 0..8 {
        requests.push(mine_request(&f.router, &f.db, &manifest).await);
    }
    let answers = futures_util::future::join_all(requests.into_iter().map(|request| {
        let router = f.router.clone();
        async move {
            let mut request = Request::post("/v1/log/mine")
                .header("content-type", "application/json")
                .body(Body::from(request.to_string()))
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 40000))));
            let response = router.oneshot(request).await.unwrap();
            (
                Instant::now(),
                response.status(),
                response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .map(|v| v.to_str().unwrap().to_string()),
            )
        }
    }))
    .await;
    let entries = f.app.owners.hooks().stamps("served_entered");
    assert_eq!(entries.len(), 8, "every mine entered the shared read path");
    let earliest = entries.iter().min().unwrap();
    for (at, status, retry) in answers {
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry.as_deref(), Some("5"));
        // The wait, the one-candidate bound, the scheduling margin and the entry spread.
        assert!(
            at.duration_since(*earliest) <= Duration::from_millis(1000 + 500 + 50 + 100),
            "a mine answered after {:?}",
            at.duration_since(*earliest)
        );
    }
}
