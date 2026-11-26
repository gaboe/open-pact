//! S1 with the real client: a gateway on a socket, a device that enrols and claims through
//! `open_pact_client::run`, and the files the client leaves in its home.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;

use open_pact_client::{Command, Invocation, LogCommand};
use open_pact_core::{Checkpoint, Invitation, WitnessKey};

use super::*;

pub(super) struct Live {
    pub url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Live {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) struct Device {
    pub home: tempfile::TempDir,
}

impl Device {
    pub fn certificate(&self) -> PathBuf {
        self.home.path().join("vpn-cert.pem")
    }

    pub fn installed(&self) -> bool {
        self.certificate().exists()
    }

    /// The `log_checkpoint` of the newest reply the client kept, if it kept one.
    pub fn reply_note(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.home.path().join("claims.jsonl")).ok()?;
        text.lines().filter_map(find_note).next_back()
    }
}

fn find_note(line: &str) -> Option<String> {
    let record: Value = serde_json::from_str(line).ok()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(record["response_b64"].as_str()?)
        .ok()?;
    let reply: Value = serde_json::from_slice(&bytes).ok()?;
    reply["log_checkpoint"].as_str().map(str::to_owned)
}

impl Fixture {
    pub async fn real() -> Fixture {
        let mut options = Options::new(1, 1);
        options.real_client = true;
        Fixture::build(options).await
    }

    /// `count` devices enrolled through the client, then the current size witnessed by a read.
    pub async fn enrolled(&self, live: &Live, count: usize) -> Vec<Arc<Device>> {
        self.enrolled_under(live, count, &self.query).await
    }

    /// The same, with the witnessing read made under the policy `query` names.
    pub async fn enrolled_under(&self, live: &Live, count: usize, query: &str) -> Vec<Arc<Device>> {
        let devices = futures_util::future::join_all((0..count).map(|_| self.enrol(live))).await;
        let reply = self.get(Some(query)).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        devices.into_iter().map(Arc::new).collect()
    }

    pub async fn live(&self) -> Live {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let service = router(self.app.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, service).await;
        });
        Live { url, task }
    }

    async fn invitation(&self, url: &str) -> String {
        let (code, _) = invitations::create(&self.db, time::Duration::hours(1), "fixture")
            .await
            .unwrap();
        let company = PublicKey::from(&self.app.keys.manifest);
        Invitation::new(url, &company, &self.log, code).encode()
    }

    /// Enrols a device through the client. The gateway approves it at once.
    pub async fn enrol(&self, live: &Live) -> Device {
        let invitation = self.invitation(&live.url).await;
        let (device, code) = join_with(invitation).await;
        let code = match code {
            Ok(code) => code,
            Err(e) => {
                let pushes: Vec<(u64, u64, u16)> = self.witnesses[0]
                    .received()
                    .iter()
                    .map(|r| (r.size, r.old_size, r.status))
                    .collect();
                panic!("the join failed: {e:#}; witness record {pushes:?}")
            }
        };
        assert_eq!(code, ExitCode::SUCCESS, "the join failed");
        device
    }

    /// A manual check: preflight, claim, certificate. The exit code is the client's.
    pub async fn claim(device: &Device) -> ExitCode {
        open_pact_client::run(
            Invocation {
                home: Some(device.home.path().to_path_buf()),
                insecure_dev: true,
                command: Command::Check {
                    dry_run: false,
                    timings: true,
                    json: false,
                },
            },
            std::path::Path::new("open-pact-client"),
        )
        .await
        .unwrap()
    }
}

impl Fixture {
    /// Two witnesses; the manifest lists the first (Old). `new_manifest` lists the second.
    pub async fn two_policies() -> Fixture {
        let mut options = Options::new(2, 1);
        options.real_client = true;
        options.listed = Some(vec![0]);
        Fixture::build(options).await
    }

    pub fn manifest_of(&self, keys: &[&WitnessKey], quorum: usize) -> String {
        let listed: Vec<String> = keys.iter().map(|k| listed_entry(k)).collect();
        manifest_text(&listed, quorum, false, true)
    }

    pub fn policy_in(&self, toml: &str) -> LogPolicy {
        Manifest::parse(toml.as_bytes())
            .unwrap()
            .body()
            .log
            .clone()
            .unwrap()
    }

    /// The gateway enforces `toml` from now on; waits until every owner drained the reload.
    pub async fn enforce(&self, toml: &str) {
        let hooks = self.app.owners.hooks();
        let before = hooks.count("reload_drained");
        manifests::set_for_test(&self.db, &self.app.keys, toml).await;
        reload_manifest(&self.app).await.unwrap();
        let owners = self.app.owners.views().len();
        until(
            "the owners drained the reload",
            Duration::from_secs(10),
            || hooks.count("reload_drained") >= before + owners,
        )
        .await;
    }

    /// A gateway process started again on the same database: new caches, new owners, and only the
    /// enforced manifest's keys.
    pub async fn restarted(&self) -> App {
        let row = manifests::active(&self.db).await.unwrap().unwrap();
        let enforced =
            Arc::new(manifests::enforced(&row.toml, &self.app.keys, Some(row.version)).unwrap());
        let current = Arc::new(RwLock::new(enforced.clone()));
        let urls = witness::normalize_urls(self.witnesses.iter().map(|w| w.url.clone()).collect());
        let owners = Owners::start(
            urls,
            enforced.log.witnesses.keys().to_vec(),
            current.clone(),
            self.db.clone(),
            self.app.read_db.clone(),
            None,
        )
        .unwrap();
        App {
            enforced,
            current,
            owners: Arc::new(owners),
            ..self.app.clone()
        }
    }

    /// Serves `app` on the address `live` had, after `live` stopped.
    pub async fn live_again(app: App, mut live: Live) -> Live {
        let addr = live.url.trim_start_matches("http://").to_string();
        live.task.abort();
        let _ = live.task_done().await;
        let mut tries = 0;
        let listener = loop {
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => break listener,
                Err(error) => {
                    tries += 1;
                    assert!(tries < 100, "{addr}: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };
        let service = router(app).into_make_service_with_connect_info::<SocketAddr>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, service).await;
        });
        Live {
            url: format!("http://{addr}"),
            task,
        }
    }

    /// A line of `key` for the tree this gateway holds, stored as an owner would.
    pub async fn seed_line(&self, key: &(ed25519_dalek::SigningKey, WitnessKey)) {
        let tree = self.app.tree().await.unwrap();
        let cp = Checkpoint {
            origin: self.log.origin().to_string(),
            size: tree.size(),
            root: tree.root(),
        };
        let line = key.1.cosign(&key.0, &cp, now_secs());
        sqlx::query(witness::UPSERT)
            .bind(i64::try_from(cp.size).unwrap())
            .bind(cp.root.to_string())
            .bind(key.1.vkey())
            .bind(line.to_string().trim_end())
            .execute(&self.db)
            .await
            .unwrap();
    }
}

impl Live {
    async fn task_done(&mut self) -> Result<(), tokio::task::JoinError> {
        (&mut self.task).await
    }
}

/// The client's join with this invitation, in a new home.
async fn join_with(invitation: String) -> (Device, anyhow::Result<ExitCode>) {
    let device = Device {
        home: tempfile::tempdir().unwrap(),
    };
    let code = open_pact_client::run(
        Invocation {
            home: Some(device.home.path().to_path_buf()),
            insecure_dev: true,
            command: Command::Join {
                invitation: Some(invitation),
                yes: true,
                software_key: true,
                no_wait: false,
                preview: false,
                json: false,
                folders: vec![],
                auto_send: None,
            },
        },
        std::path::Path::new("open-pact-client"),
    )
    .await;
    (device, code)
}

pub(super) fn spawn_claim(device: &Arc<Device>) -> tokio::task::JoinHandle<()> {
    let device = device.clone();
    tokio::spawn(async move {
        let _ = Fixture::claim(&device).await;
    })
}

impl Device {
    /// The witness lines of the kept reply: how many, and whether the log's line is first.
    pub fn reply_lines(&self, origin: &str) -> (usize, bool) {
        let note = self.reply_note().expect("the client kept the reply");
        let lines: Vec<&str> = note.lines().filter(|l| l.starts_with("— ")).collect();
        let witnesses = lines
            .iter()
            .filter(|l| l.starts_with("— witness.example.org/"))
            .count();
        (
            witnesses,
            lines
                .first()
                .is_some_and(|l| l.starts_with(&format!("— {origin}"))),
        )
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_real_client_claim_installs_its_certificate() {
    let f = Fixture::real().await;
    let live = f.live().await;
    let devices = f.enrolled(&live, 1).await;
    let code = Fixture::claim(&devices[0]).await;
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(devices[0].installed());
    let note = devices[0].reply_note().expect("the client kept the reply");
    f.verifies(&note, &f.policy);
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn an_accepted_claim_reply_keeps_the_log_signature() {
    // Case 1: one witness, quorum 1.
    let f = Fixture::real().await;
    let live = f.live().await;
    let devices = f.enrolled(&live, 1).await;
    let _ = Fixture::claim(&devices[0]).await;
    assert!(devices[0].installed());
    let note = devices[0].reply_note().expect("the client kept the reply");
    f.verifies(&note, &f.policy);
    assert_eq!(devices[0].reply_lines(f.log.origin()), (1, true), "{note}");
    // Case 2: a manifest that allows split views and lists no witness.
    let mut options = Options::new(0, 0);
    options.real_client = true;
    options.split_views = true;
    let g = Fixture::build(options).await;
    let live = g.live().await;
    let devices = g.enrolled(&live, 1).await;
    let _ = Fixture::claim(&devices[0]).await;
    assert!(devices[0].installed());
    let note = devices[0].reply_note().expect("the client kept the reply");
    assert!(g.log.verify(&Note::parse(&note).unwrap()).is_ok(), "{note}");
    assert_eq!(devices[0].reply_lines(g.log.origin()), (0, true), "{note}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_failed_lead_leaves_its_follower_queued() {
    let f = Fixture::real().await;
    let live = f.live().await;
    let devices = f.enrolled(&live, 2).await;
    let before = f.size().await;
    let size = before + 1;
    let hooks = f.app.owners.hooks();
    let committed = hooks.arm_always("claim_committed");
    let c1 = spawn_claim(&devices[0]);
    committed.reached().await;
    let c2 = spawn_claim(&devices[1]);
    committed.reached().await;
    f.append(1).await;
    let fanouts = f.app.owners.fanouts.load(Ordering::SeqCst);
    let commit = hooks.arm("dispatch_commit_entered");
    committed.release();
    commit.reached().await;
    // The second claim reads the same size not fresh and short, and queues its own Push.
    f.app.log.witnesses.force_retry();
    committed.disarm();
    until("the follower's fan-out", Duration::from_secs(60), || {
        f.app.owners.fanouts.load(Ordering::SeqCst) == fanouts + 2
    })
    .await;
    f.witnesses[0].set(Behaviour::AnswerOnce(500));
    commit.release();
    c1.await.unwrap();
    c2.await.unwrap();
    let at_size: Vec<u16> = f.witnesses[0]
        .received()
        .iter()
        .filter(|r| r.size == size)
        .map(|r| r.status)
        .collect();
    assert_eq!(at_size, [500, 200]);
    assert!(!devices[0].installed(), "the lead has no witness line");
    assert_eq!(devices[0].reply_lines(f.log.origin()), (0, true));
    assert!(devices[1].installed());
    let note = devices[1].reply_note().unwrap();
    assert_eq!(f.verifies(&note, &f.policy).size, size);
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_complete_quorum_claim_answers_its_first_read() {
    let f = Fixture::real().await;
    let live = f.live().await;
    let devices = f.enrolled(&live, 2).await;
    let size = f.size().await + 1;
    let hooks = f.app.owners.hooks();
    let committed = hooks.arm_always("claim_committed");
    let c1 = spawn_claim(&devices[0]);
    committed.reached().await;
    let c2 = spawn_claim(&devices[1]);
    committed.reached().await;
    f.append(1).await;
    let read = hooks.arm_always("checkpoint_tree_read");
    committed.release();
    read.reached().await;
    committed.release();
    read.reached().await;
    // The first claim makes the size fresh, pushes it and stores its line.
    read.release();
    c1.await.unwrap();
    assert!(devices[0].installed());
    // Every database step of the second claim after its first read of the stored lines fails.
    let reads = hooks.count("stored_lines_read");
    hooks.fail_after_reads(1);
    let answered = hooks.arm("claim_checkpointed");
    read.disarm();
    // The claim's own steps fail; the client's later verification reads are not part of the check.
    answered.reached().await;
    hooks.clear_fault();
    answered.release();
    c2.await.unwrap();
    assert_eq!(
        hooks.count("stored_lines_read"),
        reads + 1,
        "one read, no fallback"
    );
    assert!(devices[1].installed());
    let note = devices[1].reply_note().unwrap();
    assert_eq!(f.verifies(&note, &f.policy).size, size);
    assert_eq!(
        f.witnesses[0]
            .sizes()
            .iter()
            .filter(|s| **s == size)
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_claim_reply_verifies_under_the_consented_policy() {
    let f = Fixture::two_policies().await;
    let old = f.policy.clone();
    let live = f.live().await;
    let devices = f.enrolled(&live, 1).await;
    let new = f.manifest_of(&[&f.witnesses[1].inner.key], 1);
    f.enforce(&new).await;
    f.append(1).await;
    let _ = Fixture::claim(&devices[0]).await;
    assert!(
        devices[0].installed(),
        "the client installs its certificate"
    );
    let note = devices[0].reply_note().expect("the client kept the reply");
    f.verifies(&note, &old);
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_restarted_gateway_accepts_the_consented_witness_line() {
    let f = Fixture::two_policies().await;
    let old = f.policy.clone();
    let live = f.live().await;
    let devices = f.enrolled(&live, 1).await;
    let new = f.manifest_of(&[&f.witnesses[1].inner.key], 1);
    f.enforce(&new).await;
    // Process 1 still knows Old's key: it stores a fresh Old quorum at the current size.
    let stored = f.get(Some(&encode(&old))).await;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.body);
    let size = f.size().await;
    // Process 2 starts on New with the same database and both URLs: only New's key is enforced.
    let restarted = f.restarted().await;
    let owners = restarted.owners.clone();
    let _live = Fixture::live_again(restarted, live).await;
    let committed = owners.hooks().arm("claim_committed");
    let claim = spawn_claim(&devices[0]);
    committed.reached().await;
    f.append(1).await;
    committed.release();
    claim.await.unwrap();
    assert!(
        devices[0].installed(),
        "the client installs its certificate"
    );
    let note = devices[0].reply_note().expect("the client kept the reply");
    assert_eq!(f.verifies(&note, &old).size, size + 1);
    // A started owner knows no size: its first push says 0 and gets a 409 with the witness's size,
    // then the one retry from that size is the accepted push.
    let statuses: Vec<u16> = f.witnesses[0]
        .received()
        .iter()
        .filter(|r| r.size == size + 1)
        .map(|r| r.status)
        .collect();
    assert_eq!(statuses, [409, 200]);
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_rotated_witness_key_is_not_reused_for_a_claim() {
    let f = Fixture::real().await;
    let live = f.live().await;
    let new_key = f.witnesses[0].rotated([77; 32]);
    let new = f.manifest_of(&[&new_key.1], 1);
    let new_policy = f.policy_in(&new);
    // New's key signs from the reload on, so no push the reload wakes is signed by Old.
    f.witnesses[0].script(vec![new_key.clone()]);
    f.enforce(&new).await;
    let devices = f.enrolled_under(&live, 1, &encode(&new_policy)).await;
    let hooks = f.app.owners.hooks();
    let committed = hooks.arm("claim_committed");
    let claim = spawn_claim(&devices[0]);
    committed.reached().await;
    // An Old replica answers at the same URL: the owner stores its line and keeps it as `last`.
    f.append(1).await;
    let size = f.size().await;
    f.witnesses[0].script(vec![f.witnesses[0].original()]);
    f.app.owners.refresh_all();
    until(
        "the owner stored the Old line",
        Duration::from_secs(10),
        || f.witnesses[0].sizes().last() == Some(&size),
    )
    .await;
    until("the owner is idle", Duration::from_secs(5), || {
        f.app.owners.views().iter().all(|v| v.idle)
    })
    .await;
    f.witnesses[0].script(vec![new_key.clone()]);
    committed.release();
    claim.await.unwrap();
    let at_size: Vec<u16> = f.witnesses[0]
        .received()
        .iter()
        .filter(|r| r.size == size)
        .map(|r| r.status)
        .collect();
    assert_eq!(
        at_size,
        [200, 200],
        "the claim's Push is sent, not answered from the Old line"
    );
    assert!(devices[0].installed());
    let note = devices[0].reply_note().unwrap();
    assert_eq!(f.verifies(&note, &new_policy).size, size);
    let read = f.get(Some(&encode(&new_policy))).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_same_size_follower_gets_its_own_key() {
    let f = Fixture::real().await;
    let live = f.live().await;
    let old_policy = f.policy.clone();
    let old_key = f.witnesses[0].original();
    let new_key = f.witnesses[0].rotated([77; 32]);
    let d1 = f.enrolled(&live, 1).await;
    let new = f.manifest_of(&[&new_key.1], 1);
    let new_policy = f.policy_in(&new);
    f.witnesses[0].script(vec![new_key.clone()]);
    f.enforce(&new).await;
    let d2 = f.enrolled_under(&live, 1, &encode(&new_policy)).await;
    // Both policies have a quorum at the current size: the preflights pass without the owner.
    f.seed_line(&old_key).await;
    f.seed_line(&new_key).await;
    for (policy, device) in [(&old_policy, &d1), (&new_policy, &d2)] {
        let _ = device;
        let reply = f.get(Some(&encode(policy))).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    }
    let hooks = f.app.owners.hooks();
    let committed = hooks.arm_always("claim_committed");
    let c1 = spawn_claim(&d1[0]);
    committed.reached().await;
    let c2 = spawn_claim(&d2[0]);
    committed.reached().await;
    f.append(1).await;
    let size = f.size().await;
    let fanouts = f.app.owners.fanouts.load(Ordering::SeqCst);
    let commit = hooks.arm("dispatch_commit_entered");
    committed.release();
    commit.reached().await;
    f.app.log.witnesses.force_retry();
    committed.disarm();
    until("the New claim's fan-out", Duration::from_secs(60), || {
        f.app.owners.fanouts.load(Ordering::SeqCst) == fanouts + 2
    })
    .await;
    f.witnesses[0].script(vec![old_key.clone(), new_key.clone()]);
    commit.release();
    c1.await.unwrap();
    c2.await.unwrap();
    let at_size: Vec<(u16, u64)> = f.witnesses[0]
        .received()
        .iter()
        .filter(|r| r.size == size)
        .map(|r| (r.status, r.old_size))
        .collect();
    assert_eq!(at_size, [(200, size - 1), (200, size)]);
    assert!(d1[0].installed());
    let old_note = d1[0].reply_note().unwrap();
    assert_eq!(f.verifies(&old_note, &old_policy).size, size);
    assert!(d2[0].installed());
    let new_note = d2[0].reply_note().unwrap();
    assert_eq!(f.verifies(&new_note, &new_policy).size, size);
    let read = f.get(Some(&encode(&new_policy))).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_base_tree_read_keeps_base_limits() {
    let mut options = Options::new(1, 1);
    options.real_client = true;
    options.wait_ms = 1000;
    let f = Fixture::build(options).await;
    let live = f.live().await;
    let devices = f.enrolled(&live, 1).await;
    let before = f.size().await;
    let hooks = f.app.owners.hooks();
    let committed = hooks.arm("claim_committed");
    let claim = spawn_claim(&devices[0]);
    committed.reached().await;
    // A real enrolment at a fresh size, held at the top of its checkpoint.
    let entered = hooks.arm("checkpoint_entered");
    let enrolment = {
        let live_url = live.url.clone();
        let invitation = f.invitation(&live_url).await;
        tokio::spawn(async move { join_with(invitation).await.1.unwrap() })
    };
    entered.reached().await;
    // Every tree SELECT now waits on the table lock.
    let mut lock = f.db.begin().await.unwrap();
    sqlx::query("LOCK TABLE log_entries IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    entered.release();
    let blocked = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
             AND query ILIKE '%log_entries%' AND query NOT ILIKE '%pg_stat_activity%'",
        )
        .fetch_one(&f.db)
        .await
        .unwrap()
    };
    // The lock transaction holds its own connection; wait on a second one.
    let started = Instant::now();
    while blocked().await == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "no SELECT waits on the lock"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The lock is released 3 s after the first SELECT was seen waiting, inside the client's limit.
    let locked_at = Instant::now();
    committed.release();
    let router = f.router.clone();
    let proof = tokio::spawn(async move {
        router
            .oneshot(
                Request::get(format!(
                    "/v1/log/proof/consistency?from={}&to={}",
                    before - 1,
                    before
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap()
    });
    let reader = f.get(Some(&f.query)).await;
    tokio::time::sleep(Duration::from_secs(3).saturating_sub(locked_at.elapsed())).await;
    lock.rollback().await.unwrap();
    expect_unavailable(&reader, Duration::from_millis(1000 + 500 + 50));
    let proof = proof.await.unwrap();
    assert_eq!(proof.status(), StatusCode::OK);
    let body = axum::body::to_bytes(proof.into_body(), 1 << 20)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let hashes: Vec<open_pact_core::LogHash> =
        serde_json::from_value(value["proof"].clone()).unwrap();
    let tree = f.app.tree().await.unwrap();
    open_pact_core::verify_consistency(
        before - 1,
        before,
        &tree.root_at(before - 1),
        &tree.root_at(before),
        &hashes,
    )
    .unwrap();
    claim.await.unwrap();
    assert!(devices[0].installed());
    assert_eq!(
        enrolment.await.unwrap(),
        ExitCode::SUCCESS,
        "the enrolment answered 200"
    );
    let after = f.get(Some(&f.query)).await;
    assert_eq!(after.status, StatusCode::OK, "{}", after.body);
    f.verifies(&after.body, &f.policy);
}

/// Rounds of the burst. Each real client command takes seconds in a test build.
const BURST_ROUNDS: usize = 3;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn checkpoints_during_a_join_burst_are_witnessed() {
    let mut options = Options::new(2, 2);
    options.real_client = true;
    let f = Fixture::build(options).await;
    let live = f.live().await;
    // Four devices claim every round and four others prove their enrolment (a mine request).
    let devices = f.enrolled(&live, 8).await;
    for round in 0..BURST_ROUNDS {
        f.append(1).await;
        let mut invitations = vec![];
        for _ in 0..4 {
            invitations.push(f.invitation(&live.url).await);
        }
        let enrolments = invitations
            .into_iter()
            .map(|invitation| tokio::spawn(async move { join_with(invitation).await.1.unwrap() }))
            .collect::<Vec<_>>();
        let claims = devices[..4].iter().map(spawn_claim).collect::<Vec<_>>();
        let proves = devices[4..]
            .iter()
            .map(|device| {
                let device = device.clone();
                tokio::spawn(async move {
                    let mut codes = vec![];
                    for _ in 0..2 {
                        let code = open_pact_client::run(
                            Invocation {
                                home: Some(device.home.path().to_path_buf()),
                                insecure_dev: true,
                                command: Command::Log {
                                    command: LogCommand::Prove { index: None },
                                },
                            },
                            std::path::Path::new("open-pact-client"),
                        )
                        .await
                        .unwrap();
                        codes.push(code);
                    }
                    codes
                })
            })
            .collect::<Vec<_>>();
        let reads = futures_util::future::join_all(
            (0..32).map(|_| Fixture::get_with(f.router.clone(), Some(f.query.clone()))),
        );
        let (reads, enrolments, claims, proves) = tokio::join!(
            reads,
            futures_util::future::join_all(enrolments),
            futures_util::future::join_all(claims),
            futures_util::future::join_all(proves),
        );
        for reply in reads {
            assert_eq!(
                reply.status,
                StatusCode::OK,
                "round {round}: {}",
                reply.body
            );
            f.verifies(&reply.body, &f.policy);
        }
        for code in enrolments {
            assert_eq!(
                code.unwrap(),
                ExitCode::SUCCESS,
                "round {round}: an enrolment failed"
            );
        }
        for claim in claims {
            claim.unwrap();
        }
        for device in &devices[..4] {
            assert!(
                device.installed(),
                "round {round}: a claim installed no certificate"
            );
            let note = device.reply_note().expect("the client kept the reply");
            f.verifies(&note, &f.policy);
        }
        for codes in proves {
            for code in codes.unwrap() {
                assert_eq!(code, ExitCode::SUCCESS, "round {round}: a mine failed");
            }
        }
    }
    f.sizes_are_non_decreasing();
    f.assert_no_fork_line().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
async fn a_claim_push_ignores_the_cooldown() {
    let f = Fixture::real().await;
    let live = f.live().await;
    let devices = f.enrolled(&live, 1).await;
    let hooks = f.app.owners.hooks();
    // The preflight runs at a witnessed size; the claim is held after it.
    let committed = hooks.arm("claim_committed");
    let claim = spawn_claim(&devices[0]);
    committed.reached().await;
    // A failed renewal at that size puts the owner into its cooldown.
    f.witnesses[0].set(Behaviour::Answer(500));
    f.app.owners.refresh_all();
    until("the renewal failed", Duration::from_secs(5), || {
        f.app.owners.views().iter().all(|v| v.cooling())
    })
    .await;
    f.witnesses[0].set(Behaviour::Healthy);
    f.append(1).await;
    let size = f.size().await;
    committed.release();
    claim.await.unwrap();
    let failed_at = f.witnesses[0]
        .received()
        .iter()
        .find(|r| r.status == 500)
        .map(|r| r.at)
        .expect("the renewal reached the witness");
    let claim_push = f.witnesses[0]
        .received()
        .into_iter()
        .find(|r| r.size == size)
        .expect("the claim's push reached the witness");
    assert!(
        claim_push.arrived.duration_since(failed_at) < Duration::from_millis(1000),
        "the claim waited for the cooldown: {:?}",
        claim_push.arrived.duration_since(failed_at)
    );
    assert_eq!(claim_push.status, 200);
    assert!(devices[0].installed());
}
