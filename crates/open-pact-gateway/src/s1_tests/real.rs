//! S1 with the real client: a gateway on a socket, a device that enrols and claims through
//! `open_pact_client::run`, and the files the client leaves in its home.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;

use open_pact_client::{Command, Invocation};
use open_pact_core::Invitation;

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
        text.lines().filter_map(find_note).last()
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
        let devices = futures_util::future::join_all((0..count).map(|_| self.enrol(live))).await;
        let reply = self.get(Some(&self.query)).await;
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
        .await
        .unwrap();
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

pub(super) fn spawn_claim(device: &Arc<Device>) -> tokio::task::JoinHandle<ExitCode> {
    let device = device.clone();
    tokio::spawn(async move { Fixture::claim(&device).await })
}

impl Device {
    /// The witness lines of the kept reply: how many, and whether the log's line is first.
    pub fn reply_lines(&self) -> (usize, bool) {
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
                .is_some_and(|l| l.starts_with("— log.example.org/")),
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
    Fixture::claim(&devices[0]).await;
    assert!(devices[0].installed());
    let note = devices[0].reply_note().expect("the client kept the reply");
    f.verifies(&note, &f.policy);
    assert_eq!(devices[0].reply_lines(), (1, true), "{note}");
    // Case 2: a manifest that allows split views and lists no witness.
    let mut options = Options::new(0, 0);
    options.real_client = true;
    options.split_views = true;
    let g = Fixture::build(options).await;
    let live = g.live().await;
    let devices = g.enrolled(&live, 1).await;
    Fixture::claim(&devices[0]).await;
    assert!(devices[0].installed());
    let note = devices[0].reply_note().expect("the client kept the reply");
    assert!(g.log.verify(&Note::parse(&note).unwrap()).is_ok(), "{note}");
    assert_eq!(devices[0].reply_lines(), (0, true), "{note}");
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
    assert_eq!(devices[0].reply_lines(), (0, true));
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
