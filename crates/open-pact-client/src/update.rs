//! The newer-release notice that `status --online` prints. It asks GitHub for the latest release
//! and reports nothing when the check fails, so a slow or offline network never changes the status.

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

const CHECK_LIMIT: Duration = Duration::from_secs(3);
const OPT_OUT: &str = "OPEN_PACT_NO_UPDATE_CHECK";

#[derive(Debug, Serialize)]
pub struct Notice {
    pub current: String,
    pub latest: String,
    pub command: Option<&'static str>,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
}

impl Notice {
    pub(crate) fn line(&self) -> String {
        match self.command {
            Some(command) => format!(
                "open-pact-client {} is available. Update: {command}",
                self.latest
            ),
            None => {
                let mut line = format!("open-pact-client {} is available.", self.latest);
                let running = std::env::current_exe().ok();
                if let Some(block) = running.and_then(|exe| {
                    machine_upgrade(&exe, &crate::machine::machine_path(), &self.latest)
                }) {
                    line.push_str(&format!(
                        "\nUpgrade the machine client from an elevated Windows PowerShell 5.1 prompt (powershell.exe, not pwsh):\n{block}"
                    ));
                }
                line
            }
        }
    }
}

/// The upgrade block when `exe` is the machine client at `machine`: an administrator or IT
/// channel owns that copy, so the block is the one install block for the newer version.
fn machine_upgrade(exe: &Path, machine: &Path, latest: &str) -> Option<String> {
    if !crate::machine::same_windows_path(exe, machine) {
        return None;
    }
    Some(crate::machine::install_block(
        &semver::Version::parse(latest).ok()?,
    ))
}

fn latest_release_url() -> String {
    format!(
        "https://api.github.com/repos/{}/releases/latest",
        crate::machine::REPOSITORY
    )
}

pub(crate) fn latest_notice() -> Option<Notice> {
    let switch = std::env::var(OPT_OUT).ok();
    let exe = std::env::current_exe().ok();
    let url = latest_release_url();
    bounded(CHECK_LIMIT, move || async move {
        check(
            switch.as_deref(),
            &url,
            CHECK_LIMIT,
            env!("CARGO_PKG_VERSION"),
            exe.as_deref(),
        )
        .await
    })
}

/// Runs `work` on its own thread and waits at most `limit` for its answer. The thread is never
/// joined: a DNS lookup that it started cannot be cancelled, and the CLI runtime must not wait for it.
fn bounded<T, F, Fut>(limit: Duration, work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Option<T>>,
{
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let answer = runtime.block_on(work());
            let _ = send.send(answer);
        })
        .ok()?;
    receive.recv_timeout(limit).ok().flatten()
}

async fn check(
    switch: Option<&str>,
    url: &str,
    limit: Duration,
    current: &str,
    exe: Option<&Path>,
) -> Option<Notice> {
    if switch == Some("1") {
        return None;
    }
    let tag = fetch_tag(url, limit, current).await?;
    let text = tag.strip_prefix('v')?;
    let latest = semver::Version::parse(text).ok()?;
    if !latest.pre.is_empty() {
        return None;
    }
    if !latest
        .cmp_precedence(&semver::Version::parse(current).ok()?)
        .is_gt()
    {
        return None;
    }
    Some(Notice {
        current: current.into(),
        latest: text.into(),
        command: exe.and_then(|path| install_command(&path.to_string_lossy())),
    })
}

async fn fetch_tag(url: &str, limit: Duration, current: &str) -> Option<String> {
    let http = crate::http_client_with(limit, limit).ok()?;
    let release: Release = http
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            format!("open-pact-client/{current}"),
        )
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    Some(release.tag_name)
}

/// Homebrew and Scoop own their copies, so only they get a command. The desktop app updates its own copy.
fn install_command(exe: &str) -> Option<&'static str> {
    if exe.contains("/Cellar/") || exe.contains("/homebrew/") {
        Some("brew upgrade open-pact")
    } else if exe.to_ascii_lowercase().contains("\\scoop\\apps\\") {
        Some("scoop update open-pact")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const BREW: &str = "/opt/homebrew/Cellar/open-pact-client/0.6.0/bin/open-pact-client";

    /// CI builds without `OPEN_PACT_REPOSITORY`, so the default repository is the one asked.
    #[test]
    fn the_update_check_asks_this_repository_by_default() {
        assert_eq!(crate::machine::REPOSITORY, "gaboe/open-pact");
        assert_eq!(
            latest_release_url(),
            "https://api.github.com/repos/gaboe/open-pact/releases/latest"
        );
    }

    struct Mock {
        url: String,
        heads: Arc<Mutex<Vec<String>>>,
    }

    async fn mock(status: u16, reply: &'static str) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/releases/latest", listener.local_addr().unwrap());
        let heads = Arc::new(Mutex::new(Vec::new()));
        let seen = heads.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    head.extend_from_slice(&chunk[..n]);
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).to_lowercase());
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            }
        });
        Mock { url, heads }
    }

    async fn notice(reply: &'static str, current: &str) -> Option<Notice> {
        let mock = mock(200, reply).await;
        check(
            None,
            &mock.url,
            Duration::from_secs(3),
            current,
            Some(Path::new(BREW)),
        )
        .await
    }

    #[tokio::test]
    async fn a_newer_release_gives_a_notice_with_the_brew_command() {
        let mock = mock(200, r#"{"tag_name":"v0.6.1"}"#).await;
        let found = check(
            None,
            &mock.url,
            Duration::from_secs(3),
            "0.6.0",
            Some(Path::new(BREW)),
        )
        .await
        .unwrap();
        assert_eq!(
            found.line(),
            "open-pact-client 0.6.1 is available. Update: brew upgrade open-pact"
        );
        let heads = mock.heads.lock().unwrap();
        assert!(
            heads[0].contains("user-agent: open-pact-client/0.6.0\r\n"),
            "{heads:?}"
        );
    }

    #[tokio::test]
    async fn versions_compare_as_numbers_not_text() {
        let found = notice(r#"{"tag_name":"v0.10.0"}"#, "0.9.3").await.unwrap();
        assert_eq!(found.latest, "0.10.0");
    }

    #[tokio::test]
    async fn the_same_or_an_older_release_gives_no_notice() {
        assert!(notice(r#"{"tag_name":"v0.6.0"}"#, "0.6.0").await.is_none());
        assert!(notice(r#"{"tag_name":"v0.5.9"}"#, "0.6.0").await.is_none());
        assert!(
            notice(r#"{"tag_name":"v0.6.0"}"#, "0.6.0+build.1")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_stable_release_is_newer_than_the_release_candidate_before_it() {
        let found = notice(r#"{"tag_name":"v0.6.0"}"#, "0.6.0-rc.1")
            .await
            .unwrap();
        assert_eq!(found.latest, "0.6.0");
    }

    #[tokio::test]
    async fn build_metadata_on_the_running_version_does_not_hide_a_newer_release() {
        let found = notice(r#"{"tag_name":"v0.6.1"}"#, "0.6.0+build.1")
            .await
            .unwrap();
        assert_eq!(found.latest, "0.6.1");
    }

    #[tokio::test]
    async fn build_metadata_on_the_latest_release_does_not_make_it_newer() {
        assert!(
            notice(r#"{"tag_name":"v0.6.0+build.2"}"#, "0.6.0+build.1")
                .await
                .is_none()
        );
        assert!(
            notice(r#"{"tag_name":"v0.6.0+build.1"}"#, "0.6.0")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_malformed_or_failed_answer_gives_no_notice() {
        for (status, reply) in [
            (200, "not json"),
            (200, r#"{"name":"0.6.1"}"#),
            (200, r#"{"tag_name":"latest"}"#),
            (200, r#"{"tag_name":"v0.6"}"#),
            (200, r#"{"tag_name":"v0.6.1-rc.1"}"#),
            (500, r#"{"tag_name":"v0.6.1"}"#),
        ] {
            let mock = mock(status, reply).await;
            let found = check(None, &mock.url, Duration::from_secs(3), "0.6.0", None).await;
            assert!(found.is_none(), "{status} {reply}");
        }
    }

    #[test]
    fn an_answer_inside_the_limit_comes_back() {
        assert_eq!(bounded(CHECK_LIMIT, || async { Some(7) }), Some(7));
    }

    #[test]
    fn a_check_that_blocks_past_the_limit_gives_no_answer() {
        let start = std::time::Instant::now();
        let found: Option<u8> = bounded(CHECK_LIMIT, || async {
            std::thread::sleep(Duration::from_secs(10));
            Some(1)
        });
        assert!(found.is_none());
        assert!(
            start.elapsed() < CHECK_LIMIT + Duration::from_secs(1),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn a_silent_gateway_ends_at_the_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/releases/latest", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let start = std::time::Instant::now();
        let found = check(None, &url, Duration::from_millis(200), "0.6.0", None).await;
        assert!(found.is_none());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn the_opt_out_makes_no_request() {
        let mock = mock(200, r#"{"tag_name":"v0.6.1"}"#).await;
        let found = check(Some("1"), &mock.url, Duration::from_secs(3), "0.6.0", None).await;
        assert!(found.is_none());
        assert!(mock.heads.lock().unwrap().is_empty());
    }

    #[test]
    fn install_paths_name_their_update_command() {
        assert_eq!(
            install_command("/usr/local/Cellar/open-pact-client/0.6.0/bin/x"),
            Some("brew upgrade open-pact")
        );
        assert_eq!(
            install_command("/opt/homebrew/bin/open-pact-client"),
            Some("brew upgrade open-pact")
        );
        assert_eq!(
            install_command(r"C:\Users\me\scoop\apps\open-pact\current\open-pact-client.exe"),
            Some("scoop update open-pact")
        );
        assert_eq!(
            install_command(r"C:\Users\me\SCOOP\APPS\open-pact\open-pact-client.exe"),
            Some("scoop update open-pact")
        );
        assert_eq!(
            install_command("/Applications/Open Pact.app/Contents/MacOS/open-pact-client"),
            None
        );
        assert_eq!(
            install_command(r"C:\Program Files\Open Pact\open-pact-client.exe"),
            None
        );
    }

    #[test]
    fn only_the_machine_client_gets_the_install_block() {
        let machine = Path::new(r"C:\Program Files\open-pact-client\open-pact-client.exe");
        let block = machine_upgrade(machine, machine, "0.9.1").unwrap();
        assert_eq!(
            block,
            crate::machine::install_block(&semver::Version::new(0, 9, 1))
        );
        assert!(block.contains("releases/download/v0.9.1"));
        assert!(
            machine_upgrade(
                Path::new(r"C:\Users\me\open-pact-client.exe"),
                machine,
                "0.9.1"
            )
            .is_none()
        );
        assert!(machine_upgrade(machine, machine, "latest").is_none());
    }

    #[test]
    fn the_line_drops_the_update_part_without_a_command() {
        let found = Notice {
            current: "0.6.0".into(),
            latest: "0.6.1".into(),
            command: None,
        };
        assert_eq!(found.line(), "open-pact-client 0.6.1 is available.");
    }
}
