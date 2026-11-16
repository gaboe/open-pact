//! The newer-release notice that `status --online` prints. It asks GitHub for the latest release
//! and reports nothing when the check fails, so a slow or offline network never changes the status.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

const LATEST_RELEASE: &str = "https://api.github.com/repos/gaboe/open-pact/releases/latest";
const CHECK_LIMIT: Duration = Duration::from_secs(3);
const OPT_OUT: &str = "OPEN_PACT_NO_UPDATE_CHECK";

#[derive(Debug, Serialize)]
pub(crate) struct Notice {
    pub(crate) current: String,
    pub(crate) latest: String,
    pub(crate) command: Option<&'static str>,
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
            None => format!("open-pact-client {} is available.", self.latest),
        }
    }
}

pub(crate) async fn latest_notice() -> Option<Notice> {
    let switch = std::env::var(OPT_OUT).ok();
    let exe = std::env::current_exe().ok();
    check(
        switch.as_deref(),
        LATEST_RELEASE,
        CHECK_LIMIT,
        env!("CARGO_PKG_VERSION"),
        exe.as_deref(),
    )
    .await
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
    let latest = tag.strip_prefix('v')?;
    if parse_semver(latest)? <= parse_semver(current)? {
        return None;
    }
    Some(Notice {
        current: current.into(),
        latest: latest.into(),
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

fn parse_semver(text: &str) -> Option<[u64; 3]> {
    let mut parts = text.split('.');
    let mut version = [0; 3];
    for slot in &mut version {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(version)
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
    fn the_line_drops_the_update_part_without_a_command() {
        let found = Notice {
            current: "0.6.0".into(),
            latest: "0.6.1".into(),
            command: None,
        };
        assert_eq!(found.line(), "open-pact-client 0.6.1 is available.");
    }

    #[test]
    fn semver_reads_three_numbers_only() {
        assert_eq!(parse_semver("0.6.1"), Some([0, 6, 1]));
        for text in ["0.6", "0.6.1.2", "0.6.x", "0.6.+1", "", "0..1"] {
            assert_eq!(parse_semver(text), None, "{text}");
        }
    }
}
