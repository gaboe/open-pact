//! The typed API of the client for an app. A [`Session`] runs the same code as the CLI and returns
//! the same documents as the `--json` commands, as values. Nothing reads a terminal, installs a
//! signal handler or ends the process; the text a command would print is dropped.
//!
//! The caller owns the runtime. The CLI builds its runtime on a thread with an 8 MiB stack, because
//! the debug futures overflow the 1 MiB main stack of Windows: an app should do the same.

use std::future::Future;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

use crate::device_config;
use crate::json_out::{self, Answers, Json};
use crate::{
    APPROVAL_POLL_INTERVAL, AcceptPreview, ClaimReport, Home, Host, JoinOptions, JoinPreview,
    JoinResult, JoinStep, host, status,
};

/// The owner's answers to the questions of `join`, which the CLI asks on a terminal.
#[derive(Clone, Debug, Default)]
pub struct JoinChoices {
    /// Keep a new device key in a file (trust level L0) even when a Secure Enclave is available.
    pub software_key: bool,
    /// Stop after the enrolment instead of waiting for IT to approve the device.
    pub no_wait: bool,
    /// Send claims automatically, as the signed manifest allows.
    pub auto_send: bool,
    /// Folders that hold the owner's repositories, for the manifest's repository checks.
    pub folders: Vec<PathBuf>,
}

/// The error of a call that its caller's cancel future ended.
#[derive(Debug)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}

impl std::error::Error for Cancelled {}

/// One device home, and the installed client that the OS job runs.
///
/// Keep one call in flight per home. The claim lock keeps two calls, or a call and the job, from
/// writing the same files, but it makes the later one wait.
#[derive(Clone, Debug)]
pub struct Session {
    home: Home,
    cli: PathBuf,
    insecure_dev: bool,
}

impl Session {
    /// The session of `home` (the default home when `None`). `cli` is the installed
    /// `open-pact-client` that the OS job runs and the VPN probe starts, never the app itself.
    pub fn open(home: Option<PathBuf>, cli: PathBuf) -> Result<Session> {
        Ok(Session {
            home: Home::new(home)?,
            cli,
            insecure_dev: false,
        })
    }

    /// Allow a plain http:// gateway other than localhost. For development only.
    pub fn insecure_dev(mut self, allow: bool) -> Session {
        self.insecure_dev = allow;
        self
    }

    /// Where this session keeps its files.
    pub fn home(&self) -> &Path {
        &self.home.0
    }

    /// The device status. With `online` it also asks the gateway, the VPN probe and the OS.
    pub async fn status(&self, online: bool) -> Result<status::Report> {
        status::report(&self.home, online, self.insecure_dev, &self.cli).await
    }

    /// What joining would sign. Makes GET requests only and writes no file.
    pub async fn join_preview(&self, invitation: &str) -> Result<JoinPreview> {
        let (preview, _) = json_out::scope(
            Json::observed(Answers::default(), |_| {}),
            crate::join_preview(&self.home, invitation, self.insecure_dev),
        )
        .await?;
        Ok(preview)
    }

    /// Joins with the owner's answers given up front. `on_step` hears each wizard step. When
    /// `cancel` completes, the join ends at once with [`Cancelled`], with or without `no_wait`.
    /// A repository scan that already runs on a blocking thread keeps that thread until its read
    /// returns.
    pub async fn join(
        &self,
        invitation: &str,
        choices: JoinChoices,
        cancel: impl Future<Output = ()>,
        on_step: impl FnMut(JoinStep) + Send + 'static,
    ) -> Result<JoinResult> {
        let JoinChoices {
            software_key,
            no_wait,
            auto_send,
            folders,
        } = choices;
        // The CLI normalizes its folders before the join starts. So does a session, so that the
        // folder API finds the same paths again.
        let folders = join_folders(folders)?;
        let json = Json::observed(Answers { auto_send, folders }, on_step);
        let options = JoinOptions {
            insecure_dev: self.insecure_dev,
            executable: &self.cli,
            no_wait,
            poll_interval: APPROVAL_POLL_INTERVAL,
        };
        // The join future is large: it lives on the heap, not on the caller's stack.
        let flow = Box::pin(json_out::scope(
            json,
            crate::join_run(&self.home, Some(invitation), software_key, options),
        ));
        let run = Self::until(cancel, flow).await?;
        run.finished.map_err(|text| anyhow!(text))
    }

    /// Sends the claim for the signed manifest and gives what the gateway answered.
    pub async fn check(&self) -> Result<ClaimReport> {
        self.check_with(|_| {}).await
    }

    /// `check`, and `on_step` hears when the call waits for the scheduled job.
    pub async fn check_with(
        &self,
        on_step: impl FnMut(JoinStep) + Send + 'static,
    ) -> Result<ClaimReport> {
        let run = json_out::scope(
            Json::observed(Answers::default(), on_step),
            crate::check_report(&self.home, self.insecure_dev, &self.cli),
        )
        .await?;
        run.report.map_err(|text| anyhow!(text))
    }

    /// The changes of the manifest the gateway enforces against the one this device signed. Makes
    /// GET requests only and writes no file.
    pub async fn accept_preview(&self) -> Result<AcceptPreview> {
        json_out::scope(
            Json::observed(Answers::default(), |_| {}),
            crate::accept_preview(&self.home, self.insecure_dev),
        )
        .await
    }

    /// Signs the manifest the gateway enforces and moves this device to it.
    pub async fn accept(&self) -> Result<()> {
        self.accept_with(|_| {}).await
    }

    /// `accept`, and `on_step` hears when the call waits for the scheduled job.
    pub async fn accept_with(&self, on_step: impl FnMut(JoinStep) + Send + 'static) -> Result<()> {
        let code = json_out::scope(Json::observed(Answers::default(), on_step), async {
            let code = crate::accept(&self.home, true, self.insecure_dev, &self.cli).await;
            (code, json_out::last_note())
        })
        .await;
        match code {
            (Ok(code), _) if code == std::process::ExitCode::SUCCESS => Ok(()),
            (Ok(_), note) => Err(anyhow!(
                note.unwrap_or_else(|| "accept did not finish".into())
            )),
            (Err(error), _) => Err(error),
        }
    }

    /// Turns automatic sending on or off, and installs or removes the OS job that runs `cli`.
    pub async fn schedule(&self, on: bool) -> Result<()> {
        json_out::scope(Json::observed(Answers::default(), |_| {}), async {
            if on {
                crate::schedule::turn_on(&self.home, None, false, &self.cli).await
            } else {
                crate::schedule::turn_off(&self.home, false, &self.cli).await
            }
        })
        .await
    }

    /// The folders that hold the owner's repositories.
    pub fn folders(&self) -> Result<Vec<PathBuf>> {
        crate::folders_list(&self.home)
    }

    /// Adds a folder. Gives `false` when it was listed already.
    pub async fn add_folder(&self, path: &Path) -> Result<bool> {
        Ok(crate::folder_add(&self.home, path).await?.1)
    }

    /// Removes a folder. Fails when it is not listed.
    pub async fn remove_folder(&self, path: &Path) -> Result<()> {
        crate::folder_remove(&self.home, path).await?;
        Ok(())
    }

    /// Runs `flow` until it ends. When `cancel` completes first, the flow is dropped where it
    /// waits, and the call ends with [`Cancelled`]. The flow gets no interrupt of its own, so this
    /// holds for a join with `no_wait` too.
    async fn until<T>(
        cancel: impl Future<Output = ()>,
        flow: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let flow = host::with_host(Host::closed(), flow);
        tokio::pin!(flow, cancel);
        let result = tokio::select! {
            result = &mut flow => result,
            () = &mut cancel => return Err(Cancelled.into()),
        };
        result.map_err(|error| {
            if host::is_interrupt(&error) {
                Cancelled.into()
            } else {
                error
            }
        })
    }
}

/// The folders of a join, normalized as the CLI normalizes its `--folder` choices: a `~` path
/// expands to the owner's home, a relative path becomes absolute, and an empty path fails.
fn join_folders(folders: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let user_home = crate::user_profile();
    folders
        .iter()
        .map(|folder| device_config::absolute_folder(folder, user_home.as_deref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_folders_are_absolute_like_the_cli_saves_them() {
        let folders = join_folders(vec![PathBuf::from("work")]).unwrap();
        assert_eq!(folders, vec![std::path::absolute("work").unwrap()]);
        let home = crate::user_profile().expect("the test runs with a home");
        assert_eq!(
            join_folders(vec![PathBuf::from("~/work")]).unwrap(),
            vec![home.join("work")]
        );
    }
}
