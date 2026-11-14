use std::fs::{File, OpenOptions};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::Home;

const LOCK: &str = "claim.lock";
const WAIT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(200);

/// Held while one command reads and writes the enrolment, the stored manifest, the log checkpoint,
/// the claim log or the VPN pair. `check`, `accept` and the scheduled job take it, so none of them
/// can write back a file that another one changed in the meantime.
pub(crate) struct ClaimLock(Option<File>);

impl Drop for ClaimLock {
    fn drop(&mut self) {
        if let Some(file) = &self.0 {
            let _ = file.unlock();
        }
    }
}

fn open(home: &Home) -> Result<Option<File>> {
    // Without a home there is nothing to protect. The command reports the missing home itself.
    if !home.0.is_dir() {
        return Ok(None);
    }
    let path = home.file(LOCK);
    Ok(Some(
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| path.display().to_string())?,
    ))
}

/// Takes the lock for a command the owner started. Waits while another command holds it.
pub(crate) async fn lock(home: &Home) -> Result<ClaimLock> {
    lock_for(home, WAIT).await
}

async fn lock_for(home: &Home, wait: Duration) -> Result<ClaimLock> {
    let Some(file) = open(home)? else {
        return Ok(ClaimLock(None));
    };
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(ClaimLock(Some(file))),
            Err(std::fs::TryLockError::WouldBlock) => {
                if tokio::time::Instant::now() >= deadline {
                    bail!(
                        "another open-pact command has held {} for {} seconds; wait for it to finish and run this command again",
                        home.file(LOCK).display(),
                        wait.as_secs()
                    );
                }
                tokio::time::sleep(POLL).await;
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).context("lock the claim lock");
            }
        }
    }
}

/// Takes the lock for the scheduled job, which skips its tick instead of waiting.
pub(crate) fn try_lock(home: &Home) -> Result<Option<ClaimLock>> {
    let Some(file) = open(home)? else {
        return Ok(Some(ClaimLock(None)));
    };
    match file.try_lock() {
        Ok(()) => Ok(Some(ClaimLock(Some(file)))),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error).context("lock the claim lock"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_second_holder_cannot_take_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let first = lock(&home).await.unwrap();
        assert!(try_lock(&home).unwrap().is_none());
        drop(first);
        assert!(try_lock(&home).unwrap().is_some());
    }

    #[tokio::test]
    async fn a_waiting_command_gives_up_with_the_lock_path() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let _held = try_lock(&home).unwrap().unwrap();
        let error = lock_for(&home, Duration::from_millis(300))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("claim.lock"), "{error}");
    }

    #[tokio::test]
    async fn a_missing_home_has_nothing_to_lock() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().join("absent"));
        assert!(lock(&home).await.is_ok());
        assert!(try_lock(&home).unwrap().is_some());
        assert!(!home.0.exists());
    }
}
