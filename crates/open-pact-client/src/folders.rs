use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::Home;

const FILE: &str = "managed-folders.toml";
const LOCK: &str = "managed-folders.lock";

#[derive(Debug, Default)]
pub(crate) struct ManagedFolders {
    paths: BTreeSet<PathBuf>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FolderFile {
    folders: Vec<PathBuf>,
}

impl ManagedFolders {
    pub(crate) fn load(home: &Home) -> Result<Self> {
        let managed = Self::load_for_management(home)?;
        for path in &managed.paths {
            if !path.is_dir() {
                bail!(
                    "registered folder is missing or is not a folder: {}",
                    path.display()
                );
            }
        }
        Ok(managed)
    }

    fn load_for_management(home: &Home) -> Result<Self> {
        let file = home.file(FILE);
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).with_context(|| file.display().to_string()),
        };
        let value: FolderFile =
            toml::from_str(&text).with_context(|| format!("{}: invalid TOML", file.display()))?;
        let mut managed = Self::default();
        for path in value.folders {
            if !path.is_absolute() {
                bail!(
                    "{}: folder path is not absolute: {}",
                    file.display(),
                    path.display()
                );
            }
            managed.insert(path)?;
        }
        Ok(managed)
    }

    pub(crate) fn add(home: &Home, path: &Path) -> Result<PathBuf> {
        with_lock(home, |mut managed| {
            let canonical = canonical_folder(path)?;
            managed.insert(canonical.clone())?;
            managed.save(home)?;
            Ok(canonical)
        })
    }

    pub(crate) fn remove(home: &Home, path: &Path) -> Result<PathBuf> {
        with_lock(home, |mut managed| {
            let absolute = absolute_path(path)?;
            let registered = canonical_folder(&absolute).unwrap_or(absolute);
            if !managed.paths.remove(&registered) {
                bail!("folder is not registered: {}", registered.display());
            }
            managed.save(home)?;
            Ok(registered)
        })
    }

    pub(crate) fn list(home: &Home) -> Result<Vec<PathBuf>> {
        with_lock(home, |managed| Ok(managed.paths.into_iter().collect()))
    }

    fn save(&self, home: &Home) -> Result<()> {
        std::fs::create_dir_all(&home.0)?;
        let mut file = tempfile::NamedTempFile::new_in(&home.0)?;
        let value = FolderFile {
            folders: self.paths.iter().cloned().collect(),
        };
        file.write_all(toml::to_string(&value)?.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist(home.file(FILE))
            .with_context(|| format!("cannot replace {}", home.file(FILE).display()))?;
        Ok(())
    }

    fn insert(&mut self, candidate: PathBuf) -> Result<()> {
        for registered in &self.paths {
            if candidate == *registered {
                return Ok(());
            }
            if candidate.starts_with(registered) {
                bail!(
                    "folder {} is covered by registered folder {}",
                    candidate.display(),
                    registered.display()
                );
            }
            if registered.starts_with(&candidate) {
                bail!(
                    "folder {} covers registered folder {}",
                    candidate.display(),
                    registered.display()
                );
            }
        }
        self.paths.insert(candidate);
        Ok(())
    }
}

fn with_lock<T>(home: &Home, action: impl FnOnce(ManagedFolders) -> Result<T>) -> Result<T> {
    std::fs::create_dir_all(&home.0)?;
    let lock_path = home.file(LOCK);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("cannot open {}", lock_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))?;
    }
    lock.lock_exclusive()
        .with_context(|| format!("cannot lock {}", lock_path.display()))?;
    let result = action(ManagedFolders::load_for_management(home)?);
    FileExt::unlock(&lock)?;
    result
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn canonical_folder(path: &Path) -> Result<PathBuf> {
    let absolute = absolute_path(path)?;
    let canonical = std::fs::canonicalize(&absolute)
        .with_context(|| format!("cannot resolve folder {}", absolute.display()))?;
    if !canonical.is_dir() {
        bail!("path is not a folder: {}", canonical.display());
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_list_and_persist_canonical_paths() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().join("home"));
        let folder = temp.path().join("work");
        std::fs::create_dir(&folder).unwrap();

        let registered = ManagedFolders::add(&home, &folder).unwrap();
        assert_eq!(registered, folder.canonicalize().unwrap());
        assert_eq!(ManagedFolders::add(&home, &folder).unwrap(), registered);
        assert_eq!(
            ManagedFolders::list(&home).unwrap().as_slice(),
            std::slice::from_ref(&registered)
        );
        assert_eq!(ManagedFolders::remove(&home, &folder).unwrap(), registered);
        assert!(ManagedFolders::list(&home).unwrap().is_empty());
    }

    #[test]
    fn resolves_relative_paths_from_the_current_directory() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().join("home"));
        let registered = ManagedFolders::add(&home, Path::new(".")).unwrap();
        assert_eq!(
            registered,
            std::env::current_dir().unwrap().canonicalize().unwrap()
        );
    }

    #[test]
    fn rejects_missing_folders_and_nested_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().join("home"));
        let parent = temp.path().join("work");
        let child = parent.join("nested");
        std::fs::create_dir_all(&child).unwrap();
        ManagedFolders::add(&home, &parent).unwrap();

        let error = ManagedFolders::add(&home, &child).unwrap_err().to_string();
        assert!(error.contains(&parent.display().to_string()));
        assert!(ManagedFolders::add(&home, &temp.path().join("missing")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolves_symlinks_before_duplicate_checks() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().join("home"));
        let folder = temp.path().join("work");
        let alias = temp.path().join("alias");
        std::fs::create_dir(&folder).unwrap();
        std::os::unix::fs::symlink(&folder, &alias).unwrap();
        ManagedFolders::add(&home, &folder).unwrap();
        assert!(ManagedFolders::add(&home, &alias).is_ok());
        assert_eq!(ManagedFolders::list(&home).unwrap().len(), 1);
    }

    #[test]
    fn rejects_relative_paths_loaded_from_file() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().to_path_buf());
        std::fs::write(home.file(FILE), "folders = [\"relative\"]\n").unwrap();
        assert!(ManagedFolders::list(&home).is_err());
    }

    #[test]
    fn stale_registered_paths_remain_removable_and_do_not_block_other_commands() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().join("home"));
        let stale = temp.path().join("work");
        let other = temp.path().join("other");
        std::fs::create_dir(&stale).unwrap();
        std::fs::create_dir(&other).unwrap();
        let registered = ManagedFolders::add(&home, &stale).unwrap();
        std::fs::remove_dir(&stale).unwrap();

        assert_eq!(
            ManagedFolders::list(&home).unwrap().as_slice(),
            std::slice::from_ref(&registered)
        );
        assert_eq!(
            ManagedFolders::add(&home, &other).unwrap(),
            other.canonicalize().unwrap()
        );
        assert!(ManagedFolders::load(&home).is_err());
        assert_eq!(
            ManagedFolders::remove(&home, &registered).unwrap(),
            registered
        );
        assert_eq!(
            ManagedFolders::list(&home).unwrap(),
            [other.canonicalize().unwrap()]
        );
    }

    #[test]
    fn parses_and_writes_real_toml() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().join("home"));
        let folder = temp.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        std::fs::create_dir(&home.0).unwrap();
        std::fs::write(
            home.file(FILE),
            format!("# comment\nfolders = [\n  '{}',\n]\n", folder.display()),
        )
        .unwrap();

        assert_eq!(
            ManagedFolders::list(&home).unwrap().as_slice(),
            std::slice::from_ref(&folder)
        );
        let managed = ManagedFolders::load_for_management(&home).unwrap();
        managed.save(&home).unwrap();
        let written = std::fs::read_to_string(home.file(FILE)).unwrap();
        assert!(written.starts_with("folders = ["));
        assert!(toml::from_str::<FolderFile>(&written).is_ok());

        std::fs::write(home.file(FILE), "folders = [\"\\/tmp\"]\n").unwrap();
        assert!(ManagedFolders::list(&home).is_err());
        std::fs::write(home.file(FILE), "folders = []\nextra = true\n").unwrap();
        assert!(ManagedFolders::list(&home).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn registry_file_is_owner_only_on_creation_and_rewrite() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().join("home"));
        let folder = temp.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        ManagedFolders::add(&home, &folder).unwrap();
        let file = home.file(FILE);
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        ManagedFolders::add(&home, &folder).unwrap();
        assert_eq!(
            std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn concurrent_additions_are_not_lost() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().join("home"));
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let expected = [
            first.canonicalize().unwrap(),
            second.canonicalize().unwrap(),
        ];
        let first_home = Home(home.0.clone());
        let second_home = Home(home.0.clone());
        let first_path = first.clone();
        let second_path = second.clone();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_thread = std::thread::spawn(move || {
            with_lock(&first_home, |mut managed| {
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                managed.insert(first_path.canonicalize()?)?;
                managed.save(&first_home)
            })
        });
        locked_rx.recv().unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let second_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = ManagedFolders::add(&second_home, &second_path);
            finished_tx.send(result.is_ok()).unwrap();
            result
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        first_thread.join().unwrap().unwrap();
        second_thread.join().unwrap().unwrap();
        assert!(finished_rx.recv().unwrap());
        assert_eq!(ManagedFolders::list(&home).unwrap(), expected);
    }
}
