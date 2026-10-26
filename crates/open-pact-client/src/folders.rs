use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::Home;

const FILE: &str = "managed-folders.toml";
const KEY: &str = "folders = ";

#[derive(Debug, Default)]
pub(crate) struct ManagedFolders {
    paths: BTreeSet<PathBuf>,
}

impl ManagedFolders {
    pub(crate) fn load(home: &Home) -> Result<Self> {
        let file = home.file(FILE);
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).with_context(|| file.display().to_string()),
        };
        let values = text
            .strip_prefix(KEY)
            .with_context(|| format!("{}: expected `{KEY}...`", file.display()))?;
        let paths: Vec<PathBuf> = serde_json::from_str(values.trim())
            .with_context(|| format!("{}: invalid folders array", file.display()))?;
        let mut managed = Self::default();
        for path in paths {
            if !path.is_absolute() {
                bail!(
                    "{}: folder path is not absolute: {}",
                    file.display(),
                    path.display()
                );
            }
            let canonical = canonical_folder(&path)?;
            managed.insert(canonical)?;
        }
        Ok(managed)
    }

    pub(crate) fn add(&mut self, path: &Path) -> Result<PathBuf> {
        let canonical = canonical_folder(path)?;
        self.insert(canonical.clone())?;
        Ok(canonical)
    }

    pub(crate) fn remove(&mut self, path: &Path) -> Result<PathBuf> {
        let canonical = canonical_folder(path)?;
        if !self.paths.remove(&canonical) {
            bail!("folder is not registered: {}", canonical.display());
        }
        Ok(canonical)
    }

    pub(crate) fn list(&self) -> impl Iterator<Item = &Path> {
        self.paths.iter().map(PathBuf::as_path)
    }

    pub(crate) fn save(&self, home: &Home) -> Result<()> {
        let paths: Vec<&Path> = self.list().collect();
        let value = serde_json::to_string(&paths)?;
        home.write(FILE, format!("{KEY}{value}\n").as_bytes())?;
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

fn canonical_folder(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
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
        let mut folders = ManagedFolders::load(&home).unwrap();

        let registered = folders.add(&folder).unwrap();
        assert_eq!(registered, folder.canonicalize().unwrap());
        assert_eq!(folders.add(&folder).unwrap(), registered);
        folders.save(&home).unwrap();

        let loaded = ManagedFolders::load(&home).unwrap();
        assert_eq!(loaded.list().collect::<Vec<_>>(), [registered.as_path()]);
        assert_eq!(folders.remove(&folder).unwrap(), registered);
        folders.save(&home).unwrap();
        assert!(ManagedFolders::load(&home).unwrap().list().next().is_none());
    }

    #[test]
    fn resolves_relative_paths_from_the_current_directory() {
        let mut folders = ManagedFolders::default();
        assert_eq!(
            folders.add(Path::new(".")).unwrap(),
            std::env::current_dir().unwrap().canonicalize().unwrap()
        );
    }

    #[test]
    fn rejects_missing_folders_and_nested_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("work");
        let child = parent.join("nested");
        std::fs::create_dir_all(&child).unwrap();
        let mut folders = ManagedFolders::default();
        folders.add(&parent).unwrap();

        let error = folders.add(&child).unwrap_err().to_string();
        assert!(error.contains(&parent.display().to_string()));
        assert!(folders.add(&temp.path().join("missing")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolves_symlinks_before_duplicate_checks() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("work");
        let alias = temp.path().join("alias");
        std::fs::create_dir(&folder).unwrap();
        std::os::unix::fs::symlink(&folder, &alias).unwrap();
        let mut folders = ManagedFolders::default();
        folders.add(&folder).unwrap();
        assert!(folders.add(&alias).is_ok());
        assert_eq!(folders.list().count(), 1);
    }

    #[test]
    fn rejects_relative_paths_loaded_from_file() {
        let temp = tempfile::tempdir().unwrap();
        let home = Home(temp.path().to_path_buf());
        std::fs::write(home.file(FILE), "folders = [\"relative\"]\n").unwrap();
        assert!(ManagedFolders::load(&home).is_err());
    }
}
