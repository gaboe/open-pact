//! File operations in the client home.
//!
//! A Windows SYSTEM job works in a home that a standard user owns. That user can put a junction,
//! a symbolic link or a hard link where the job expects a file or a folder, and so turn a write,
//! rename, delete or read of the job into one on a file the user cannot touch. `protect` opens
//! the home once and checks that no link leads to it. While the returned `Protection` lives,
//! every operation of this module below that home starts at that open folder and opens one name
//! at a time. It refuses a name that is a link (a reparse point), a file with another hard link,
//! and a folder where a file belongs, before it reads or changes anything. The job's own log goes
//! to the protected state folder instead (`job_log_home`).
//!
//! Without a protection, each operation is the one of `std::fs`, and a read still refuses a
//! reparse point on Windows.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result};

/// A home that a SYSTEM job must not trust, and where that job writes its own log.
struct Protected {
    home: PathBuf,
    job_log: PathBuf,
    /// The home, opened once and checked. Every protected operation starts here.
    #[cfg_attr(not(windows), allow(dead_code))]
    root: Arc<File>,
}

static PROTECTED: Mutex<Vec<Protected>> = Mutex::new(Vec::new());

fn protected_homes() -> MutexGuard<'static, Vec<Protected>> {
    PROTECTED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Keeps `home` protected until it drops.
pub(crate) struct Protection(PathBuf);

impl Drop for Protection {
    fn drop(&mut self) {
        protected_homes().retain(|protected| protected.home != self.0);
    }
}

/// Protects `home` for this process: see the module text. `job_log` is the folder that gets the
/// job's log while the protection lives. Fails when the home is a link or a link leads to it.
pub(crate) fn protect(home: &Path, job_log: &Path) -> Result<Protection> {
    #[cfg(windows)]
    let root = sys::open_root(home)
        .with_context(|| format!("refuse the client home {}", home.display()))?;
    #[cfg(not(windows))]
    let root = File::open(home).with_context(|| home.display().to_string())?;
    protected_homes().push(Protected {
        home: home.to_path_buf(),
        job_log: job_log.to_path_buf(),
        root: Arc::new(root),
    });
    Ok(Protection(home.to_path_buf()))
}

/// The folder for the job log of `home`: the protected state folder of a SYSTEM job, else the home.
pub(crate) fn job_log_home(home: &Path) -> PathBuf {
    protected_homes()
        .iter()
        .find(|protected| protected.home == home)
        .map_or_else(|| home.to_path_buf(), |protected| protected.job_log.clone())
}

/// The names from `home` down to `path`; `None` when `path` is not below `home`. A name that
/// climbs (`..`) or a root is an error: a protected path never leaves the home.
fn names_below<'a>(home: &Path, path: &'a Path) -> Option<io::Result<Vec<&'a OsStr>>> {
    let rest = path.strip_prefix(home).ok()?;
    Some(
        rest.components()
            .map(|component| match component {
                Component::Normal(name) => Ok(name),
                Component::CurDir => Ok(OsStr::new("")),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path leaves the client home",
                )),
            })
            .filter(|name| !matches!(name, Ok(name) if name.is_empty()))
            .collect(),
    )
}

/// The open home and the names below it when `path` is in a protected home.
#[cfg_attr(not(windows), allow(dead_code))]
fn protected(path: &Path) -> Option<io::Result<(Arc<File>, Vec<std::ffi::OsString>)>> {
    let homes = protected_homes();
    homes.iter().find_map(|protected| {
        names_below(&protected.home, path).map(|names| {
            names.map(|names| {
                (
                    protected.root.clone(),
                    names.into_iter().map(OsStr::to_os_string).collect(),
                )
            })
        })
    })
}

/// What an open handle says about the name it opened, without following a link.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Opened {
    pub(crate) reparse_point: bool,
    pub(crate) directory: bool,
    pub(crate) links: u32,
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Directory,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn refused(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what.to_owned())
}

/// Fails closed unless `opened` is a plain item of `kind`: no reparse point (junction, symbolic
/// link, mount point), and a file with no other hard link.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn check(opened: Opened, kind: Kind) -> io::Result<()> {
    if opened.reparse_point {
        return Err(refused("home file is a reparse point"));
    }
    match kind {
        Kind::File if opened.directory => Err(refused("home file is a folder")),
        Kind::File if opened.links != 1 => Err(refused("home file has another hard link")),
        Kind::Directory if !opened.directory => Err(refused("home folder is a file")),
        _ => Ok(()),
    }
}

/// Whether the final path Windows reports for an open handle names `expected`. Windows paths
/// ignore case; the `\\?\` prefix and a final separator do not count.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn same_path(final_path: &str, expected: &str) -> bool {
    fn plain(path: &str) -> String {
        let path = path.replace('/', "\\");
        let path = if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{rest}")
        } else if let Some(rest) = path.strip_prefix(r"\\?\") {
            rest.to_owned()
        } else {
            path
        };
        path.trim_end_matches('\\').to_lowercase()
    }
    plain(final_path) == plain(expected)
}

/// How `open` opens a file.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Open {
    /// Read and write, created when missing, never truncated: a lock file.
    Lock,
    /// Read, and write at the end, created when missing.
    Append,
    /// Write a new file that must not exist yet. Unix: only the owner may read it.
    CreateNew,
    /// Write, created when missing, emptied.
    Truncate,
}

/// Reads a whole file of the home.
pub(crate) fn read(path: &Path) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    if let Some(target) = protected(path) {
        let (root, names) = target?;
        let mut file = sys::open_file(&root, &names, sys::Access::Read)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        return Ok(bytes);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x00200000) // FILE_FLAG_OPEN_REPARSE_POINT
            .open(path)?;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(refused("home file is a reparse point"));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    #[cfg(not(windows))]
    {
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

/// Opens a file of the home as `how` says.
pub(crate) fn open(path: &Path, how: Open) -> io::Result<File> {
    #[cfg(windows)]
    if let Some(target) = protected(path) {
        let (root, names) = target?;
        let file = sys::open_file(&root, &names, sys::Access::Open(how))?;
        if matches!(how, Open::Truncate) {
            file.set_len(0)?;
        }
        return Ok(file);
    }
    let mut options = std::fs::OpenOptions::new();
    match how {
        Open::Lock => options.read(true).write(true).create(true).truncate(false),
        Open::Append => options.read(true).append(true).create(true),
        Open::CreateNew => {
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options.write(true).create_new(true)
        }
        Open::Truncate => options.write(true).create(true).truncate(true),
    };
    options.open(path)
}

/// Renames `from` to `to` in the same folder, replacing `to`.
pub(crate) fn rename(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if let Some(target) = protected(from) {
        let (root, names) = target?;
        let new_name = match (names.split_last(), protected(to)) {
            (Some((_, folders)), Some(Ok((_, to_names))))
                if to_names
                    .split_last()
                    .is_some_and(|(_, to_folders)| to_folders == folders) =>
            {
                to_names.last().cloned().unwrap_or_default()
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a protected rename stays in its folder",
                ));
            }
        };
        return sys::rename(&root, &names, &new_name);
    }
    std::fs::rename(from, to)
}

/// Deletes a file, or the link itself when the home is not protected.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if let Some(target) = protected(path) {
        let (root, names) = target?;
        let file = sys::open_file(&root, &names, sys::Access::Delete)?;
        return sys::delete(&file);
    }
    std::fs::remove_file(path)
}

/// Creates one folder; its parent must exist.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn create_dir(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if let Some(target) = protected(path) {
        let (root, names) = target?;
        sys::open_dir(&root, &names, sys::Folder::Create)?;
        return Ok(());
    }
    std::fs::create_dir(path)
}

/// Creates a folder and every missing parent.
pub(crate) fn create_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if let Some(target) = protected(path) {
        let (root, names) = target?;
        sys::open_dir(&root, &names, sys::Folder::OpenOrCreate)?;
        return Ok(());
    }
    std::fs::create_dir_all(path)
}

/// Deletes a folder and everything in it. In a protected home a link anywhere inside stops it.
pub(crate) fn remove_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if let Some(target) = protected(path) {
        let (root, names) = target?;
        let folder = sys::open_dir(&root, &names, sys::Folder::Delete)?;
        // The names come from the folder this handle opened, not from the path.
        for (name, directory) in sys::entries(&folder)? {
            let child = path.join(&name);
            if directory {
                remove_dir_all(&child)?;
            } else {
                remove_file(&child)?;
            }
        }
        return sys::delete(&folder);
    }
    std::fs::remove_dir_all(path)
}

#[cfg(windows)]
mod sys {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
        FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS,
        FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation,
        FileRenameInformationEx, NTCREATEFILE_CREATE_DISPOSITION, NtCreateFile,
        NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
        OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_APPEND_DATA,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FULL_DIR_INFO,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        FileDispositionInfo, FileDispositionInfoEx, FileFullDirectoryInfo,
        FileFullDirectoryRestartInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, OPEN_EXISTING, SYNCHRONIZE, SetFileInformationByHandle,
        VOLUME_NAME_DOS,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use super::{Kind, Open, Opened, check, refused, same_path};

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const FOLDER_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES;

    /// What a protected file operation needs from its handle.
    #[derive(Clone, Copy)]
    pub(super) enum Access {
        Read,
        Open(Open),
        Delete,
    }

    /// What a protected folder operation does with the last name.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Folder {
        Open,
        OpenOrCreate,
        Create,
        Delete,
    }

    fn status(status: NTSTATUS) -> io::Result<()> {
        if status >= 0 {
            return Ok(());
        }
        // SAFETY: a pure conversion of a status code.
        let code = unsafe { RtlNtStatusToDosError(status) };
        Err(io::Error::from_raw_os_error(code as i32))
    }

    pub(super) fn opened(file: &File) -> io::Result<Opened> {
        // SAFETY: zero is a valid value of this plain C struct.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        // SAFETY: the handle is open for the life of `file`, and `info` is writable.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Opened {
            reparse_point: info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
            directory: info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            links: info.nNumberOfLinks,
        })
    }

    fn final_path(file: &File) -> io::Result<String> {
        let mut buffer = vec![0u16; 512];
        loop {
            // SAFETY: the buffer holds `buffer.len()` UTF-16 units.
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle() as HANDLE,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            } as usize;
            if length == 0 {
                return Err(io::Error::last_os_error());
            }
            if length < buffer.len() {
                return String::from_utf16(&buffer[..length])
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "path is not UTF-16"));
            }
            buffer.resize(length + 1, 0);
        }
    }

    /// Opens the home by its path and checks that neither it nor any folder above it is a link:
    /// the path Windows resolved must be the path the job was given.
    pub(super) fn open_root(path: &Path) -> io::Result<File> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: `wide` is a NUL-terminated path; the other arguments are plain values.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FOLDER_ACCESS | SYNCHRONIZE,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a new open handle that only this `File` owns.
        let root = unsafe { File::from_raw_handle(handle as _) };
        check(opened(&root)?, Kind::Directory)?;
        let expected = path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "home path is not UTF-8"))?;
        if !same_path(&final_path(&root)?, expected) {
            return Err(refused("a link leads to the client home"));
        }
        Ok(root)
    }

    /// Opens `name` in the open folder `parent`. The name is one name, never a path, and a link
    /// at it is opened as the link itself.
    fn open_at(
        parent: &File,
        name: &OsStr,
        access: u32,
        disposition: NTCREATEFILE_CREATE_DISPOSITION,
        options: u32,
    ) -> io::Result<File> {
        let mut wide: Vec<u16> = name.encode_wide().collect();
        if wide.is_empty()
            || wide
                .iter()
                .any(|unit| matches!(unit, 0 | 0x5c | 0x2f | 0x3a))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not one plain name",
            ));
        }
        let length = u16::try_from(wide.len() * 2)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name is too long"))?;
        let object_name = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: wide.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.as_raw_handle() as HANDLE,
            ObjectName: &object_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let mut handle: HANDLE = null_mut();
        // SAFETY: zero is a valid value of this plain C struct.
        let mut io_status: IO_STATUS_BLOCK = unsafe { zeroed() };
        // SAFETY: every pointer refers to a live local value for the length of the call.
        status(unsafe {
            NtCreateFile(
                &mut handle,
                access | SYNCHRONIZE,
                &attributes,
                &mut io_status,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                SHARE_ALL,
                disposition,
                options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        })?;
        // SAFETY: `handle` is a new open handle that only this `File` owns.
        Ok(unsafe { File::from_raw_handle(handle as _) })
    }

    /// Opens the folder that `names` lead to from the home, one checked folder at a time.
    pub(super) fn open_dir(root: &File, names: &[OsString], last: Folder) -> io::Result<File> {
        let mut folder = root.try_clone()?;
        for (index, name) in names.iter().enumerate() {
            let is_last = index + 1 == names.len();
            let (access, disposition) = match (is_last, last) {
                (true, Folder::Create) => (FOLDER_ACCESS, FILE_CREATE),
                (true, Folder::Delete) => (FOLDER_ACCESS | DELETE, FILE_OPEN),
                (_, Folder::OpenOrCreate) => (FOLDER_ACCESS, FILE_OPEN_IF),
                _ => (FOLDER_ACCESS, FILE_OPEN),
            };
            let next = open_at(&folder, name, access, disposition, FILE_DIRECTORY_FILE)?;
            check(opened(&next)?, Kind::Directory)?;
            folder = next;
        }
        Ok(folder)
    }

    /// Opens the file that `names` lead to from the home, and checks it before any use.
    pub(super) fn open_file(root: &File, names: &[OsString], access: Access) -> io::Result<File> {
        let (name, folders) = names
            .split_last()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the home is no file"))?;
        let parent = open_dir(root, folders, Folder::Open)?;
        let (rights, disposition) = match access {
            Access::Read => (FILE_GENERIC_READ, FILE_OPEN),
            Access::Delete => (DELETE | FILE_READ_ATTRIBUTES, FILE_OPEN),
            Access::Open(Open::Lock) => (FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OPEN_IF),
            Access::Open(Open::Append) => (FILE_GENERIC_READ | FILE_APPEND_DATA, FILE_OPEN_IF),
            Access::Open(Open::CreateNew) => (FILE_GENERIC_WRITE, FILE_CREATE),
            Access::Open(Open::Truncate) => (FILE_GENERIC_WRITE, FILE_OPEN_IF),
        };
        // The check below reads the attributes, which needs `FILE_READ_ATTRIBUTES`.
        let file = open_at(
            &parent,
            name,
            rights | FILE_READ_ATTRIBUTES,
            disposition,
            FILE_NON_DIRECTORY_FILE,
        )?;
        check(opened(&file)?, Kind::File)?;
        Ok(file)
    }

    /// Renames the checked file at `names` to `new_name` in the same open folder, replacing a
    /// file there. A folder at `new_name` is never replaced.
    pub(super) fn rename(root: &File, names: &[OsString], new_name: &OsStr) -> io::Result<()> {
        let folders = &names[..names.len().saturating_sub(1)];
        let parent = open_dir(root, folders, Folder::Open)?;
        let file = open_file(root, names, Access::Delete)?;
        let name: Vec<u16> = new_name.encode_wide().collect();
        if name.is_empty()
            || name
                .iter()
                .any(|unit| matches!(unit, 0 | 0x5c | 0x2f | 0x3a))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not one plain name",
            ));
        }
        let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let bytes = name.len() * 2;
        let size = (header + bytes).max(size_of::<FILE_RENAME_INFORMATION>());
        // u64 units keep the struct aligned.
        let mut buffer = vec![0u64; size.div_ceil(8)];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let rename_with = |class, flags: u32| -> io::Result<()> {
            // SAFETY: `buffer` holds the header and the name; the pointers stay in it.
            unsafe {
                (*info).Anonymous.Flags = flags;
                (*info).RootDirectory = parent.as_raw_handle() as HANDLE;
                (*info).FileNameLength = bytes as u32;
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    info.cast::<u8>().add(header).cast::<u16>(),
                    name.len(),
                );
            }
            // SAFETY: zero is a valid value of this plain C struct.
            let mut io_status: IO_STATUS_BLOCK = unsafe { zeroed() };
            // SAFETY: the handle is open and `info` points at `size` bytes.
            status(unsafe {
                NtSetInformationFile(
                    file.as_raw_handle() as HANDLE,
                    &mut io_status,
                    info.cast(),
                    size as u32,
                    class,
                )
            })
        };
        // POSIX semantics replace a file that another program holds open, as std::fs::rename
        // does. Older Windows and some file systems know only the plain rename.
        match rename_with(
            FileRenameInformationEx,
            FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
        ) {
            Err(error)
                if matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
                ) =>
            {
                // A BOOLEAN ReplaceIfExists of 1 in the first byte.
                rename_with(FileRenameInformation, 1)
            }
            result => result,
        }
    }

    /// Deletes what the open handle names, which needs `DELETE` access.
    pub(super) fn delete(file: &File) -> io::Result<()> {
        let handle = file.as_raw_handle() as HANDLE;
        let info = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        };
        // SAFETY: the handle is open and `info` is a live value of the stated size.
        if unsafe {
            SetFileInformationByHandle(
                handle,
                FileDispositionInfoEx,
                (&raw const info).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        } != 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error().map(|code| code as u32),
            Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
        ) {
            return Err(error);
        }
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: as above.
        if unsafe {
            SetFileInformationByHandle(
                handle,
                FileDispositionInfo,
                (&raw const info).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The names in an open folder and whether each is a folder, read through the handle.
    pub(super) fn entries(folder: &File) -> io::Result<Vec<(OsString, bool)>> {
        let mut buffer = vec![0u64; 8 * 1024];
        let mut class = FileFullDirectoryRestartInfo;
        let mut entries = Vec::new();
        loop {
            // SAFETY: the buffer holds `buffer.len() * 8` writable bytes.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    folder.as_raw_handle() as HANDLE,
                    class,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                )
            };
            if ok == 0 {
                let error = io::Error::last_os_error();
                // ERROR_NO_MORE_FILES
                if error.raw_os_error() == Some(18) {
                    return Ok(entries);
                }
                return Err(error);
            }
            class = FileFullDirectoryInfo;
            let mut offset = 0usize;
            loop {
                // SAFETY: Windows wrote whole records into the buffer, linked by
                // `NextEntryOffset` and each aligned for its struct.
                let (next, attributes, name) = unsafe {
                    let entry = buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_FULL_DIR_INFO>();
                    let length = (*entry).FileNameLength as usize / 2;
                    let name = std::slice::from_raw_parts(
                        (&raw const (*entry).FileName).cast::<u16>(),
                        length,
                    );
                    (
                        (*entry).NextEntryOffset as usize,
                        (*entry).FileAttributes,
                        OsString::from_wide(name),
                    )
                };
                if name != "." && name != ".." {
                    entries.push((
                        name,
                        attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                            && attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                    ));
                }
                if next == 0 {
                    break;
                }
                offset += next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain() -> Opened {
        Opened {
            reparse_point: false,
            directory: false,
            links: 1,
        }
    }

    #[test]
    fn only_a_plain_item_of_the_expected_kind_passes() {
        assert!(check(plain(), Kind::File).is_ok());
        let folder = Opened {
            directory: true,
            ..plain()
        };
        assert!(check(folder, Kind::Directory).is_ok());
        for (opened, kind, why) in [
            (
                Opened {
                    reparse_point: true,
                    ..plain()
                },
                Kind::File,
                "reparse point",
            ),
            (
                Opened {
                    reparse_point: true,
                    ..folder
                },
                Kind::Directory,
                "reparse point",
            ),
            (
                Opened {
                    links: 2,
                    ..plain()
                },
                Kind::File,
                "another hard link",
            ),
            (
                Opened {
                    links: 0,
                    ..plain()
                },
                Kind::File,
                "another hard link",
            ),
            (folder, Kind::File, "is a folder"),
            (plain(), Kind::Directory, "is a file"),
        ] {
            let error = check(opened, kind).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{opened:?}");
            assert!(error.to_string().contains(why), "{error}");
        }
    }

    #[test]
    fn the_resolved_home_must_be_the_given_path() {
        let home = r"C:\Users\example\.config\open-pact";
        assert!(same_path(r"\\?\C:\Users\example\.config\open-pact", home));
        assert!(same_path(r"\\?\c:\users\EXAMPLE\.config\open-pact\", home));
        assert!(same_path(
            r"\\?\UNC\server\share\home",
            r"\\server\share\home"
        ));
        assert!(same_path(
            r"\\?\C:\Users\example\.config\open-pact",
            "C:/Users/example/.config/open-pact"
        ));
        // A junction anywhere above or at the home makes Windows report the target instead.
        assert!(!same_path(r"\\?\C:\Windows\System32", home));
        assert!(!same_path(
            r"\\?\C:\ProgramData\open-pact\system\ab12",
            home
        ));
        assert!(!same_path(
            r"\\?\C:\Users\example\.config\open-pact-other",
            home
        ));
    }

    #[test]
    fn a_protected_path_is_the_names_below_the_home_and_never_climbs() {
        let home = Path::new("/home/example/.config/open-pact");
        assert!(names_below(home, Path::new("/home/example/other")).is_none());
        let below = home.join("vpn").join("current");
        let names = names_below(home, &below).unwrap().unwrap();
        assert_eq!(names, [OsStr::new("vpn"), OsStr::new("current")]);
        assert!(names_below(home, home).unwrap().unwrap().is_empty());
        let climbing = home.join("vpn").join("..").join("..").join("secret");
        assert_eq!(
            names_below(home, &climbing).unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_protected_home_sends_the_job_log_to_the_state_folder_until_it_drops() {
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        assert_eq!(job_log_home(home.path()), home.path());
        let protection = protect(home.path(), state.path()).unwrap();
        assert_eq!(job_log_home(home.path()), state.path());
        assert_eq!(job_log_home(other.path()), other.path());
        drop(protection);
        assert_eq!(job_log_home(home.path()), home.path());
    }

    /// A home that SYSTEM protects, a folder outside it that holds what a user must not reach
    /// through it, and a state folder for the job log.
    #[cfg(windows)]
    struct Planted {
        _dir: tempfile::TempDir,
        home: PathBuf,
        outside: PathBuf,
        _protection: Protection,
    }

    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
    }

    #[cfg(windows)]
    fn planted() -> Planted {
        let dir = tempfile::tempdir().unwrap();
        // The final path Windows reports, so a short 8.3 name in TEMP does not count as a link.
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let root = PathBuf::from(root.to_str().unwrap().trim_start_matches(r"\\?\"));
        let home = root.join("home");
        let outside = root.join("outside");
        let state = root.join("state");
        for folder in [&home, &outside, &state] {
            std::fs::create_dir(folder).unwrap();
        }
        std::fs::write(outside.join("secret.txt"), b"fictional protected content").unwrap();
        let protection = protect(&home, &state).unwrap();
        Planted {
            _dir: dir,
            home,
            outside,
            _protection: protection,
        }
    }

    #[cfg(windows)]
    fn assert_untouched(planted: &Planted) {
        let mut names: Vec<_> = std::fs::read_dir(&planted.outside)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, [std::ffi::OsString::from("secret.txt")]);
        assert_eq!(
            std::fs::read(planted.outside.join("secret.txt")).unwrap(),
            b"fictional protected content"
        );
    }

    /// The operation failed closed because of the link, not for another reason.
    #[cfg(windows)]
    fn assert_refused<T>(result: io::Result<T>, why: &str) {
        let Err(error) = result else {
            panic!("expected a refusal: {why}");
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains(why), "{error}");
    }

    #[cfg(windows)]
    #[test]
    fn a_protected_home_works_without_links() {
        let planted = planted();
        let vpn = planted.home.join("vpn").join("123-456");
        create_dir_all(&vpn).unwrap();
        create_dir_all(&vpn).unwrap();
        let temp = vpn.join(".ca.pem.tmp");
        std::io::Write::write_all(&mut open(&temp, Open::CreateNew).unwrap(), b"first").unwrap();
        assert_eq!(
            open(&temp, Open::CreateNew).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        rename(&temp, &vpn.join("ca.pem")).unwrap();
        assert_eq!(read(&vpn.join("ca.pem")).unwrap(), b"first");
        let log = planted.home.join("claims.jsonl");
        crate::locallog::append_with_status(&log, b"sent", b"answer", Some(200)).unwrap();
        crate::locallog::append_with_status(&log, b"sent", b"answer", Some(200)).unwrap();
        assert_eq!(crate::locallog::read(&log).unwrap().len(), 2);
        let marker = planted.home.join("marker");
        std::io::Write::write_all(&mut open(&marker, Open::Truncate).unwrap(), b"long text")
            .unwrap();
        std::io::Write::write_all(&mut open(&marker, Open::Truncate).unwrap(), b"x").unwrap();
        assert_eq!(read(&marker).unwrap(), b"x");
        drop(open(&planted.home.join("claim.lock"), Open::Lock).unwrap());
        remove_file(&marker).unwrap();
        assert_eq!(read(&marker).unwrap_err().kind(), io::ErrorKind::NotFound);
        remove_dir_all(&planted.home.join("vpn")).unwrap();
        assert!(!planted.home.join("vpn").exists());
        assert_untouched(&planted);
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_in_a_protected_home_stops_every_operation_through_it() {
        let planted = planted();
        let vpn = planted.home.join("vpn");
        junction(&vpn, &planted.outside);
        let secret = vpn.join("secret.txt");
        let why = "reparse point";
        assert_refused(read(&secret), why);
        assert_refused(open(&secret, Open::Lock), why);
        assert_refused(open(&secret, Open::Append), why);
        assert_refused(open(&secret, Open::Truncate), why);
        assert_refused(open(&vpn.join("new.pem"), Open::CreateNew), why);
        assert_refused(remove_file(&secret), why);
        assert_refused(create_dir(&vpn.join("123-456")), why);
        assert_refused(create_dir_all(&vpn.join("123-456")), why);
        assert_refused(remove_dir_all(&vpn), why);
        assert_refused(rename(&secret, &vpn.join("moved.txt")), why);
        assert_refused(
            crate::locallog::append_with_status(&vpn.join("claims.jsonl"), b"s", b"r", None),
            why,
        );
        assert_untouched(&planted);
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_inside_a_folder_the_job_deletes_stops_the_deletion() {
        let planted = planted();
        let generation = planted.home.join("vpn").join("123-456");
        create_dir_all(&generation).unwrap();
        junction(&generation.join("nested"), &planted.outside);
        assert!(remove_dir_all(&planted.home.join("vpn")).is_err());
        assert_untouched(&planted);
    }

    #[cfg(windows)]
    #[test]
    fn a_hard_link_in_a_protected_home_is_neither_read_nor_changed() {
        let planted = planted();
        let link = planted.home.join("ca.pem");
        std::fs::hard_link(planted.outside.join("secret.txt"), &link).unwrap();
        for result in [
            read(&link).map(drop),
            open(&link, Open::Lock).map(drop),
            open(&link, Open::Append).map(drop),
            open(&link, Open::Truncate).map(drop),
            remove_file(&link),
            crate::locallog::append_with_status(&link, b"s", b"r", None),
        ] {
            assert_refused(result, "another hard link");
        }
        assert_untouched(&planted);
    }

    #[cfg(windows)]
    #[test]
    fn a_symbolic_link_in_a_protected_home_is_neither_followed_nor_changed() {
        let planted = planted();
        let link = planted.home.join("vpn-cert.pem");
        // Windows CI runs elevated, which may create symbolic links.
        std::os::windows::fs::symlink_file(planted.outside.join("secret.txt"), &link).unwrap();
        for result in [
            read(&link).map(drop),
            open(&link, Open::Lock).map(drop),
            open(&link, Open::Append).map(drop),
            open(&link, Open::Truncate).map(drop),
            remove_file(&link),
        ] {
            assert_refused(result, "reparse point");
        }
        // A rename over the link replaces the link, never the file it points at.
        let temp = planted.home.join(".vpn-cert.pem.tmp");
        std::io::Write::write_all(&mut open(&temp, Open::CreateNew).unwrap(), b"new").unwrap();
        rename(&temp, &link).unwrap();
        assert_eq!(read(&link).unwrap(), b"new");
        assert_untouched(&planted);
    }

    #[cfg(windows)]
    #[test]
    fn a_system_job_neither_installs_nor_deletes_the_vpn_pair_through_a_link() {
        let planted = planted();
        let home = crate::Home(planted.home.clone());
        junction(&planted.home.join("vpn"), &planted.outside);
        let error = home
            .install_vpn_pair(b"fictional CA", b"fictional certificate")
            .unwrap_err();
        assert!(format!("{error:#}").contains("reparse point"), "{error:#}");
        assert_untouched(&planted);

        let planted = self::planted();
        let home = crate::Home(planted.home.clone());
        std::fs::hard_link(
            planted.outside.join("secret.txt"),
            planted.home.join("vpn-cert.pem"),
        )
        .unwrap();
        let error = home.remove_vpn_pair().unwrap_err();
        assert!(
            format!("{error:#}").contains("another hard link"),
            "{error:#}"
        );
        assert_untouched(&planted);
    }

    #[cfg(windows)]
    #[test]
    fn a_home_that_is_a_junction_or_lies_below_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let root = PathBuf::from(root.to_str().unwrap().trim_start_matches(r"\\?\"));
        let target = root.join("target");
        std::fs::create_dir_all(target.join("inner")).unwrap();
        let state = root.join("state");
        std::fs::create_dir(&state).unwrap();
        let home = root.join("home");
        junction(&home, &target);
        assert!(protect(&home, &state).is_err());
        assert!(protect(&home.join("inner"), &state).is_err());
        assert!(protect(&target, &state).is_ok());
    }
}
