//! Audited descriptor-relative primitives for immutable route generations.
//!
//! This module is deliberately neutral with respect to startup and release
//! publication protocols. Protocol modules own their identities and state;
//! this module owns only their shared filesystem safety boundary.
#![allow(dead_code)]

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use sha2::{Digest as _, Sha256};

pub(super) const GENERATIONS_DIRECTORY: &str = "generations";
pub(super) const CURRENT_SELECTOR: &str = "current";
pub(super) const MAX_ROUTE_BYTES: usize = 65_536;
const MAX_SELECTOR_BYTES: usize = 128;
pub(super) const ROUTE_ROOT_MODE: u32 = 0o750;
pub(super) const GENERATIONS_MODE: u32 = 0o750;
pub(super) const STAGING_MODE: u32 = 0o700;
pub(super) const SEALED_MODE: u32 = 0o750;
pub(super) const FILE_MODE: u32 = 0o640;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PriorSelector {
    target: String,
    directory_dev: u64,
    directory_ino: u64,
}

impl PriorSelector {
    pub(super) fn from_recorded(
        target: String,
        directory_device: u64,
        directory_inode: u64,
    ) -> io::Result<Self> {
        validate_selector_target(&target)?;
        if directory_device == 0 || directory_inode == 0 {
            return Err(invalid_input(
                "recorded selector directory identity is invalid",
            ));
        }
        Ok(Self {
            target,
            directory_dev: directory_device,
            directory_ino: directory_inode,
        })
    }

    pub(super) fn target(&self) -> &str {
        &self.target
    }

    pub(super) fn directory_device(&self) -> u64 {
        self.directory_dev
    }

    pub(super) fn directory_inode(&self) -> u64 {
        self.directory_ino
    }
}

/// Read the live selector for durable admission evidence. The observation is
/// exact only when both reads agree and the target is a safe direct generation
/// directory on the route root filesystem.
pub(super) fn observe_current_selector(route_root: &Path) -> io::Result<PriorSelector> {
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    observe_selector_from_handles(&root, &generations)
}

/// Re-open a selector target persisted by the database and bind it to its
/// current directory identity.
pub(super) fn observe_generation_selector(
    route_root: &Path,
    target: &str,
) -> io::Result<PriorSelector> {
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    observe_selector_target(&generations, target.to_owned())
}

pub(super) fn validate_route_bytes(contents: &[u8]) -> io::Result<()> {
    if contents.is_empty()
        || contents.len() > MAX_ROUTE_BYTES
        || contents.contains(&0)
        || !contents.ends_with(b"\n")
    {
        return Err(invalid_input(
            "route configuration must be bounded, non-empty, NUL-free, and newline terminated",
        ));
    }
    Ok(())
}

pub(super) fn validate_digest(value: &str, description: &str) -> io::Result<()> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if valid {
        Ok(())
    } else {
        Err(invalid_input(format!("{description} is invalid")))
    }
}

pub(super) fn validate_selector_target(target: &str) -> io::Result<()> {
    let path = Path::new(target);
    let mut components = path.components();
    if components.next() != Some(Component::Normal(OsStr::new(GENERATIONS_DIRECTORY))) {
        return Err(invalid_state(
            "route selector escapes the generations directory",
        ));
    }
    let Some(Component::Normal(name)) = components.next() else {
        return Err(invalid_state("route selector has no generation name"));
    };
    if components.next().is_some()
        || name.is_empty()
        || name.as_bytes().len() > 64
        || !name
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(invalid_state(
            "route selector target is not a direct generation child",
        ));
    }
    Ok(())
}

pub(super) fn selector_generation_name(target: &str) -> io::Result<&str> {
    validate_selector_target(target)?;
    Path::new(target)
        .components()
        .nth(1)
        .and_then(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .ok_or_else(|| invalid_state("route selector generation name is invalid"))
}

pub(super) fn observe_selector_from_handles(
    root: &File,
    generations: &File,
) -> io::Result<PriorSelector> {
    let selector = cstring(CURRENT_SELECTOR)?;
    let first = read_link_at(root, &selector)?;
    let observed = observe_selector_target(generations, first.clone())?;
    let second = read_link_at(root, &selector)?;
    if second != first {
        return Err(invalid_state("route selector changed during observation"));
    }
    Ok(observed)
}

pub(super) fn observe_selector_target(
    generations: &File,
    target: String,
) -> io::Result<PriorSelector> {
    let generation_name = selector_generation_name(&target)?;
    let selected = open_at_directory(generations, &cstring(generation_name)?)?;
    validate_directory(&selected, SEALED_MODE, "selected route generation")?;
    ensure_same_filesystem(generations, &selected)?;
    let metadata = selected.metadata()?;
    Ok(PriorSelector {
        target,
        directory_dev: metadata.dev(),
        directory_ino: metadata.ino(),
    })
}

pub(super) fn validate_current_selector(root: &File, expected: &str) -> io::Result<()> {
    let name = cstring(CURRENT_SELECTOR)?;
    validate_symlink_at(root, &name)?;
    let observed = read_link_at(root, &name)?;
    validate_selector_target(&observed)?;
    if observed != expected {
        return Err(invalid_state(
            "selected route generation does not match candidate",
        ));
    }
    Ok(())
}

pub(super) fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}

pub(super) fn validate_directory(
    file: &File,
    expected_mode: u32,
    description: &str,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{description} has unsafe type, ownership, or mode"),
        ));
    }
    Ok(())
}

pub(super) fn validate_regular_file(
    file: &File,
    expected_mode: u32,
    description: &str,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != expected_mode
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{description} has unsafe type, ownership, mode, or link count"),
        ));
    }
    Ok(())
}

pub(super) fn ensure_same_filesystem(parent: &File, child: &File) -> io::Result<()> {
    if parent.metadata()?.dev() != child.metadata()?.dev() {
        return Err(invalid_state(
            "route generation crosses a filesystem boundary",
        ));
    }
    Ok(())
}

pub(super) fn cstring(value: impl AsRef<str>) -> io::Result<CString> {
    CString::new(value.as_ref()).map_err(|_| invalid_input("filesystem name contains a NUL"))
}

pub(super) fn open_directory(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_input("route root contains a NUL"))?;
    // SAFETY: the C string is valid and ownership of a successful descriptor
    // is transferred exactly once to `File`.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_file(descriptor)
}

pub(super) fn open_at_directory(parent: &File, name: &CString) -> io::Result<File> {
    // SAFETY: parent and name remain valid for the call. O_NOFOLLOW rejects a
    // substituted directory symlink.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_file(descriptor)
}

pub(super) fn open_at_file(parent: &File, name: &CString) -> io::Result<File> {
    // SAFETY: parent and name remain valid for the call. O_NOFOLLOW rejects a
    // substituted file symlink.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_file(descriptor)
}

pub(super) fn open_at_append_file(parent: &File, name: &CString) -> io::Result<File> {
    // SAFETY: parent and name remain valid for the call. O_NOFOLLOW and
    // O_NONBLOCK reject substituted symlinks and avoid blocking on hostile
    // special files before the caller validates the descriptor.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_APPEND | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_file(descriptor)
}

pub(super) fn create_at_file(parent: &File, name: &CString, mode: u32) -> io::Result<File> {
    // SAFETY: parent and name remain valid; the new descriptor is uniquely
    // transferred to File. O_EXCL makes writes immutable within staging.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    owned_file(descriptor)
}

fn owned_file(descriptor: libc::c_int) -> io::Result<File> {
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful open/openat descriptor is uniquely owned here.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

pub(super) fn mkdir_at(parent: &File, name: &CString, mode: u32) -> io::Result<()> {
    // SAFETY: parent and name are valid and mkdirat does not retain pointers.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn symlink_at(target: &CString, parent: &File, name: &CString) -> io::Result<()> {
    // SAFETY: all descriptors and strings remain live for the call.
    if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn rename_exchange(parent: &File, left: &CString, right: &CString) -> io::Result<()> {
    // SAFETY: both paths are direct children of the same validated directory;
    // RENAME_EXCHANGE atomically preserves the old selector at `left`.
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn unlink_at(parent: &File, name: &CString, directory: bool) -> io::Result<()> {
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: parent and name remain valid and the direct child was validated.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn validate_symlink_at(parent: &File, name: &CString) -> io::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable initialized-size storage and all input
    // references remain live for the call.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat returned success and initialized the structure.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFLNK
        || stat.st_uid != effective_uid()
        || stat.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "route selector has unsafe type, ownership, or link count",
        ));
    }
    Ok(())
}

pub(super) fn read_link_at(parent: &File, name: &CString) -> io::Result<String> {
    validate_symlink_at(parent, name)?;
    let mut buffer = vec![0_u8; MAX_SELECTOR_BYTES + 1];
    // SAFETY: the buffer is writable for its full length and inputs remain live.
    let length = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(length).map_err(io::Error::other)?;
    if length > MAX_SELECTOR_BYTES {
        return Err(invalid_state("route selector target exceeds its bound"));
    }
    buffer.truncate(length);
    String::from_utf8(buffer).map_err(|_| invalid_state("route selector target is not UTF-8"))
}

pub(super) fn read_bounded(file: File, bound: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(u64::try_from(bound + 1).map_err(io::Error::other)?)
        .read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(invalid_state("generation file exceeds its bound"));
    }
    Ok(bytes)
}

pub(super) fn visit_generation_entries(
    directory: &File,
    mut visitor: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    // Open `.` relative to the validated descriptor. `dup` is insufficient:
    // duplicate directory descriptors share an enumeration offset and would
    // make the result of a second validation depend on the first.
    let duplicate = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: duplicate is an owned directory descriptor. closedir below takes
    // care of it on every path after successful fdopendir.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not consume the descriptor on failure.
        unsafe { libc::close(duplicate) };
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        loop {
            // POSIX uses a null result for both EOF and failure. Clear errno so
            // a partial enumeration can never be mistaken for a complete set.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: stream remains open and is used only by this thread.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let errno = unsafe { *libc::__errno_location() };
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                break;
            }
            // SAFETY: d_name is NUL terminated for a successful readdir entry.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            let name = std::str::from_utf8(bytes)
                .map_err(|_| invalid_state("startup generation contains a non-UTF-8 name"))?;
            visitor(name)?;
        }
        Ok(())
    })();
    // SAFETY: stream was successfully created and has not been closed.
    let close_result = unsafe { libc::closedir(stream) };
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    result
}

pub(super) fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(super) fn invalid_state(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
