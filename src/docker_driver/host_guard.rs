use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::Duration;

const LOCK_DIRECTORY: &str = ".driver-locks";
const SHARED_ODOO_LOCK: &str = "shared-odoo.lock";
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Cross-process authority for effects on the one shared Odoo runtime.
///
/// The guard is intentionally independent of PostgreSQL authority. Callers
/// acquire it before database admission and retain it until the exact driver
/// receipt has been finalized. Dropping the future while it is waiting drops
/// its file descriptor; dropping the returned guard releases the advisory
/// lock, including during unwinding.
#[derive(Debug)]
pub(super) struct SharedOdooHostGuard {
    _file: File,
    _directory: File,
}

impl SharedOdooHostGuard {
    pub(super) fn prepare(route_root: &Path) -> io::Result<()> {
        open_lock_directory(route_root).map(drop)
    }

    pub(super) async fn acquire(route_root: &Path) -> io::Result<Self> {
        let directory = open_lock_directory(route_root)?;
        let file = open_lock_file(&directory, true)?;
        loop {
            match file.try_lock() {
                Ok(()) => {
                    validate_open_file_identity(&file, &directory)?;
                    return Ok(Self {
                        _file: file,
                        _directory: directory,
                    });
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
            }
        }
    }

    /// Duplicate both descriptors so an asynchronous cleanup task can retain
    /// the same advisory-lock open file description after its caller drops.
    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            _file: self._file.try_clone()?,
            _directory: self._directory.try_clone()?,
        })
    }
}

#[cfg(test)]
fn lock_path(route_root: &Path) -> std::path::PathBuf {
    route_root.join(LOCK_DIRECTORY).join(SHARED_ODOO_LOCK)
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not dereference memory.
    unsafe { libc::geteuid() }
}

fn validate_owned_directory(file: &File, expected_mode: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "shared Odoo lock directory has unsafe ownership, type, or mode",
        ));
    }
    Ok(())
}

fn open_lock_directory(route_root: &Path) -> io::Result<File> {
    let root = open_directory(route_root)?;
    validate_owned_directory(&root, 0o750)?;
    let name = CString::new(LOCK_DIRECTORY).expect("the lock directory name has no NUL");
    // SAFETY: both the validated directory descriptor and C string remain live
    // for the call; mkdirat copies the path and writes no Rust-owned memory.
    let created = unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) };
    if created != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error);
        }
    }
    let directory = open_at_directory(&root, &name)?;
    validate_owned_directory(&directory, 0o700)?;
    Ok(directory)
}

fn open_directory(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "lock root contains a NUL"))?;
    // SAFETY: the C string is NUL terminated and live for the call. On success
    // ownership of the returned descriptor is immediately transferred to File.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_file(descriptor)
}

fn open_at_directory(parent: &File, name: &CString) -> io::Result<File> {
    // SAFETY: the parent descriptor and C string are valid and live for the
    // call. `O_NOFOLLOW|O_DIRECTORY` rejects a substituted symlink or file.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_file(descriptor)
}

fn open_lock_file(directory: &File, create: bool) -> io::Result<File> {
    let name = CString::new(SHARED_ODOO_LOCK).expect("the lock file name has no NUL");
    let flags =
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | if create { libc::O_CREAT } else { 0 };
    // SAFETY: the directory descriptor and C string are valid and live for the
    // call. On success ownership is transferred immediately to File.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    let file = owned_file(descriptor)?;
    validate_lock_metadata(&file.metadata()?)?;
    Ok(file)
}

fn owned_file(descriptor: libc::c_int) -> io::Result<File> {
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a non-negative descriptor returned by open/openat is uniquely
    // owned here and is transferred exactly once to File.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_lock_metadata(metadata: &std::fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "shared Odoo lock file has unsafe ownership, type, mode, or link count",
        ));
    }
    Ok(())
}

fn validate_open_file_identity(file: &File, directory: &File) -> io::Result<()> {
    let opened = file.metadata()?;
    validate_lock_metadata(&opened)?;
    let named_file = open_lock_file(directory, false)?;
    let named = named_file.metadata()?;
    validate_lock_metadata(&named)?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "shared Odoo lock file identity changed while acquiring authority",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{DirBuilder, hard_link};
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _, symlink};
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::time::Instant;

    use super::*;
    use uuid::Uuid;

    fn root() -> PathBuf {
        let path = std::env::temp_dir().join(format!("mb-shared-odoo-lock-{}", Uuid::new_v4()));
        DirBuilder::new().mode(0o750).create(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn rejects_symlinks_wrong_modes_and_hard_links() {
        let directory_symlink_root = root();
        let substituted = directory_symlink_root.join("substituted-locks");
        DirBuilder::new().mode(0o700).create(&substituted).unwrap();
        symlink(&substituted, directory_symlink_root.join(LOCK_DIRECTORY)).unwrap();
        assert!(SharedOdooHostGuard::prepare(&directory_symlink_root).is_err());

        let symlink_root = root();
        SharedOdooHostGuard::prepare(&symlink_root).unwrap();
        let path = lock_path(&symlink_root);
        let victim = symlink_root.join("victim");
        std::fs::write(&victim, b"").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&victim, &path).unwrap();
        assert!(SharedOdooHostGuard::acquire(&symlink_root).await.is_err());

        let mode_root = root();
        let guard = SharedOdooHostGuard::acquire(&mode_root).await.unwrap();
        drop(guard);
        std::fs::set_permissions(
            lock_path(&mode_root),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(SharedOdooHostGuard::acquire(&mode_root).await.is_err());

        let link_root = root();
        let guard = SharedOdooHostGuard::acquire(&link_root).await.unwrap();
        drop(guard);
        hard_link(lock_path(&link_root), link_root.join("second-link")).unwrap();
        assert!(SharedOdooHostGuard::acquire(&link_root).await.is_err());

        for path in [directory_symlink_root, symlink_root, mode_root, link_root] {
            std::fs::remove_dir_all(path).unwrap();
        }
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_retain_the_lock() {
        let root = root();
        let first = SharedOdooHostGuard::acquire(&root).await.unwrap();
        let waiting_root = root.clone();
        let waiter = tokio::spawn(async move { SharedOdooHostGuard::acquire(&waiting_root).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        waiter.abort();
        waiter.await.unwrap_err();
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), SharedOdooHostGuard::acquire(&root))
            .await
            .expect("a cancelled waiter must release its descriptor")
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cloned_guard_retains_lock_after_original_is_dropped() {
        let root = root();
        let original = SharedOdooHostGuard::acquire(&root).await.unwrap();
        let retained = original.try_clone().unwrap();
        drop(original);

        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                SharedOdooHostGuard::acquire(&root),
            )
            .await
            .is_err()
        );
        drop(retained);
        tokio::time::timeout(Duration::from_secs(1), SharedOdooHostGuard::acquire(&root))
            .await
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn another_process_cannot_enter_until_the_holder_exits() {
        let root = root();
        let ready = root.join("child-ready");
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "docker_driver::host_guard::tests::process_lock_holder",
            ])
            .env("MB_HOST_GUARD_TEST_ROOT", &root)
            .env("MB_HOST_GUARD_TEST_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.is_file() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            ready.is_file(),
            "lock-holder subprocess did not become ready"
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(150),
                SharedOdooHostGuard::acquire(&root)
            )
            .await
            .is_err(),
            "a second process entered the shared Odoo effect boundary"
        );
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), SharedOdooHostGuard::acquire(&root))
            .await
            .expect("process exit must release the advisory lock")
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[ignore = "subprocess helper for the cross-process host-guard test"]
    async fn process_lock_holder() {
        let Some(root) = std::env::var_os("MB_HOST_GUARD_TEST_ROOT").map(PathBuf::from) else {
            return;
        };
        let ready = std::env::var_os("MB_HOST_GUARD_TEST_READY")
            .map(PathBuf::from)
            .expect("the subprocess ready path is required");
        let _guard = SharedOdooHostGuard::acquire(&root).await.unwrap();
        std::fs::write(ready, b"ready").unwrap();
        std::future::pending::<()>().await;
    }
}
