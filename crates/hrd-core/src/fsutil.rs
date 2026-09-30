//! Filesystem helpers with the properties the rest of the manager assumes.
//!
//! Three of them matter more than the rest:
//!
//! * **A file is either the old version or the new one.** [`atomic_write`]
//!   writes beside the target, syncs, renames and syncs the directory, so a
//!   crash or a full disk cannot leave a half-written registry behind.
//! * **Private means private regardless of the umask.** Modes are set with an
//!   explicit `fchmod`, not left to whatever the process inherited.
//! * **Nothing follows a symlink it was not told to.** The state directory is
//!   owned by an unprivileged user, and so is every process that runs inside it;
//!   a helper that resolved a planted link would be a way to make a more
//!   privileged component write somewhere else.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{flock, FlockOperation, OFlags};

use crate::error::{Error, IoContext, Result};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// The effective uid of this process.
pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Write `data` to `path` so that readers see either the old contents or the
/// new ones, never a prefix of the new.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| Error::invalid(format!("{} has no file name", path.display())))?
        .to_string_lossy();
    let tmp = dir.join(format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
            .open(&tmp)
            .ctx(|| format!("create {}", tmp.display()))?;
        // `mode` above is masked by the umask; this is not.
        f.set_permissions(fs::Permissions::from_mode(mode)).ctx(|| format!("chmod {}", tmp.display()))?;
        f.write_all(data).ctx(|| format!("write {}", tmp.display()))?;
        f.sync_all().ctx(|| format!("sync {}", tmp.display()))?;
        drop(f);
        fs::rename(&tmp, path).ctx(|| format!("rename {} to {}", tmp.display(), path.display()))?;
        // Without this the rename itself can be lost in a crash, which would
        // resurrect the old file after the caller was told the new one was safe.
        File::open(dir).and_then(|d| d.sync_all()).ctx(|| format!("sync directory {}", dir.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Serialise `value` as pretty JSON and [`atomic_write`] it.
pub fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    let mut text = serde_json::to_vec_pretty(value).map_err(|e| Error::Internal(format!("serialise {}: {e}", path.display())))?;
    text.push(b'\n');
    atomic_write(path, &text, mode)
}

/// Read at most `max` bytes of a file that is not supposed to be large. A
/// registry that has grown to gigabytes is a fault, not something to load.
pub fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(path)
        .ctx(|| format!("open {}", path.display()))?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf).ctx(|| format!("read {}", path.display()))?;
    if buf.len() as u64 > max {
        return Err(Error::invalid(format!("{} is larger than the {max} byte limit", path.display())));
    }
    Ok(buf)
}

/// Like [`read_limited`] but a missing file is `None`.
pub fn read_limited_opt(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    match read_limited(path, max) {
        Ok(v) => Ok(Some(v)),
        Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Make sure `path` is a directory owned by the current user with no access
/// for group or others beyond `mode`, creating it if needed.
///
/// A path that is a symlink, or a directory owned by someone else, is refused
/// rather than adopted: the whole point of a private directory is that nobody
/// else could have prepared it.
pub fn ensure_private_dir(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                return Err(Error::Denied(format!("{} is a symbolic link; refusing to use it as a private directory", path.display())));
            }
            if !md.is_dir() {
                return Err(Error::conflict(format!("{} exists and is not a directory", path.display())));
            }
            if md.uid() != euid() {
                return Err(Error::Denied(format!(
                    "{} is owned by uid {}, not by uid {}; refusing to use it",
                    path.display(),
                    md.uid(),
                    euid()
                )));
            }
            if md.mode() & 0o7777 != mode {
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).ctx(|| format!("chmod {}", path.display()))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().recursive(true).mode(mode).create(path).ctx(|| format!("create {}", path.display()))?;
            // Intermediate directories and the leaf were created through the
            // umask; the leaf must be exactly what was asked for.
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).ctx(|| format!("chmod {}", path.display()))?;
            Ok(())
        }
        Err(e) => Err(Error::io(format!("stat {}", path.display()), e)),
    }
}

/// Create (or truncate) a private file and return it open for writing. For
/// anything appended to over time, such as an instance log.
pub fn open_private_append(path: &Path, mode: u32) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(mode)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(path)
        .ctx(|| format!("open {}", path.display()))?;
    f.set_permissions(fs::Permissions::from_mode(mode)).ctx(|| format!("chmod {}", path.display()))?;
    Ok(f)
}

/// Check that a file is not readable or writable by group or others. Used on
/// anything that holds key material before it is read.
pub fn require_private_file(path: &Path) -> Result<()> {
    let md = fs::symlink_metadata(path).ctx(|| format!("stat {}", path.display()))?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(Error::Denied(format!("{} must be a regular file", path.display())));
    }
    if md.mode() & 0o077 != 0 {
        return Err(Error::Denied(format!(
            "{} has mode {:04o}; it holds key material and must not be accessible to group or others (chmod 600)",
            path.display(),
            md.mode() & 0o7777
        )));
    }
    Ok(())
}

/// An advisory lock on a file, released when dropped.
///
/// This is `flock(2)`, so the lock belongs to the open file description: it is
/// inherited across `fork` and released when the last descriptor referring to
/// it is closed. Which is what makes it a fair test of "is something still
/// holding this" and also why it must not be opened twice in one process to
/// "check" it.
#[derive(Debug)]
pub struct FileLock {
    _file: File,
    path: PathBuf,
}

impl FileLock {
    /// Take the lock without waiting. `Ok(None)` means someone else has it.
    pub fn try_acquire(path: &Path) -> Result<Option<FileLock>> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
            .open(path)
            .ctx(|| format!("open lock file {}", path.display()))?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(FileLock { _file: file, path: path.to_path_buf() })),
            Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
            Err(e) => Err(Error::io(format!("lock {}", path.display()), io::Error::from_raw_os_error(e.raw_os_error()))),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Remove a directory tree without following symlinks. `std` has done this
/// safely since 1.58.1; the wrapper exists so the intent is visible at call
/// sites and so a missing directory is not an error.
pub fn remove_dir_all_if_exists(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(format!("remove {}", path.display()), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hrd-fsutil-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn atomic_write_replaces_and_sets_the_mode_regardless_of_umask() {
        let d = scratch("aw");
        let f = d.join("x.json");
        atomic_write(&f, b"one", 0o600).unwrap();
        atomic_write(&f, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"two");
        assert_eq!(fs::metadata(&f).unwrap().mode() & 0o7777, 0o600);
        // no temporary left behind
        let leftovers: Vec<_> = fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn atomic_write_does_not_follow_a_planted_temp_name_or_target_link() {
        let d = scratch("aw-link");
        let victim = d.join("victim");
        fs::write(&victim, b"keep").unwrap();
        let target = d.join("reg.json");
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        // rename replaces the link itself; the file it pointed at is untouched
        atomic_write(&target, b"new", 0o600).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn private_dir_is_created_0700_and_fixed_when_too_open() {
        let d = scratch("pd");
        let p = d.join("a/b/c");
        ensure_private_dir(&p, 0o700).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o7777, 0o700);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&p, 0o700).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o7777, 0o700);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn private_dir_refuses_a_symlink() {
        let d = scratch("pd-link");
        let real = d.join("real");
        fs::create_dir(&real).unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(ensure_private_dir(&link, 0o700), Err(Error::Denied(_))));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn read_limited_enforces_the_limit() {
        let d = scratch("rl");
        let f = d.join("big");
        fs::write(&f, vec![b'x'; 100]).unwrap();
        assert!(read_limited(&f, 100).is_ok());
        assert!(read_limited(&f, 99).is_err());
        assert!(read_limited_opt(&d.join("missing"), 10).unwrap().is_none());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn require_private_file_rejects_group_readable_key_files() {
        let d = scratch("rp");
        let f = d.join("k");
        fs::write(&f, b"secret").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(require_private_file(&f).is_err());
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(require_private_file(&f).is_ok());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_file_lock_excludes_a_second_holder_until_dropped() {
        let d = scratch("lock");
        let f = d.join("l");
        let a = FileLock::try_acquire(&f).unwrap().expect("first acquire");
        assert!(FileLock::try_acquire(&f).unwrap().is_none(), "second acquire must be refused");
        drop(a);
        assert!(FileLock::try_acquire(&f).unwrap().is_some(), "free again after drop");
        fs::remove_dir_all(d).unwrap();
    }
}
