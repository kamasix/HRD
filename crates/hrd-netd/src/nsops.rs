//! Named network namespaces, kept as bind-mounted files.
//!
//! A namespace normally dies with the last process in it. `ip netns add` keeps
//! one alive by bind-mounting the namespace's `/proc/<pid>/ns/net` onto an
//! ordinary file, and this does the same under the manager's own directory so
//! the manager never touches `/run/netns` (which other tools own). The mount
//! outlives this helper: restarting `hrd-netd` does not disturb a running
//! client's network.

#![allow(unsafe_code)] // `unshare_unsafe(NEWNET)`; see `create`

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use hrd_core::ids::GroupName;
use hrd_core::{Error, Result};
use rustix::fs::OFlags;
use rustix::mount::{mount_bind, unmount, UnmountFlags};
use rustix::thread::{move_into_link_name_space, LinkNameSpaceType, UnshareFlags};

/// `statfs.f_type` of the filesystem that backs namespace handles.
pub const NSFS_MAGIC: u64 = 0x6e73_6673;

pub fn is_nsfs(path: &Path) -> bool {
    rustix::fs::statfs(path)
        .map(|s| s.f_type as u64 == NSFS_MAGIC)
        .unwrap_or(false)
}

fn ensure_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() && m.uid() == 0 => Ok(()),
        Ok(_) => Err(Error::Denied(format!(
            "{} must be a directory owned by root",
            dir.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(dir)
            .map_err(|e| Error::io(format!("create {}", dir.display()), e)),
        Err(e) => Err(Error::io(format!("stat {}", dir.display()), e)),
    }
}

/// Create the namespace `name` under `dir` if it does not exist. Idempotent.
pub fn create(dir: &Path, name: &GroupName) -> Result<()> {
    ensure_dir(dir)?;
    let path = dir.join(name.as_str());
    if is_nsfs(&path) {
        return Ok(());
    }
    match fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() && m.len() == 0 => {
            fs::remove_file(&path).map_err(|e| Error::io("remove a stale placeholder", e))?
        }
        Ok(_) => {
            return Err(Error::conflict(format!(
                "{} exists and is not a namespace",
                path.display()
            )))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(format!("stat {}", path.display()), e)),
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(&path)
        .map_err(|e| Error::io(format!("create {}", path.display()), e))?;

    let target = path.clone();
    let result = std::thread::spawn(move || -> io::Result<()> {
        // SAFETY: `NEWNET` detaches only this thread's network namespace. The
        // documented hazard of `unshare_unsafe` is `FILES`, which this does not
        // use. The thread ends right after the bind mount, so nothing else ever
        // runs in the new namespace from here.
        unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWNET) }.map_err(io::Error::from)?;
        mount_bind("/proc/thread-self/ns/net", &target).map_err(io::Error::from)
    })
    .join();
    let outcome = match result {
        Ok(r) => r.map_err(|e| Error::io(format!("create the namespace {}", path.display()), e)),
        Err(_) => Err(Error::Internal("the namespace thread panicked".into())),
    };
    if outcome.is_err() {
        let _ = fs::remove_file(&path);
    }
    outcome
}

/// Remove the namespace and the files generated for it. Idempotent.
pub fn remove(dir: &Path, name: &GroupName) -> Result<()> {
    let path = dir.join(name.as_str());
    if is_nsfs(&path) {
        unmount(&path, UnmountFlags::DETACH)
            .map_err(|e| Error::io(format!("unmount {}", path.display()), io::Error::from(e)))?;
    }
    for p in [
        path,
        dir.join(format!("{name}.resolv.conf")),
        dir.join(format!("{name}.nsswitch.conf")),
    ] {
        match fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(format!("remove {}", p.display()), e)),
        }
    }
    Ok(())
}

/// Open a namespace handle, refusing anything that is not a namespace.
pub fn open(path: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(path)
        .map_err(|e| Error::io(format!("open {}", path.display()), e))?;
    let st = rustix::fs::fstatfs(&f).map_err(|e| Error::io("fstatfs", io::Error::from(e)))?;
    if st.f_type as u64 != NSFS_MAGIC {
        return Err(Error::conflict(format!(
            "{} is not a network namespace",
            path.display()
        )));
    }
    Ok(f)
}

/// Run `f` on a fresh thread that has entered `ns`. Only that thread moves.
pub fn in_netns<T: Send + 'static>(ns: &File, f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    let ns = ns
        .try_clone()
        .map_err(|e| Error::io("duplicate the namespace descriptor", e))?;
    std::thread::spawn(move || -> io::Result<T> {
        move_into_link_name_space(ns.as_fd(), Some(LinkNameSpaceType::Network))
            .map_err(io::Error::from)?;
        Ok(f())
    })
    .join()
    .map_err(|_| Error::Internal("the namespace thread panicked".into()))?
    .map_err(|e| Error::io("enter the namespace", e))
}

/// Write a sysctl as the namespace sees it.
pub fn sysctl(ns: &File, key: &str, value: &str) -> Result<()> {
    if !key
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
        || key.contains("..")
    {
        return Err(Error::invalid(format!("not a sysctl name: {key:?}")));
    }
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    let value = value.to_string();
    in_netns(ns, move || {
        fs::write(&path, value).map_err(|e| Error::io(format!("write {path}"), e))
    })?
}
