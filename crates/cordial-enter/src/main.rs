//! `cordial-enter`
//!
//! ```text
//! cordial-enter run   --group NAME -- /absolute/program [args...]
//! cordial-enter check --group NAME
//! ```
//!
//! **`run`** puts the process into the network namespace of the group `NAME`,
//! gives it a private mount namespace in which the group's `resolv.conf` and
//! `nsswitch.conf` replace the host's (and the sockets that would carry a name
//! lookup around the tunnel are masked), then gives up every privilege and
//! `exec`s the program. It is installed with one file capability,
//! `cap_sys_admin`, which it needs for `setns(2)`, `unshare(2)` and `mount(2)`;
//! after the last of those it sets `no_new_privs`, empties the capability sets
//! and checks that they are empty, *before* it executes anything it was given.
//!
//! What it will not do: run as anyone else (it never changes uid), open any
//! namespace that is not a file under `/run/cordial-hrd/netns` on an `nsfs`
//! mount owned by root, read its environment to decide a path, or follow a
//! symlink. The namespace directory is a constant, not an option: an option
//! that chose the directory would let the caller pick which namespace to enter.
//!
//! **`check`** runs unprivileged, inside the client, through the profile's
//! `network.json` gate: it succeeds only if the process is in the group's
//! namespace and sees no interface but `lo` and `wg0`.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use rustix::fs::OFlags;
use rustix::mount::{mount_bind, mount_change, MountPropagationFlags};
use rustix::thread::{CapabilitySet, CapabilitySets, LinkNameSpaceType, UnshareFlags};

const NS_DIR: &str = "/run/cordial-hrd/netns";
const NSFS_MAGIC: u64 = 0x6e73_6673;
const IFACE: &str = "wg0";

const USAGE: &str = "usage:\n  cordial-enter run --group NAME -- /absolute/program [args...]\n  cordial-enter check --group NAME\n";

fn die(code: u8, msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("cordial-enter: {msg}");
    ExitCode::from(code)
}

fn valid_group(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 24
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && !s.ends_with('-')
}

fn ns_file(group: &str) -> PathBuf {
    Path::new(NS_DIR).join(group)
}

/// The namespace directory and the handle in it must be root's and closed to
/// everyone else, and the handle must be an `nsfs` file.
fn open_group_ns(group: &str) -> Result<File, String> {
    let dir = fs::symlink_metadata(NS_DIR).map_err(|e| format!("{NS_DIR}: {e}"))?;
    if !dir.is_dir() || dir.uid() != 0 || dir.mode() & 0o022 != 0 {
        return Err(format!(
            "{NS_DIR} must be a directory owned by root and not writable by others"
        ));
    }
    let path = ns_file(group);
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(&path)
        .map_err(|e| {
            format!(
                "open {}: {e} (is the group applied? `cordialctl network apply`)",
                path.display()
            )
        })?;
    let st = rustix::fs::fstatfs(&f)
        .map_err(|e| format!("fstatfs {}: {}", path.display(), io::Error::from(e)))?;
    if st.f_type as u64 != NSFS_MAGIC {
        return Err(format!("{} is not a network namespace", path.display()));
    }
    let md = f
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    if md.uid() != 0 {
        return Err(format!("{} is not owned by root", path.display()));
    }
    Ok(f)
}

fn overlay(source: &Path, target: &str) -> Result<(), String> {
    let md = fs::symlink_metadata(source).map_err(|e| format!("{}: {e}", source.display()))?;
    if !md.is_file() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(format!(
            "{} must be a regular file owned by root and not writable by others",
            source.display()
        ));
    }
    mount_bind(source, target)
        .map_err(|e| format!("cannot overlay {target}: {}", io::Error::from(e)))
}

fn mask(target: &str) {
    // A missing socket needs no masking; a mask that fails is only worth a
    // warning because the name-service switch no longer names the service.
    if fs::symlink_metadata(target).is_ok() {
        if let Err(e) = mount_bind("/dev/null", target) {
            eprintln!(
                "cordial-enter: warning: could not mask {target}: {}",
                io::Error::from(e)
            );
        }
    }
}

fn drop_everything() -> Result<(), String> {
    rustix::thread::set_no_new_privs(true)
        .map_err(|e| format!("no_new_privs: {}", io::Error::from(e)))?;
    let _ = rustix::thread::clear_ambient_capability_set();
    let empty = CapabilitySet::empty();
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: empty,
            permitted: empty,
            inheritable: empty,
        },
    )
    .map_err(|e| format!("dropping capabilities: {}", io::Error::from(e)))?;
    // Trust, but look.
    let now = rustix::thread::capabilities(None)
        .map_err(|e| format!("reading capabilities back: {}", io::Error::from(e)))?;
    if !now.effective.is_empty() || !now.permitted.is_empty() || !now.inheritable.is_empty() {
        return Err("capabilities are still present after dropping them".into());
    }
    if !rustix::thread::no_new_privs().unwrap_or(false) {
        return Err("no_new_privs is not set".into());
    }
    Ok(())
}

fn run(
    group: &str,
    program: OsString,
    args: Vec<OsString>,
) -> Result<std::convert::Infallible, String> {
    let ns = open_group_ns(group)?;
    let resolv = Path::new(NS_DIR).join(format!("{group}.resolv.conf"));
    let nss = Path::new(NS_DIR).join(format!("{group}.nsswitch.conf"));

    rustix::thread::move_into_link_name_space(ns.as_fd(), Some(LinkNameSpaceType::Network))
        .map_err(|e| format!("setns: {} (the file needs cap_sys_admin, and the caller must not have no_new_privs set)", io::Error::from(e)))?;
    drop(ns);

    // SAFETY: `NEWNS` gives this process its own copy of the mount table. The
    // hazardous flag of `unshare_unsafe` is `FILES`, which is not used, and the
    // process is single-threaded.
    #[allow(unsafe_code)]
    unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWNS) }
        .map_err(|e| format!("unshare mount namespace: {}", io::Error::from(e)))?;
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(|e| format!("making mounts private: {}", io::Error::from(e)))?;

    overlay(&resolv, "/etc/resolv.conf")?;
    overlay(&nss, "/etc/nsswitch.conf")?;
    mask("/run/nscd/socket");
    mask("/var/run/nscd/socket");
    mask("/run/systemd/resolve/io.systemd.Resolve");

    drop_everything()?;

    let err = Command::new(&program).args(&args).exec();
    Err(format!("exec {}: {err}", Path::new(&program).display()))
}

/// Unprivileged: is this process in the group's namespace, and alone in it?
fn check(group: &str) -> Result<(), String> {
    let handle = ns_file(group);
    let want = fs::metadata(&handle).map_err(|e| format!("{}: {e}", handle.display()))?;
    let have = fs::metadata("/proc/self/ns/net").map_err(|e| format!("/proc/self/ns/net: {e}"))?;
    if (want.dev(), want.ino()) != (have.dev(), have.ino()) {
        return Err(format!("this process is not in the network namespace of group {group}; it would leave through the host's own network"));
    }
    let dev =
        fs::read_to_string("/proc/self/net/dev").map_err(|e| format!("/proc/self/net/dev: {e}"))?;
    let names: Vec<&str> = dev
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next())
        .map(str::trim)
        .collect();
    if let Some(extra) = names.iter().find(|n| **n != "lo" && **n != IFACE) {
        return Err(format!(
            "the namespace has an interface other than lo and {IFACE}: {extra}"
        ));
    }
    if !names.contains(&IFACE) {
        return Err(format!(
            "the namespace has no {IFACE}: the group's tunnel is not up"
        ));
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(cmd) = args.next() else {
        return die(2, USAGE);
    };
    let flag = args.next();
    let group = args.next();
    let (Some(flag), Some(group)) = (flag, group) else {
        return die(2, USAGE);
    };
    let group = match (flag.to_str(), group.to_str()) {
        (Some("--group"), Some(g)) if valid_group(g) => g.to_string(),
        (Some("--group"), _) => return die(2, "the group name is not valid"),
        _ => return die(2, USAGE),
    };
    match cmd.to_str() {
        Some("run") => {
            if args.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
                return die(2, USAGE);
            }
            let Some(program) = args.next() else {
                return die(2, USAGE);
            };
            if !Path::new(&program).is_absolute() {
                return die(2, "the program must be an absolute path");
            }
            match run(&group, program, args.collect()) {
                Ok(never) => match never {},
                Err(e) => die(126, e),
            }
        }
        Some("check") => {
            if args.next().is_some() {
                return die(2, USAGE);
            }
            // Give up what the file granted before doing anything else; this
            // mode needs none of it.
            let _ = drop_everything();
            match check(&group) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => die(1, e),
            }
        }
        _ => die(2, USAGE),
    }
}
