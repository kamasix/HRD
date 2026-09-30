//! cgroup v2: the way the manager knows which processes belong to an instance.
//!
//! A pid is a poor identity. It can be reused, a process can re-exec, and a
//! client leaves helper processes (a compositor, a web process, a plugin
//! runtime) that nobody listed. A cgroup has none of those problems: a process
//! joins it before it runs anything, every descendant it forks is born inside
//! it, and `cgroup.kill` ends all of them at once. That is the ownership
//! primitive this manager uses, and the fallback when it is unavailable
//! ([`crate::procfs::is_same_process`] plus a process group) is reported as
//! weaker rather than hidden.
//!
//! The daemon does not need root for any of this. systemd hands a service a
//! subtree it may manage when the unit says `Delegate=yes`; everything here
//! happens below that.

use std::ffi::CStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags};

/// The cgroup2 mount point, from `/proc/self/mountinfo`.
pub fn find_mount() -> Option<PathBuf> {
    parse_mount(&fs::read_to_string("/proc/self/mountinfo").ok()?)
}

pub fn parse_mount(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(|l| {
        // `... mountpoint ... - fstype source options`; the fields before the
        // hyphen are variable in number, so anchor on the separator.
        let (head, tail) = l.split_once(" - ")?;
        let fstype = tail.split_whitespace().next()?;
        if fstype != "cgroup2" {
            return None;
        }
        head.split_whitespace()
            .nth(4)
            .map(|p| PathBuf::from(unescape_mount(p)))
    })
}

/// `mountinfo` escapes space, tab, newline and backslash as octal.
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// This process's own cgroup directory.
pub fn own() -> Option<Cgroup> {
    let mount = find_mount()?;
    let rel = crate::procfs::cgroup_of(std::process::id())?;
    Some(Cgroup::at(mount.join(rel.trim_start_matches('/'))))
}

#[derive(Debug, Clone)]
pub struct Cgroup {
    dir: PathBuf,
}

/// How [`Cgroup::kill_all`] ended the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillMethod {
    /// `cgroup.kill` (Linux 5.14+): atomic with respect to fork.
    CgroupKill,
    /// A loop of `SIGKILL`s over the member list until it was empty. Racy by
    /// construction (a process can fork between the read and the kill), which
    /// is why the loop repeats.
    Loop,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Memory {
    pub current: Option<u64>,
    pub peak: Option<u64>,
    pub swap_current: Option<u64>,
    pub anon: Option<u64>,
    pub file: Option<u64>,
    pub shmem: Option<u64>,
    pub kernel: Option<u64>,
    pub oom_kill: Option<u64>,
}

impl Cgroup {
    pub fn at(dir: PathBuf) -> Cgroup {
        Cgroup { dir }
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    pub fn exists(&self) -> bool {
        self.dir.join("cgroup.procs").exists()
    }

    fn read(&self, file: &str) -> io::Result<String> {
        fs::read_to_string(self.dir.join(file))
    }

    fn write(&self, file: &str, value: &str) -> io::Result<()> {
        fs::write(self.dir.join(file), value)
    }

    pub fn read_u64(&self, file: &str) -> Option<u64> {
        let t = self.read(file).ok()?;
        let t = t.trim();
        if t == "max" {
            return None;
        }
        t.parse().ok()
    }

    /// Controllers this cgroup may use.
    pub fn controllers(&self) -> Vec<String> {
        self.read("cgroup.controllers")
            .map(|t| t.split_whitespace().map(String::from).collect())
            .unwrap_or_default()
    }

    /// Controllers enabled for its children.
    pub fn subtree_controllers(&self) -> Vec<String> {
        self.read("cgroup.subtree_control")
            .map(|t| t.split_whitespace().map(String::from).collect())
            .unwrap_or_default()
    }

    /// Enable whichever of `wanted` the cgroup has, one at a time so that one
    /// refusal does not hide the others. Returns what ended up enabled.
    ///
    /// Fails for a non-leaf-rule reason if this cgroup still contains
    /// processes: the kernel forbids enabling a domain controller for children
    /// of a cgroup that has its own processes.
    pub fn enable_subtree(&self, wanted: &[&str]) -> io::Result<Vec<String>> {
        let have = self.controllers();
        let mut last_err = None;
        for w in wanted {
            if have.iter().any(|h| h == w) && !self.subtree_controllers().iter().any(|h| h == w) {
                if let Err(e) = self.write("cgroup.subtree_control", &format!("+{w}")) {
                    last_err = Some(e);
                }
            }
        }
        let now = self.subtree_controllers();
        if now.is_empty() {
            if let Some(e) = last_err {
                return Err(e);
            }
        }
        Ok(now)
    }

    pub fn create(&self, name: &str) -> io::Result<Cgroup> {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\0')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad cgroup name {name:?}"),
            ));
        }
        let dir = self.dir.join(name);
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        Ok(Cgroup { dir })
    }

    pub fn child(&self, name: &str) -> Cgroup {
        Cgroup {
            dir: self.dir.join(name),
        }
    }

    pub fn add_pid(&self, pid: u32) -> io::Result<()> {
        self.write("cgroup.procs", &pid.to_string())
    }

    pub fn pids(&self) -> io::Result<Vec<u32>> {
        Ok(self
            .read("cgroup.procs")?
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect())
    }

    /// Whether any process is in this cgroup or below it. Kernel-maintained,
    /// so it is true for a zombie nobody has reaped yet.
    pub fn populated(&self) -> io::Result<bool> {
        Ok(self
            .read("cgroup.events")?
            .lines()
            .any(|l| l.trim() == "populated 1"))
    }

    /// Kill everything in the cgroup and below it. Does not wait.
    pub fn kill_all(&self) -> io::Result<KillMethod> {
        if self.dir.join("cgroup.kill").exists() {
            self.write("cgroup.kill", "1")?;
            return Ok(KillMethod::CgroupKill);
        }
        for _ in 0..50 {
            let pids = self.pids()?;
            if pids.is_empty() {
                break;
            }
            for pid in pids {
                if let Some(p) = rustix::process::Pid::from_raw(pid as i32) {
                    let _ = rustix::process::kill_process(p, rustix::process::Signal::KILL);
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(KillMethod::Loop)
    }

    /// Wait until [`populated`](Self::populated) is false, up to `timeout`.
    pub fn wait_empty(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        loop {
            match self.populated() {
                Ok(false) => return true,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return true,
                _ => {}
            }
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Remove the (empty) cgroup. A cgroup that is gone is success.
    pub fn remove(&self) -> io::Result<()> {
        match fs::remove_dir(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Set one limit file. `value` is the kernel's own syntax (`max`, a number).
    pub fn set(&self, file: &str, value: &str) -> io::Result<()> {
        self.write(file, value)
    }

    pub fn memory(&self) -> Memory {
        let stat = self
            .read("memory.stat")
            .ok()
            .map(|t| parse_flat_keyed(&t))
            .unwrap_or_default();
        let events = self
            .read("memory.events")
            .ok()
            .map(|t| parse_flat_keyed(&t))
            .unwrap_or_default();
        Memory {
            current: self.read_u64("memory.current"),
            peak: self.read_u64("memory.peak"),
            swap_current: self.read_u64("memory.swap.current"),
            anon: stat.get("anon").copied(),
            file: stat.get("file").copied(),
            shmem: stat.get("shmem").copied(),
            kernel: stat.get("kernel").copied(),
            oom_kill: events.get("oom_kill").copied(),
        }
    }

    /// Total CPU time used by the cgroup, in microseconds. Unlike summing
    /// `/proc/<pid>/stat` this includes processes that have since exited.
    pub fn cpu_usage_usec(&self) -> Option<u64> {
        parse_flat_keyed(&self.read("cpu.stat").ok()?)
            .get("usage_usec")
            .copied()
    }

    pub fn pids_current(&self) -> Option<u64> {
        self.read_u64("pids.current")
    }
}

/// `key value` per line.
pub fn parse_flat_keyed(text: &str) -> std::collections::HashMap<String, u64> {
    text.lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            Some((p.next()?.to_string(), p.next()?.parse().ok()?))
        })
        .collect()
}

/// Move the calling process into the cgroup whose `cgroup.procs` path is given.
///
/// For use in a `pre_exec` hook: it performs only `open`, `write` and `close`
/// on a path prepared before the fork, allocates nothing and formats nothing,
/// which is what makes it acceptable between `fork` and `exec` in a
/// multi-threaded parent. Writing `0` means "the writing process".
pub fn enter_prepared(procs_file: &CStr) -> io::Result<()> {
    let fd = rustix::fs::open(procs_file, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(io::Error::from)?;
    let r = rustix::io::write(&fd, b"0").map_err(io::Error::from);
    drop(fd);
    r.map(|_| ())
}

/// What a manager needs from a delegated subtree: a leaf for itself, a parent
/// for instances, and the list of controllers that actually work.
#[derive(Debug, Clone)]
pub struct Delegated {
    pub manager: Cgroup,
    pub instances: Cgroup,
    pub controllers: Vec<String>,
}

/// Prepare `base` (the service's own cgroup) for per-instance children:
/// move this process to a `manager` leaf, then enable controllers on `base` and
/// on `instances`.
///
/// The order is forced by the kernel's "no internal processes" rule. The
/// daemon is *in* `base` when it starts, and a cgroup that has processes cannot
/// hand controllers to its children, so the daemon has to step aside first.
pub fn prepare_delegated(base: &Cgroup, self_pid: u32) -> io::Result<Delegated> {
    let manager = base.create("manager")?;
    manager.add_pid(self_pid)?;
    let wanted = ["memory", "pids", "cpu"];
    let enabled = base.enable_subtree(&wanted)?;
    let instances = base.create("instances")?;
    let _ = instances.enable_subtree(&wanted);
    let controllers: Vec<String> = instances.subtree_controllers();
    let _ = enabled;
    Ok(Delegated {
        manager,
        instances,
        controllers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_point_is_found_despite_variable_optional_fields() {
        let mi = "25 30 0:23 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 master:7 - cgroup2 cgroup2 rw,nsdelegate\n31 1 8:1 / / rw - ext4 /dev/sda1 rw\n";
        assert_eq!(parse_mount(mi), Some(PathBuf::from("/sys/fs/cgroup")));
        assert_eq!(parse_mount("31 1 8:1 / / rw - ext4 /dev/sda1 rw\n"), None);
        // v1 mounts named cgroup must not be mistaken for v2
        assert_eq!(
            parse_mount("40 30 0:30 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n"),
            None
        );
    }

    #[test]
    fn mount_paths_with_spaces_are_unescaped() {
        let mi = "25 30 0:23 / /mnt/my\\040cg rw - cgroup2 cgroup2 rw\n";
        assert_eq!(parse_mount(mi), Some(PathBuf::from("/mnt/my cg")));
    }

    #[test]
    fn flat_keyed() {
        let m = parse_flat_keyed("anon 100\nfile 200\nweird\nshmem x\n");
        assert_eq!(m.get("anon"), Some(&100));
        assert_eq!(m.get("file"), Some(&200));
        assert!(!m.contains_key("shmem"));
    }

    #[test]
    fn child_names_cannot_climb() {
        let cg = Cgroup::at(PathBuf::from("/nonexistent"));
        for bad in ["", ".", "..", "a/b", "../x", "a\0b"] {
            assert!(cg.create(bad).is_err(), "{bad:?}");
        }
    }

    /// A fake cgroup directory made of ordinary files exercises the parsing of
    /// the files the kernel would provide. It cannot prove the kernel behaves;
    /// `scripts/check-cgroup.sh` does that on a real host.
    #[test]
    fn memory_reads_a_directory_shaped_like_a_cgroup() {
        let d = std::env::temp_dir().join(format!("hrd-cg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("memory.current"), "1048576\n").unwrap();
        fs::write(d.join("memory.peak"), "2097152\n").unwrap();
        fs::write(d.join("memory.swap.current"), "0\n").unwrap();
        fs::write(
            d.join("memory.stat"),
            "anon 700000\nfile 300000\nshmem 1000\nkernel 50000\n",
        )
        .unwrap();
        fs::write(
            d.join("memory.events"),
            "low 0\nhigh 0\nmax 0\noom 1\noom_kill 1\n",
        )
        .unwrap();
        fs::write(
            d.join("cpu.stat"),
            "usage_usec 5000000\nuser_usec 4000000\n",
        )
        .unwrap();
        fs::write(d.join("memory.max"), "max\n").unwrap();
        let cg = Cgroup::at(d.clone());
        let m = cg.memory();
        assert_eq!(m.current, Some(1048576));
        assert_eq!(m.peak, Some(2097152));
        assert_eq!(m.anon, Some(700000));
        assert_eq!(m.oom_kill, Some(1));
        assert_eq!(cg.cpu_usage_usec(), Some(5_000_000));
        assert_eq!(cg.read_u64("memory.max"), None, "\"max\" is not a number");
        assert_eq!(cg.read_u64("does.not.exist"), None);
        fs::remove_dir_all(d).unwrap();
    }
}
