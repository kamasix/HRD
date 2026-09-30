//! `/proc` parsers. Each takes text and returns a value, so the format handling
//! is testable without a live process; the `read_*` wrappers are one line each.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn clock_ticks_per_second() -> u64 {
    rustix::param::clock_ticks_per_second().max(1)
}

pub fn page_size() -> u64 {
    rustix::param::page_size() as u64
}

// ---------------------------------------------------------------------------
// /proc/<pid>/stat
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    /// Clock ticks of CPU time in user and kernel mode. Children that have been
    /// waited for are not included (`cutime`/`cstime` are ignored on purpose:
    /// they are credited to the parent after the child is gone and would make a
    /// restarted process look like a CPU burst).
    pub utime: u64,
    pub stime: u64,
    pub num_threads: u32,
    /// Clock ticks after boot at which the process started. Together with the
    /// pid this identifies one process for the life of the machine.
    pub start_ticks: u64,
    pub vsize: u64,
    pub rss_pages: i64,
}

impl Stat {
    pub fn cpu_ticks(&self) -> u64 {
        self.utime + self.stime
    }
}

/// Parse one `/proc/<pid>/stat` line.
///
/// `comm` is in parentheses and may itself contain spaces and parentheses
/// (the engine renames its main thread, and a process can be called anything),
/// so the split is at the *last* `)`. Splitting on whitespace from the left is
/// the classic way to misread every field after a name like `Web Content`.
pub fn parse_stat(line: &str) -> Option<Stat> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close < open {
        return None;
    }
    let pid: u32 = line[..open].trim().parse().ok()?;
    let comm = line[open + 1..close].to_string();
    let rest: Vec<&str> = line[close + 1..].split_whitespace().collect();
    // Index 0 is field 3 (state); field N is at index N-3.
    let f = |n: usize| rest.get(n - 3).copied();
    Some(Stat {
        pid,
        comm,
        state: f(3)?.chars().next()?,
        ppid: f(4)?.parse().ok()?,
        pgrp: f(5)?.parse().ok()?,
        session: f(6)?.parse().ok()?,
        utime: f(14)?.parse().ok()?,
        stime: f(15)?.parse().ok()?,
        num_threads: f(20)?.parse().ok()?,
        start_ticks: f(22)?.parse().ok()?,
        vsize: f(23)?.parse().ok()?,
        rss_pages: f(24)?.parse().ok()?,
    })
}

pub fn read_stat(pid: u32) -> io::Result<Stat> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_stat(&text).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unparseable /proc/{pid}/stat"),
        )
    })
}

/// Start ticks alone, for checking that a pid still names the same process.
pub fn start_ticks(pid: u32) -> Option<u64> {
    read_stat(pid).ok().map(|s| s.start_ticks)
}

/// True if `pid` exists and started at `start_ticks`: the pid has not been
/// reused. A pid is only a name until this holds.
pub fn is_same_process(pid: u32, start_ticks_expected: u64) -> bool {
    start_ticks(pid) == Some(start_ticks_expected)
}

// ---------------------------------------------------------------------------
// /proc/<pid>/status
// ---------------------------------------------------------------------------

/// `Key:\tvalue` lines as a map. Values keep their unit text (`123 kB`).
pub fn parse_kv(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// `"123 kB"` → bytes. A bare number is taken as bytes.
pub fn kb_to_bytes(v: &str) -> Option<u64> {
    let mut it = v.split_whitespace();
    let n: u64 = it.next()?.parse().ok()?;
    match it.next() {
        Some("kB") | Some("KB") | Some("kb") => n.checked_mul(1024),
        Some(_) => None,
        None => Some(n),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub vm_rss: Option<u64>,
    pub rss_anon: Option<u64>,
    pub rss_file: Option<u64>,
    pub rss_shmem: Option<u64>,
    pub vm_swap: Option<u64>,
    pub threads: Option<u32>,
    pub uid: Option<u32>,
}

pub fn parse_status(text: &str) -> Status {
    let kv = parse_kv(text);
    let b = |k: &str| kv.get(k).and_then(|v| kb_to_bytes(v));
    Status {
        vm_rss: b("VmRSS"),
        rss_anon: b("RssAnon"),
        rss_file: b("RssFile"),
        rss_shmem: b("RssShmem"),
        vm_swap: b("VmSwap"),
        threads: kv.get("Threads").and_then(|v| v.parse().ok()),
        uid: kv
            .get("Uid")
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse().ok()),
    }
}

pub fn read_status(pid: u32) -> io::Result<Status> {
    Ok(parse_status(&fs::read_to_string(format!(
        "/proc/{pid}/status"
    ))?))
}

// ---------------------------------------------------------------------------
// /proc/<pid>/smaps_rollup
// ---------------------------------------------------------------------------

/// The memory picture of one process, in bytes. Every field is optional
/// because `smaps_rollup` needs Linux 4.14 and `SwapPss`/`Pss_*` are newer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smaps {
    pub rss: Option<u64>,
    pub pss: Option<u64>,
    pub pss_anon: Option<u64>,
    pub pss_file: Option<u64>,
    pub pss_shmem: Option<u64>,
    pub shared_clean: Option<u64>,
    pub shared_dirty: Option<u64>,
    pub private_clean: Option<u64>,
    pub private_dirty: Option<u64>,
    pub anonymous: Option<u64>,
    pub swap: Option<u64>,
    pub swap_pss: Option<u64>,
}

impl Smaps {
    /// Private memory: what would be returned to the system if this process,
    /// alone, exited. `None` unless both halves were reported.
    pub fn uss(&self) -> Option<u64> {
        Some(self.private_clean? + self.private_dirty?)
    }
}

pub fn parse_smaps_rollup(text: &str) -> Smaps {
    let kv = parse_kv(text);
    let b = |k: &str| kv.get(k).and_then(|v| kb_to_bytes(v));
    Smaps {
        rss: b("Rss"),
        pss: b("Pss"),
        pss_anon: b("Pss_Anon"),
        pss_file: b("Pss_File"),
        pss_shmem: b("Pss_Shmem"),
        shared_clean: b("Shared_Clean"),
        shared_dirty: b("Shared_Dirty"),
        private_clean: b("Private_Clean"),
        private_dirty: b("Private_Dirty"),
        anonymous: b("Anonymous"),
        swap: b("Swap"),
        swap_pss: b("SwapPss"),
    }
}

/// Reads `smaps_rollup`, which makes the kernel walk the process's address
/// space. That is why the sampler calls it far less often than it reads
/// `stat`.
pub fn read_smaps_rollup(pid: u32) -> io::Result<Smaps> {
    Ok(parse_smaps_rollup(&fs::read_to_string(format!(
        "/proc/{pid}/smaps_rollup"
    ))?))
}

// ---------------------------------------------------------------------------
// Identity of a process: exe and cgroup
// ---------------------------------------------------------------------------

/// The basename of `/proc/<pid>/exe`, which names the program and not the
/// thread. `comm` is unreliable here: the engine renames its main thread, so a
/// running client reads `Main`.
pub fn exe_basename(pid: u32) -> Option<String> {
    let target = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let name = target.file_name()?.to_string_lossy().into_owned();
    Some(
        name.strip_suffix(" (deleted)")
            .map(str::to_string)
            .unwrap_or(name),
    )
}

/// The cgroup v2 path of a process (the `0::` line), relative to the mount.
pub fn cgroup_of(pid: u32) -> Option<String> {
    parse_cgroup_v2(&fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?)
}

pub fn parse_cgroup_v2(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.to_string())
}

// ---------------------------------------------------------------------------
// System-wide
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total: Option<u64>,
    pub available: Option<u64>,
    pub swap_total: Option<u64>,
    pub swap_free: Option<u64>,
}

pub fn parse_meminfo(text: &str) -> MemInfo {
    let kv = parse_kv(text);
    let b = |k: &str| kv.get(k).and_then(|v| kb_to_bytes(v));
    MemInfo {
        total: b("MemTotal"),
        available: b("MemAvailable"),
        swap_total: b("SwapTotal"),
        swap_free: b("SwapFree"),
    }
}

pub fn read_meminfo() -> io::Result<MemInfo> {
    Ok(parse_meminfo(&fs::read_to_string("/proc/meminfo")?))
}

/// Pressure Stall Information, percent of time some / all tasks were stalled.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Psi {
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub full_avg10: f64,
}

pub fn parse_psi(text: &str) -> Option<Psi> {
    let mut out = Psi::default();
    let mut seen = false;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let kind = parts.next()?;
        let mut a10 = None;
        let mut a60 = None;
        for p in parts {
            if let Some(v) = p.strip_prefix("avg10=") {
                a10 = v.parse().ok();
            } else if let Some(v) = p.strip_prefix("avg60=") {
                a60 = v.parse().ok();
            }
        }
        match kind {
            "some" => {
                out.some_avg10 = a10?;
                out.some_avg60 = a60.unwrap_or(0.0);
                seen = true;
            }
            "full" => out.full_avg10 = a10?,
            _ => {}
        }
    }
    seen.then_some(out)
}

pub fn read_memory_psi() -> Option<Psi> {
    parse_psi(&fs::read_to_string("/proc/pressure/memory").ok()?)
}

/// All numeric entries of `/proc`.
pub fn list_pids() -> Vec<u32> {
    fs::read_dir("/proc")
        .map(|d| {
            d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Network counters of the namespace a pid lives in
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetDev {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub fn parse_net_dev(text: &str) -> Vec<NetDev> {
    text.lines()
        .skip(2)
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let f: Vec<&str> = rest.split_whitespace().collect();
            Some(NetDev {
                name: name.trim().to_string(),
                rx_bytes: f.first()?.parse().ok()?,
                tx_bytes: f.get(8)?.parse().ok()?,
            })
        })
        .collect()
}

/// Interface counters as seen from `pid`'s network namespace. Reading them
/// through a process that is inside a group's namespace is how the manager
/// sees that group's traffic without entering the namespace itself.
pub fn read_net_dev(pid: u32) -> io::Result<Vec<NetDev>> {
    Ok(parse_net_dev(&fs::read_to_string(format!(
        "/proc/{pid}/net/dev"
    ))?))
}

/// The inode of the network namespace `pid` is in, as the kernel names it.
pub fn netns_inode(pid: u32) -> Option<u64> {
    ns_inode(Path::new(&format!("/proc/{pid}/ns/net")))
}

pub fn ns_inode(p: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).ok().map(|m| m.ino())
}

pub fn proc_dir(pid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "4242 (Web (Content) x) S 1 4242 4242 0 -1 4194560 1234 0 5 0 120 30 0 0 20 0 7 0 987654 1234567890 4321 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";

    #[test]
    fn stat_survives_a_comm_with_spaces_and_parentheses() {
        let s = parse_stat(STAT).unwrap();
        assert_eq!(s.pid, 4242);
        assert_eq!(s.comm, "Web (Content) x");
        assert_eq!(s.state, 'S');
        assert_eq!(s.ppid, 1);
        assert_eq!(s.utime, 120);
        assert_eq!(s.stime, 30);
        assert_eq!(s.cpu_ticks(), 150);
        assert_eq!(s.num_threads, 7);
        assert_eq!(s.start_ticks, 987654);
        assert_eq!(s.vsize, 1234567890);
        assert_eq!(s.rss_pages, 4321);
    }

    #[test]
    fn stat_rejects_truncated_lines() {
        assert!(parse_stat("1 (x) S 1").is_none());
        assert!(parse_stat("garbage").is_none());
        assert!(parse_stat("").is_none());
    }

    #[test]
    fn status_units_are_converted() {
        let t = "Name:\tMain\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t  2048 kB\nRssAnon:\t1024 kB\nRssFile:\t1000 kB\nRssShmem:\t24 kB\nVmSwap:\t0 kB\nThreads:\t61\n";
        let s = parse_status(t);
        assert_eq!(s.vm_rss, Some(2048 * 1024));
        assert_eq!(s.rss_file, Some(1000 * 1024));
        assert_eq!(s.vm_swap, Some(0));
        assert_eq!(s.threads, Some(61));
        assert_eq!(s.uid, Some(1000));
    }

    #[test]
    fn smaps_rollup_keeps_shared_and_private_apart() {
        let t = "00400000-ff601000 ---p 00000000 00:00 0   [rollup]\nRss:  1000 kB\nPss:  400 kB\nPss_Anon: 100 kB\nPss_File: 290 kB\nPss_Shmem: 10 kB\nShared_Clean: 700 kB\nShared_Dirty: 10 kB\nPrivate_Clean: 90 kB\nPrivate_Dirty: 200 kB\nAnonymous: 210 kB\nSwap: 5 kB\nSwapPss: 4 kB\n";
        let s = parse_smaps_rollup(t);
        assert_eq!(s.rss, Some(1000 * 1024));
        assert_eq!(s.pss, Some(400 * 1024));
        assert_eq!(s.uss(), Some(290 * 1024));
        assert!(s.pss.unwrap() < s.rss.unwrap(), "pss divides shared pages");
        assert_eq!(s.swap_pss, Some(4 * 1024));
    }

    #[test]
    fn a_missing_half_means_no_uss_not_a_wrong_one() {
        let s = parse_smaps_rollup("Private_Dirty: 200 kB\n");
        assert_eq!(s.uss(), None);
    }

    #[test]
    fn meminfo_and_psi() {
        let m = parse_meminfo(
            "MemTotal: 16000000 kB\nMemAvailable: 12000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        );
        assert_eq!(m.available, Some(12_000_000 * 1024));
        let p = parse_psi("some avg10=1.50 avg60=0.75 avg300=0.10 total=123\nfull avg10=0.25 avg60=0.10 avg300=0.00 total=9\n").unwrap();
        assert_eq!(p.some_avg10, 1.5);
        assert_eq!(p.full_avg10, 0.25);
        assert!(parse_psi("").is_none());
    }

    #[test]
    fn cgroup_line_and_net_dev() {
        assert_eq!(
            parse_cgroup_v2("12:cpu:/x\n0::/system.slice/cordiald.service/i/alt-1\n").as_deref(),
            Some("/system.slice/cordiald.service/i/alt-1")
        );
        assert_eq!(parse_cgroup_v2("1:name=systemd:/\n"), None);
        let nd = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n   wg0:  123456     100    0    0    0     0          0         0   654321     90    0    0    0     0       0          0\n";
        let d = parse_net_dev(nd);
        assert_eq!(d.len(), 2);
        assert_eq!(
            d[1],
            NetDev {
                name: "wg0".into(),
                rx_bytes: 123456,
                tx_bytes: 654321
            }
        );
    }

    // The two tests below read the real /proc of the test process itself. They
    // start nothing and touch nothing outside this process.
    #[test]
    fn this_process_can_be_read_back() {
        let pid = std::process::id();
        let s = read_stat(pid).unwrap();
        assert_eq!(s.pid, pid);
        assert!(is_same_process(pid, s.start_ticks));
        assert!(!is_same_process(pid, s.start_ticks + 1));
        assert!(read_status(pid).unwrap().vm_rss.unwrap() > 0);
        assert!(exe_basename(pid).is_some());
        assert!(read_meminfo().unwrap().available.is_some());
    }

    #[test]
    fn smaps_rollup_of_this_process_is_consistent() {
        if let Ok(s) = read_smaps_rollup(std::process::id()) {
            let (rss, pss) = (s.rss.unwrap(), s.pss.unwrap());
            assert!(pss <= rss, "PSS {pss} cannot exceed RSS {rss}");
            assert!(s.uss().unwrap() <= rss);
        }
    }
}
