//! Per-process samples, classified and summed without double counting.

use std::collections::HashMap;

use hrd_core::proto::ClassStats;

use crate::procfs;

/// What a process is for, decided by its executable and not its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// `hrdd`, `hrdctl`, `hrd-netd`.
    Manager,
    /// `cordial-run`: the open layer and, inside it, the closed engine.
    /// These two cannot be told apart from outside the process.
    Engine,
    /// `cage`, the nested compositor.
    Compositor,
    /// Everything else in an instance: plugin runtime, web process, sandbox,
    /// and the keyring and session bus.
    Helper,
}

pub fn classify(exe_basename: &str) -> Class {
    match exe_basename {
        "cordial-run" => Class::Engine,
        "cage" => Class::Compositor,
        "hrdd" | "hrdctl" | "hrd-netd" | "hrd-enter" => Class::Manager,
        _ => Class::Helper,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcSample {
    pub pid: u32,
    pub class: Class,
    pub start_ticks: u64,
    pub threads: u32,
    pub cpu_ticks: u64,
    pub rss: Option<u64>,
    pub pss: Option<u64>,
    pub uss: Option<u64>,
    pub swap: Option<u64>,
}

/// Sample one process. `with_smaps` selects the expensive read. Returns `None`
/// if the process is gone, which happens between listing and reading and is
/// not an error.
pub fn sample(pid: u32, with_smaps: bool) -> Option<ProcSample> {
    let stat = procfs::read_stat(pid).ok()?;
    let status = procfs::read_status(pid).ok();
    let exe = procfs::exe_basename(pid).unwrap_or_else(|| stat.comm.clone());
    let (pss, uss, swap_smaps, rss_smaps) = if with_smaps {
        match procfs::read_smaps_rollup(pid) {
            Ok(s) => (s.pss, s.uss(), s.swap, s.rss),
            Err(_) => (None, None, None, None),
        }
    } else {
        (None, None, None, None)
    };
    Some(ProcSample {
        pid,
        class: classify(&exe),
        start_ticks: stat.start_ticks,
        threads: status
            .as_ref()
            .and_then(|s| s.threads)
            .unwrap_or(stat.num_threads),
        cpu_ticks: stat.cpu_ticks(),
        rss: status.as_ref().and_then(|s| s.vm_rss).or(rss_smaps),
        pss,
        uss,
        swap: swap_smaps.or_else(|| status.as_ref().and_then(|s| s.vm_swap)),
    })
}

/// Turns cumulative CPU ticks into a percentage of one core.
///
/// **How it is counted**, because the brief asks for it to be stated:
/// `percent = Δ(utime + stime) / CLK_TCK / Δwall × 100`, between two calls for
/// the same process, so 100 means one core fully busy and 400 four. A process
/// first seen on this call has no previous reading and reports `None`, not 0.
/// CPU spent by a process that exited between two samples is not counted in
/// that interval; per-instance CPU is therefore taken from the cgroup's
/// `usage_usec` where there is one, and from these sums only as a fallback.
#[derive(Debug, Default)]
pub struct CpuWindow {
    prev: HashMap<(u32, u64), (u64, u64)>,
    /// Used only to drop entries for processes that were not seen this round.
    round: u64,
    last_seen: HashMap<(u32, u64), u64>,
    tck: u64,
}

impl CpuWindow {
    pub fn new() -> Self {
        CpuWindow {
            tck: procfs::clock_ticks_per_second(),
            ..Default::default()
        }
    }

    pub fn begin_round(&mut self) {
        self.round += 1;
    }

    pub fn percent(
        &mut self,
        pid: u32,
        start_ticks: u64,
        cpu_ticks: u64,
        now_ms: u64,
    ) -> Option<f64> {
        let key = (pid, start_ticks);
        self.last_seen.insert(key, self.round);
        let out = match self.prev.get(&key) {
            Some(&(t0, ms0)) if now_ms > ms0 && cpu_ticks >= t0 => {
                let cpu_s = (cpu_ticks - t0) as f64 / self.tck.max(1) as f64;
                let wall_s = (now_ms - ms0) as f64 / 1000.0;
                Some(cpu_s / wall_s * 100.0)
            }
            _ => None,
        };
        self.prev.insert(key, (cpu_ticks, now_ms));
        out
    }

    /// Forget processes not seen since the previous round.
    pub fn end_round(&mut self) {
        let round = self.round;
        self.last_seen.retain(|_, r| *r == round);
        let keep = &self.last_seen;
        self.prev.retain(|k, _| keep.contains_key(k));
    }
}

/// Add a sample to a class total. A total field stays `None` until at least one
/// sample contributed it, so "nothing measured" never prints as 0.
pub fn add(total: &mut ClassStats, s: &ProcSample, cpu: Option<f64>) {
    total.processes += 1;
    total.threads += s.threads;
    fn acc(slot: &mut Option<u64>, v: Option<u64>) {
        if let Some(v) = v {
            *slot = Some(slot.unwrap_or(0) + v);
        }
    }
    acc(&mut total.rss_bytes, s.rss);
    acc(&mut total.pss_bytes, s.pss);
    acc(&mut total.uss_bytes, s.uss);
    acc(&mut total.swap_bytes, s.swap);
    if let Some(c) = cpu {
        total.cpu_percent = Some(total.cpu_percent.unwrap_or(0.0) + c);
    }
}

pub fn merge(into: &mut ClassStats, from: &ClassStats) {
    into.processes += from.processes;
    into.threads += from.threads;
    fn acc(slot: &mut Option<u64>, v: Option<u64>) {
        if let Some(v) = v {
            *slot = Some(slot.unwrap_or(0) + v);
        }
    }
    acc(&mut into.rss_bytes, from.rss_bytes);
    acc(&mut into.pss_bytes, from.pss_bytes);
    acc(&mut into.uss_bytes, from.uss_bytes);
    acc(&mut into.swap_bytes, from.swap_bytes);
    if let Some(c) = from.cpu_percent {
        into.cpu_percent = Some(into.cpu_percent.unwrap_or(0.0) + c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_follows_the_executable() {
        assert_eq!(classify("cordial-run"), Class::Engine);
        assert_eq!(classify("cage"), Class::Compositor);
        assert_eq!(classify("hrdd"), Class::Manager);
        assert_eq!(classify("deno"), Class::Helper);
        assert_eq!(classify("WebKitWebProcess"), Class::Helper);
        // `Main` is what the engine renames its main thread to; it must not
        // be mistaken for a program.
        assert_eq!(classify("Main"), Class::Helper);
    }

    #[test]
    fn cpu_percent_is_relative_to_one_core_and_needs_two_readings() {
        let mut w = CpuWindow::new();
        let tck = procfs::clock_ticks_per_second();
        w.begin_round();
        assert_eq!(w.percent(1, 10, 0, 1_000), None, "first sight has no rate");
        w.end_round();
        w.begin_round();
        // one full core for 2 s: tck * 2 ticks over 2000 ms
        let p = w.percent(1, 10, tck * 2, 3_000).unwrap();
        assert!((p - 100.0).abs() < 0.01, "{p}");
        w.end_round();
        w.begin_round();
        // half a core for 1 s
        let p = w.percent(1, 10, tck * 2 + tck / 2, 4_000).unwrap();
        assert!((p - 50.0).abs() < 0.01, "{p}");
    }

    #[test]
    fn a_reused_pid_is_a_different_process() {
        let mut w = CpuWindow::new();
        w.begin_round();
        w.percent(7, 100, 5000, 1000);
        w.end_round();
        w.begin_round();
        // same pid, different start time: no rate computed from the old one
        assert_eq!(w.percent(7, 200, 10, 2000), None);
    }

    #[test]
    fn departed_processes_are_forgotten() {
        let mut w = CpuWindow::new();
        w.begin_round();
        w.percent(1, 1, 1, 1);
        w.percent(2, 1, 1, 1);
        w.end_round();
        w.begin_round();
        w.percent(1, 1, 2, 2);
        w.end_round();
        assert_eq!(w.prev.len(), 1);
    }

    #[test]
    fn totals_stay_unmeasured_until_something_measures() {
        let mut t = ClassStats::default();
        let s = ProcSample {
            pid: 1,
            class: Class::Engine,
            start_ticks: 1,
            threads: 4,
            cpu_ticks: 0,
            rss: Some(100),
            pss: None,
            uss: None,
            swap: None,
        };
        add(&mut t, &s, None);
        assert_eq!(t.rss_bytes, Some(100));
        assert_eq!(t.pss_bytes, None, "no PSS sample must not print as zero");
        assert_eq!(t.cpu_percent, None);
        assert_eq!((t.processes, t.threads), (1, 4));
        let mut all = ClassStats::default();
        merge(&mut all, &t);
        assert_eq!(all.rss_bytes, Some(100));
        assert_eq!(all.pss_bytes, None);
    }

    #[test]
    fn sampling_this_process_classifies_it_as_not_the_engine() {
        let s = sample(std::process::id(), true).unwrap();
        assert_ne!(s.class, Class::Engine);
        assert!(s.rss.unwrap() > 0);
        assert!(s.threads >= 1);
        if let (Some(pss), Some(uss), Some(rss)) = (s.pss, s.uss, s.rss) {
            assert!(
                uss <= pss + 4096 && pss <= rss + 4096,
                "uss {uss} <= pss {pss} <= rss {rss}"
            );
        }
    }
}
