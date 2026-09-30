//! Measuring the fleet from `/proc` and cgroup files.
//!
//! What is measured and how (docs/stats.md repeats this for the operator):
//!
//! * **RSS** and **threads** come from `/proc/<pid>/status`, cheap, every round.
//! * **PSS, USS and swap** come from `/proc/<pid>/smaps_rollup`, which walks the
//!   process's memory map. It is read for at most a handful of instances per
//!   round and each instance at most every `stats.pss_interval_s`; between
//!   reads the last figures are shown with their age. 0 turns it off.
//! * **memory.current** is the cgroup's charge, which includes page cache and
//!   kernel memory. It is not RSS and not PSS and is shown separately.
//! * **CPU** is a percentage of one core: the cgroup's `usage_usec` delta over
//!   wall time when the instance has a cgroup, otherwise the delta of summed
//!   `utime+stime` of the processes seen in both rounds. 100 is one core busy.
//! * Anything that cannot be read is `None` and is displayed as "not measured";
//!   it is never counted as zero.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use hrd_core::ids::AccountName;
use hrd_core::proto::{ClassStats, KsmView, MemberView, MemoryView, NetTraffic, StatsView};
use hrd_core::time::{monotonic_ms, now_unix};
use hrd_proc::stats::{self, Class, CpuWindow};
use hrd_proc::{cgroup::Cgroup, disk, procfs};

use crate::state::Daemon;

#[derive(Debug, Clone, Default)]
pub struct InstSample {
    pub mem: MemoryView,
    pub cpu_percent: Option<f64>,
    pub processes: u32,
    pub threads: u32,
    pub members: Vec<MemberView>,
}

#[derive(Default)]
pub struct Samples {
    pub per: BTreeMap<AccountName, InstSample>,
    pub stats: StatsView,
    smaps: HashMap<AccountName, SmapsAgg>,
    cpu: Option<CpuWindow>,
    cg_prev: HashMap<AccountName, (u64, u64)>,
    disk: Option<(u64, u64)>,
    last_ms: u64,
}

#[derive(Clone, Copy, Default)]
struct SmapsAgg {
    at: u64,
    pss: Option<u64>,
    uss: Option<u64>,
    swap: Option<u64>,
}

struct Target {
    id: AccountName,
    cg: Option<Cgroup>,
    members: Vec<u32>,
}

const SMAPS_PER_ROUND: usize = 20;

fn class_name(c: Class) -> &'static str {
    match c {
        Class::Manager => "manager",
        Class::Engine => "engine",
        Class::Compositor => "compositor",
        Class::Helper => "helper",
    }
}

pub fn run_once(d: &Daemon) {
    let cfg = d.cfg();
    let now_ms = monotonic_ms();
    let now = now_unix();
    let targets: Vec<Target> = {
        let inner = d.lock();
        inner
            .live
            .values()
            .filter(|l| l.has_process())
            .map(|l| Target {
                id: l.rec.id.clone(),
                cg: l.cg.clone(),
                members: crate::runs::members(l),
            })
            .collect()
    };
    let (mem_avail, psi_mem, psi_cpu) = (
        procfs::read_meminfo().ok().and_then(|m| m.available),
        procfs::read_memory_psi().map(|p| p.some_avg10),
        read_cpu_psi(),
    );

    let mut guard = d.samples.lock().unwrap_or_else(|e| e.into_inner());
    let s = &mut *guard;
    let cpu = s.cpu.get_or_insert_with(CpuWindow::new);
    cpu.begin_round();
    let window_s = (s.last_ms != 0).then(|| now_ms.saturating_sub(s.last_ms) as f64 / 1000.0);

    // Who gets a memory-map read this round: the stalest, a few at a time.
    let mut due: Vec<(u64, &AccountName)> = Vec::new();
    if cfg.stats.pss_interval_s > 0 {
        for t in &targets {
            let age = s
                .smaps
                .get(&t.id)
                .map(|a| now.saturating_sub(a.at))
                .unwrap_or(u64::MAX);
            if age >= cfg.stats.pss_interval_s {
                due.push((age, &t.id));
            }
        }
        due.sort_by(|a, b| b.0.cmp(&a.0));
        due.truncate(SMAPS_PER_ROUND);
    }
    let due: Vec<AccountName> = due.into_iter().map(|(_, i)| i.clone()).collect();

    let mut per = BTreeMap::new();
    let mut tot = [
        ClassStats::default(),
        ClassStats::default(),
        ClassStats::default(),
        ClassStats::default(),
    ];
    let mut cg_total: Option<u64> = None;
    for t in &targets {
        let with_smaps = due.contains(&t.id);
        let mut is = InstSample::default();
        let mut agg = SmapsAgg {
            at: now,
            ..Default::default()
        };
        let mut sum_cpu: Option<f64> = None;
        let mut rss_sum: Option<u64> = None;
        for pid in &t.members {
            let Some(ps) = stats::sample(*pid, with_smaps) else {
                continue;
            };
            let pct = cpu.percent(ps.pid, ps.start_ticks, ps.cpu_ticks, now_ms);
            if let Some(p) = pct {
                sum_cpu = Some(sum_cpu.unwrap_or(0.0) + p);
            }
            let idx = match ps.class {
                Class::Manager => 0,
                Class::Engine => 1,
                Class::Compositor => 2,
                Class::Helper => 3,
            };
            stats::add(&mut tot[idx], &ps, pct);
            is.processes += 1;
            is.threads += ps.threads;
            if let Some(r) = ps.rss {
                rss_sum = Some(rss_sum.unwrap_or(0) + r);
            }
            for (slot, v) in [
                (&mut agg.pss, ps.pss),
                (&mut agg.uss, ps.uss),
                (&mut agg.swap, ps.swap),
            ] {
                if let Some(v) = v {
                    *slot = Some(slot.unwrap_or(0) + v);
                }
            }
            is.members.push(MemberView {
                pid: ps.pid,
                name: procfs::exe_basename(ps.pid).unwrap_or_default(),
                class: class_name(ps.class).into(),
                rss_bytes: ps.rss,
                threads: Some(ps.threads),
            });
        }
        if with_smaps {
            s.smaps.insert(t.id.clone(), agg);
        }
        let last = s.smaps.get(&t.id).copied().unwrap_or_default();
        let (cur, peak, swap_cg) = match &t.cg {
            Some(cg) => {
                let m = cg.memory();
                (m.current, m.peak, m.swap_current)
            }
            None => (None, None, None),
        };
        if let Some(c) = cur {
            cg_total = Some(cg_total.unwrap_or(0) + c);
        }
        is.mem = MemoryView {
            rss_bytes: rss_sum,
            pss_bytes: last.pss,
            uss_bytes: last.uss,
            swap_bytes: last.swap.or(swap_cg),
            cgroup_current_bytes: cur,
            cgroup_peak_bytes: peak,
            pss_sampled_at: (last.at != 0 && last.pss.is_some()).then_some(last.at),
        };
        // CPU from the cgroup where possible: it includes processes that have
        // come and gone between two rounds.
        is.cpu_percent = match t.cg.as_ref().and_then(|c| c.cpu_usage_usec()) {
            Some(us) => {
                let r = s.cg_prev.get(&t.id).and_then(|(u0, m0)| {
                    (now_ms > *m0 && us >= *u0)
                        .then(|| (us - u0) as f64 / 1000.0 / (now_ms - m0) as f64 * 100.0)
                });
                s.cg_prev.insert(t.id.clone(), (us, now_ms));
                r.or(sum_cpu)
            }
            None => sum_cpu,
        };
        per.insert(t.id.clone(), is);
    }
    cpu.end_round();
    s.cg_prev.retain(|k, _| per.contains_key(k));
    s.smaps.retain(|k, _| per.contains_key(k));

    // The manager: this process, sampled on the same terms.
    let me = std::process::id();
    if let Some(ps) = stats::sample(me, cfg.stats.pss_interval_s > 0) {
        let pct = cpu_self(s, &ps, now_ms);
        stats::add(&mut tot[0], &ps, pct);
    }
    let mut total = ClassStats::default();
    for c in &tot {
        stats::merge(&mut total, c);
    }

    let mut notes = Vec::new();
    if d.deleg.is_none() {
        notes.push(
            "no delegated cgroup: per-instance memory.current and cgroup CPU are not measured"
                .to_string(),
        );
    }
    if cfg.stats.pss_interval_s == 0 {
        notes.push("PSS/USS sampling is off (stats.pss_interval_s = 0)".to_string());
    }
    let cache = match s.disk {
        Some((at, b)) if now.saturating_sub(at) < 120 => Some(b),
        _ => {
            let acct = disk::usage(&d.layout.state_dir.join("acct"), 500_000);
            let rt = disk::usage(&d.layout.runtime_store(), 500_000);
            let b = acct.allocated + rt.allocated;
            s.disk = Some((now, b));
            if acct.truncated || rt.truncated {
                notes
                    .push("disk usage walk stopped early: the figure is a lower bound".to_string());
            }
            Some(b)
        }
    };
    let network: BTreeMap<String, NetTraffic> = d
        .lock()
        .net_status
        .iter()
        .map(|(g, (_, st))| {
            (
                g.to_string(),
                NetTraffic {
                    rx_bytes: st.rx_bytes,
                    tx_bytes: st.tx_bytes,
                },
            )
        })
        .collect();
    s.stats = StatsView {
        cpu_window_s: window_s,
        manager: tot[0].clone(),
        engines: tot[1].clone(),
        compositors: tot[2].clone(),
        helpers: tot[3].clone(),
        total,
        instances: per.len() as u32,
        sampled_at: Some(now),
        cgroup_current_bytes: cg_total,
        mem_available_bytes: mem_avail,
        memory_pressure_some_avg10: psi_mem,
        cache_disk_bytes: cache,
        network,
        ksm: read_ksm(),
        notes,
    };
    s.per = per;
    s.last_ms = now_ms;
    let _ = psi_cpu; // kept for the scheduler, which reads its own copy
}

fn cpu_self(s: &mut Samples, ps: &stats::ProcSample, now_ms: u64) -> Option<f64> {
    s.cpu
        .as_mut()?
        .percent(ps.pid, ps.start_ticks, ps.cpu_ticks, now_ms)
}

/// `some avg10` of `/proc/pressure/cpu`.
pub fn read_cpu_psi() -> Option<f64> {
    let t = std::fs::read_to_string("/proc/pressure/cpu").ok()?;
    procfs::parse_psi(&t).map(|p| p.some_avg10)
}

fn read_ksm() -> Option<KsmView> {
    let rd = |f: &str| {
        std::fs::read_to_string(format!("/sys/kernel/mm/ksm/{f}"))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    };
    let run = rd("run")?;
    (run != 0).then(|| KsmView {
        pages_shared: rd("pages_shared").unwrap_or(0),
        pages_sharing: rd("pages_sharing").unwrap_or(0),
        run,
    })
}

pub fn spawn_thread(d: Arc<Daemon>) {
    std::thread::Builder::new()
        .name("sampler".into())
        .spawn(move || {
            while !d.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                run_once(&d);
                let secs = d.cfg().stats.interval_s.max(1);
                for _ in 0..secs * 4 {
                    if d.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        })
        .ok();
}
