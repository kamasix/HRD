//! One run of one instance: starting its process set, watching it, ending it.
//!
//! Ownership of a set is the instance's cgroup when the daemon has a delegated
//! subtree (every process, however it forked, re-executed or was orphaned, is in
//! it, and `cgroup.kill` ends all of them at once). Without one the fallback is
//! the process group, which a program can leave, and `doctor` says so. A pid is
//! never trusted alone: the record holds the start time too, and a pid whose
//! start time differs is somebody else's process and is left alone.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use hrd_core::config::Config;
use hrd_core::ids::AccountName;
use hrd_core::model::{ExitRecord, ProcessIdent, ResourceMode, State};
use hrd_core::time::{monotonic_ms, now_unix};
use hrd_core::{fsutil, Error, Result};
use hrd_proc::{cgroup::Cgroup, procfs};
use rustix::process::{kill_process, Pid, Signal};

use crate::logtail::Tail;
use crate::machine::{self, Effect};
use crate::spawn::{self, Inputs, ProcSettings};
use crate::state::{Daemon, Inner, Live, StopProgress};

// ---------------------------------------------------------------------------
// The set
// ---------------------------------------------------------------------------

pub fn members(live: &Live) -> Vec<u32> {
    if let Some(cg) = &live.cg {
        return cg.pids().unwrap_or_default();
    }
    let Some(p) = &live.rec.process else {
        return Vec::new();
    };
    pgid_members(p)
}

/// Members of a set that has no cgroup: the leader if it is the same process,
/// and every live process in the recorded process group that started after the
/// leader (so a process group id reused later by something unrelated, which
/// started earlier, is not mistaken for ours).
pub fn pgid_members(p: &hrd_core::model::ProcessIdent) -> Vec<u32> {
    let Some(pgid) = p.pgid else {
        return if procfs::is_same_process(p.pid, p.start_ticks) {
            vec![p.pid]
        } else {
            Vec::new()
        };
    };
    procfs::list_pids()
        .into_iter()
        .filter(|pid| {
            procfs::read_stat(*pid)
                .map(|s| s.pgrp == pgid && s.state != 'Z' && s.start_ticks >= p.start_ticks)
                .unwrap_or(false)
        })
        .collect()
}

fn signal(pids: &[u32], sig: Signal) {
    for p in pids {
        if let Some(pid) = Pid::from_raw(*p as i32) {
            let _ = kill_process(pid, sig);
        }
    }
}

fn kill_set(live: &Live) {
    if let Some(cg) = &live.cg {
        let _ = cg.kill_all();
        return;
    }
    signal(&members(live), Signal::KILL);
}

/// `Some` once the first process of the set has ended.
pub fn main_exit(live: &mut Live) -> Option<ExitRecord> {
    if let Some(child) = live.child.as_mut() {
        return match child.try_wait() {
            Ok(None) => None,
            Ok(Some(st)) => {
                use std::os::unix::process::ExitStatusExt;
                Some(ExitRecord {
                    code: st.code(),
                    signal: st.signal(),
                    oom_killed: false,
                    unobserved: false,
                })
            }
            Err(_) => Some(ExitRecord {
                unobserved: true,
                ..Default::default()
            }),
        };
    }
    let p = live.rec.process.as_ref()?;
    let alive = procfs::read_stat(p.pid)
        .map(|s| s.start_ticks == p.start_ticks && s.state != 'Z')
        .unwrap_or(false);
    if alive {
        None
    } else {
        Some(ExitRecord {
            unobserved: true,
            ..Default::default()
        })
    }
}

pub fn begin_stop(live: &mut Live, force: bool, operator: bool) {
    if live.stop.is_none() {
        live.stop = Some(StopProgress {
            since_ms: monotonic_ms(),
            termed: false,
            killed: false,
            force,
        });
    } else if force {
        if let Some(s) = live.stop.as_mut() {
            s.force = true;
        }
    }
    if operator {
        live.tr.operator_stop = true;
    }
}

/// Advance a stop in progress. Returns true when the set is gone.
pub fn progress_stop(live: &mut Live, grace_s: u64) -> bool {
    let Some(mut st) = live.stop else {
        return false;
    };
    let now = monotonic_ms();
    let mem = members(live);
    let empty = match &live.cg {
        Some(cg) => matches!(cg.populated(), Ok(false)) || (mem.is_empty() && !cg.exists()),
        None => mem.is_empty(),
    };
    if empty {
        live.stop = Some(st);
        return true;
    }
    if st.force && !st.killed {
        kill_set(live);
        st.killed = true;
    } else if !st.termed && !st.force {
        signal(&mem, Signal::TERM);
        st.termed = true;
    } else if !st.killed && now.saturating_sub(st.since_ms) >= grace_s * 1000 {
        kill_set(live);
        st.killed = true;
    } else if st.killed {
        // Something survived a kill (an uninterruptible sleep); keep trying.
        kill_set(live);
    }
    live.stop = Some(st);
    false
}

/// The set is gone: release what the run held.
pub fn finalize(d: &Daemon, inner: &mut Inner, id: &AccountName) {
    let Some(live) = inner.live.get_mut(id) else {
        return;
    };
    let from = live.rec.state;
    if let Some(mut c) = live.child.take() {
        let _ = c.wait();
    }
    if let Some(cg) = live.cg.take() {
        if let (Some(base), Some(now)) = (live.oom_base, cg.memory().oom_kill) {
            if now > base {
                if let Some(e) = live.rec.exit.as_mut() {
                    e.oom_killed = true;
                }
            }
        }
        for _ in 0..20 {
            if cg.remove().is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    // A run that died while still starting (a locked profile, a missing file)
    // peaked at almost nothing; counting it would teach the scheduler that
    // starts are cheap. Only runs that got past Starting are recorded, in the
    // supervisor.
    live.start_recorded = true;
    let live = inner.live.get_mut(id).expect("still present");
    let _ = std::fs::remove_dir_all(d.layout.instance_run(id));
    live.proc_tail = None;
    live.engine_tail = None;
    live.stop = None;
    live.devctl = None;
    live.tr = Default::default();
    live.rec.process = None;
    // A run that was stopped while something still says it is live.
    if live.rec.state.expects_processes() {
        machine::set_state(
            &mut live.rec,
            State::Unknown,
            Some("the process set ended without a verdict".into()),
            now_unix(),
        );
    }
    live.rec.ended_at.get_or_insert(now_unix());
    d.changed(live, from);
}

// ---------------------------------------------------------------------------
// Starting
// ---------------------------------------------------------------------------

fn prepare_tree(d: &Daemon, id: &AccountName, build: &crate::runtime::Build) -> Result<()> {
    let l = &d.layout;
    for p in [
        l.state_dir.join("acct"),
        l.account_home(id),
        l.account_data(id),
        l.account_config(id),
        l.account_cache(id),
        l.account_cache(id).join("tmp"),
        l.account_cache(id).join("cordial"),
        l.account_state(id),
        l.run_dir.join("i"),
        l.instance_run(id),
    ] {
        fsutil::ensure_private_dir(&p, 0o700)?;
    }
    // One read-only tree of assets for every client; the client finds it at its
    // usual place and its stamp check passes without writing.
    let link = l.account_cache(id).join("cordial/assets");
    let want = build.dir.join("assets");
    match std::fs::read_link(&link) {
        Ok(t) if t == want => {}
        Ok(_) | Err(_) => {
            match std::fs::symlink_metadata(&link) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
                    std::fs::remove_dir_all(&link)
                        .map_err(|e| Error::io("replace a private asset copy", e))?
                }
                Ok(_) => std::fs::remove_file(&link)
                    .map_err(|e| Error::io("replace the asset link", e))?,
                Err(_) => {}
            }
            std::os::unix::fs::symlink(&want, &link)
                .map_err(|e| Error::io("link the shared assets", e))?;
        }
    }
    Ok(())
}

fn open_log(d: &Daemon, id: &AccountName, run: u64) -> Result<std::fs::File> {
    let path = d.layout.instance_log(id);
    let max = d.cfg().logs.max_bytes;
    if let Ok(md) = std::fs::metadata(&path) {
        if md.len() > max {
            let _ = std::fs::rename(&path, path.with_extension("log.1"));
        }
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::CLOEXEC.bits() as i32)
        .open(&path)
        .map_err(|e| Error::io(format!("open {}", path.display()), e))?;
    let _ = writeln!(
        f,
        "=== hrd run {run} start {} ===",
        hrd_core::time::rfc3339(now_unix())
    );
    Ok(f)
}

/// Keep a running client's log from growing without bound: past `logs.max_bytes`
/// it is copied to `.1` and truncated in place. The client writes with
/// `O_APPEND`, so it carries on at the new end; the supervisor's reader notices
/// the file got shorter and starts again. Called right after the log was read,
/// so what is lost is at most the few bytes written between that read and the
/// truncate. A line naming the run is written first so a restarted daemon can
/// still find where the run's lines begin.
pub fn rotate_running_log(d: &Daemon, id: &AccountName, run: u64, max: u64) {
    let path = d.layout.instance_log(id);
    let Ok(md) = std::fs::metadata(&path) else {
        return;
    };
    if max == 0 || md.len() <= max {
        return;
    }
    let old = path.with_extension("log.1");
    if std::fs::copy(&path, &old).is_err() {
        return;
    }
    let _ = std::fs::set_permissions(&old, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    let Ok(f) = OpenOptions::new().write(true).open(&path) else {
        return;
    };
    if f.set_len(0).is_err() {
        return;
    }
    if let Ok(mut a) = OpenOptions::new().append(true).open(&path) {
        let _ = writeln!(
            a,
            "=== hrd run {run} start (log rotated {}) ===",
            hrd_core::time::rfc3339(now_unix())
        );
    }
}

pub fn engine_log_dir(d: &Daemon, id: &AccountName) -> PathBuf {
    d.layout
        .account_profile(id, spawn::PROFILE)
        .join("data/files/appData/logs")
}

/// The engine's newest log file, if any.
pub fn newest_engine_log(dir: &std::path::Path) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max()
        .map(|(_, p)| p)
}

fn set_limits(d: &Daemon, cg: &Cgroup, cfg: &Config) {
    let r = &cfg.resources;
    let set = |file: &str, val: String| {
        if let Err(e) = cg.set(file, &val) {
            d.note(format!(
                "cannot set {file}={val} on instance cgroups: {e} (controller not delegated?)"
            ));
        }
    };
    if r.memory_high_mib > 0 {
        set("memory.high", (r.memory_high_mib * 1024 * 1024).to_string());
    }
    if r.memory_max_mib > 0 {
        set("memory.max", (r.memory_max_mib * 1024 * 1024).to_string());
    }
    if let Some(s) = r.swap_max_mib {
        set("memory.swap.max", (s * 1024 * 1024).to_string());
    }
    if r.cpu_weight != 100 {
        set("cpu.weight", r.cpu_weight.to_string());
    }
    set("pids.max", r.pids_max.to_string());
}

/// Create the process set for `id` and move it to `starting`. On failure the
/// record says why and nothing is left running.
pub fn spawn_run(d: &Daemon, inner: &mut Inner, id: &AccountName) -> Result<()> {
    let cfg = d.cfg();
    let build = crate::runtime::current(&d.layout)?;
    let (kind, place, mode, group, run, code) = {
        let l = inner
            .live
            .get(id)
            .ok_or_else(|| Error::not_found(format!("no instance {id}")))?;
        (
            l.rec.kind,
            l.rec.place_id,
            l.rec.mode,
            l.rec.group.clone(),
            l.rec.run,
            l.tr_code(),
        )
    };
    if let Some(g) = &group {
        // Fail closed before anything is created: the namespace must exist.
        if !crate::netops::namespace_present(&d.layout, g) {
            return Err(Error::unavailable(format!(
                "group {g} has no network namespace: run `hrdctl network apply` (the client would otherwise use the host's network, so it was not started)"
            )));
        }
    } else if !cfg.network.allow_unrouted {
        return Err(Error::unavailable(
            "the account has no group and network.allow_unrouted is off",
        ));
    }
    let render = spawn::find_render_node();
    let graphics = spawn::choose_graphics(&cfg, render.as_deref())?;
    let icd = if graphics.software {
        spawn::find_lavapipe_icd(&cfg)
    } else {
        None
    };
    if graphics.software && icd.is_none() {
        d.note("software rendering is selected but no lavapipe ICD (lvp_icd*.json) was found: install mesa-vulkan-drivers, or the engine's Vulkan path may fail");
    }
    prepare_tree(d, id, &build)?;

    // Engine logs from an earlier run would be mistaken for this one's.
    let elog = engine_log_dir(d, id);
    if let Ok(rd) = std::fs::read_dir(&elog) {
        for e in rd.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }

    // The process set's cgroup.
    let cg = match &d.deleg {
        Some(dl) => {
            let cg = dl
                .instances
                .create(id.as_str())
                .map_err(|e| Error::io("create the instance cgroup", e))?;
            if matches!(cg.populated(), Ok(true)) {
                return Err(Error::conflict(format!(
                    "a previous process set of {id} still exists; stop it first"
                )));
            }
            set_limits(d, &cg, &cfg);
            Some(cg)
        }
        None => None,
    };
    let oom_base = cg.as_ref().and_then(|c| c.memory().oom_kill);

    let plan = spawn::build(&Inputs {
        cfg: &cfg,
        layout: &d.layout,
        account: id,
        kind,
        place,
        private_server_code: code.as_deref(),
        mode,
        group: group.as_ref(),
        build_dir: &build.dir,
        graphics: &graphics,
        lavapipe_icd: icd.as_deref(),
        dbus_address: Some(d.secrets.bus_address().ok_or_else(|| {
            Error::unavailable("the secret store went away between the request and the start; unlock it again (`hrdctl secrets unlock`)")
        })?),
        secret_store_keyring: true,
    })?;
    let log = open_log(d, id, run)?;
    let log_path = plan.log_path.clone();
    let settings = ProcSettings {
        cgroup_procs: cg
            .as_ref()
            .and_then(|c| spawn::path_cstring(&c.path().join("cgroup.procs"))),
        oom_score_adj: cfg.resources.oom_score_adj,
        cpus: spawn::cpu_set(inner.spawn_seq, cfg.engine.cpus_per_instance, d.online_cpus),
        ksm: cfg.resources.ksm,
    };
    inner.spawn_seq += 1;
    let child = spawn::launch(&plan, log, &settings)
        .map_err(|e| Error::io(format!("start {}", plan.program.display()), e))?;
    let pid = child.id();
    let start_ticks = procfs::start_ticks(pid).unwrap_or(0);

    let now = now_unix();
    let live = inner.live.get_mut(id).expect("checked above");
    let from = live.rec.state;
    live.rec.runtime = Some(build.version.clone());
    live.rec.started_at = Some(now);
    live.rec.ended_at = None;
    live.rec.exit = None;
    live.rec.signals = Default::default();
    live.rec.start_peak_bytes = None;
    live.rec.process = Some(ProcessIdent {
        pid,
        start_ticks,
        cgroup: cg
            .as_ref()
            .map(|c| c.path().display().to_string())
            .unwrap_or_default(),
        pgid: Some(pid),
    });
    live.child = Some(child);
    live.cg = cg;
    live.oom_base = oom_base;
    live.started_ms = monotonic_ms();
    live.stop = None;
    live.tr = Default::default();
    live.start_recorded = false;
    live.proc_tail = Some(Tail::from_end(&log_path));
    live.engine_tail = Some(Tail::new(elog.join("none")));
    live.devctl = plan.devctl_socket.clone();
    let why = format!(
        "process started ({}; graphics: {})",
        build.version, graphics.why
    );
    machine::set_state(&mut live.rec, State::Starting, Some(why), now);
    d.changed(live, from);
    Ok(())
}

impl Live {
    /// The private-server code is held only in memory, from the request to the
    /// spawn; it is never written to the record.
    pub fn tr_code(&self) -> Option<String> {
        self.secret_code.clone()
    }
}

pub fn apply_effects(d: &Daemon, inner: &mut Inner, id: &AccountName, fx: Vec<Effect>) {
    for e in fx {
        match e {
            Effect::StopSet => {
                if let Some(l) = inner.live.get_mut(id) {
                    begin_stop(l, false, false);
                }
            }
            Effect::Auth(status, detail) => {
                crate::ops_registry::note_auth(d, inner, id, status, detail)
            }
        }
    }
}

pub fn default_mode(
    cfg: &Config,
    account_mode: Option<ResourceMode>,
    asked: Option<ResourceMode>,
) -> ResourceMode {
    asked.or(account_mode).unwrap_or(cfg.resources.default_mode)
}
