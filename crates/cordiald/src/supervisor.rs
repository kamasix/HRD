//! The loop that keeps the fleet honest: read what the clients say, notice when
//! they end, carry out stops, and admit queued starts.
//!
//! It runs twice a second. Nothing here starts a client on its own initiative:
//! only entries the operator queued are admitted, and a run that ended stays
//! ended.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use hrd_core::config::{auto_concurrent_starts, Config, Graphics};
use hrd_core::ids::AccountName;
use hrd_core::model::{RunKind, State};
use hrd_core::time::{monotonic_ms, now_unix};
use hrd_proc::procfs;

use crate::machine::{self, Effect, Timing};
use crate::sched::{self, Facts, Verdict};
use crate::state::{Daemon, Inner};
use crate::{netops, runs, sampler, signals};

const LOG_BYTES_PER_TICK: u64 = 256 * 1024;

fn timing(cfg: &Config) -> Timing {
    Timing {
        start_timeout_s: cfg.scheduler.start_timeout_s,
        join_timeout_s: cfg.scheduler.join_timeout_s,
        disconnect_grace_s: cfg.scheduler.disconnect_grace_s,
        login_timeout_s: cfg.login.timeout_s,
    }
}

/// Whether a render node can be opened, remembered for half a minute: asking
/// opens the device, and admission asks twice a second.
fn has_render_node() -> bool {
    static CACHE: std::sync::Mutex<Option<(std::time::Instant, bool)>> =
        std::sync::Mutex::new(None);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match *c {
        Some((at, v)) if at.elapsed() < Duration::from_secs(30) => v,
        _ => {
            let v = crate::spawn::find_render_node().is_some();
            *c = Some((std::time::Instant::now(), v));
            v
        }
    }
}

pub fn concurrency(d: &Daemon, cfg: &Config) -> u32 {
    if cfg.scheduler.max_concurrent_starts > 0 {
        return cfg.scheduler.max_concurrent_starts;
    }
    let software = match cfg.engine.graphics {
        Graphics::Software => true,
        Graphics::Gpu => false,
        Graphics::Auto => !has_render_node(),
    };
    auto_concurrent_starts(d.online_cpus, software)
}

fn service(d: &Daemon, inner: &mut Inner, cfg: &Config, id: &AccountName, now: u64) {
    let t = timing(cfg);
    let mut fx: Vec<Effect> = Vec::new();
    {
        let Some(live) = inner.live.get_mut(id) else {
            return;
        };
        let deciding = live.rec.state.expects_processes() && live.stop.is_none();

        // What the client says.
        if deciding {
            let mut lines = Vec::new();
            let dir = runs::engine_log_dir(d, id);
            if let Some(tail) = live.engine_tail.as_mut() {
                if !tail.path().is_file() {
                    if let Some(p) = runs::newest_engine_log(&dir) {
                        tail.set_path(p);
                    }
                }
                lines.extend(tail.poll(LOG_BYTES_PER_TICK));
            }
            // Engine lines first: a disconnect notice in the engine log normally
            // comes before the rejoin the process log reports, and applying them
            // in that order lets the rejoin cancel the notice.
            if let Some(tail) = live.proc_tail.as_mut() {
                lines.extend(tail.poll(LOG_BYTES_PER_TICK));
            }
            for line in lines {
                if let Some(sig) = signals::parse_line(&line) {
                    fx.extend(machine::on_signal(&mut live.rec, &mut live.tr, sig, now));
                }
            }
            fx.extend(machine::on_tick(&mut live.rec, &mut live.tr, &t, now));
        }

        // What starting costs, for the next admission decision.
        if live.rec.state == State::Starting
            || (live.rec.kind == RunKind::Login && live.rec.signals.screen.is_none())
        {
            let cur = match &live.cg {
                Some(cg) => {
                    let m = cg.memory();
                    m.peak.or(m.current)
                }
                None => {
                    let rss: u64 = runs::members(live)
                        .iter()
                        .filter_map(|p| procfs::read_status(*p).ok().and_then(|s| s.vm_rss))
                        .sum();
                    (rss > 0).then_some(rss)
                }
            };
            if let Some(c) = cur {
                live.rec.start_peak_bytes = Some(live.rec.start_peak_bytes.unwrap_or(0).max(c));
            }
        } else if !live.start_recorded && live.has_process() {
            if let Some(p) = live.rec.start_peak_bytes {
                inner.est.record(p);
            }
            if let Some(l) = inner.live.get_mut(id) {
                l.start_recorded = true;
            }
        }
    }
    {
        let Some(live) = inner.live.get_mut(id) else {
            return;
        };
        // The first process has ended.
        if live.has_process() && live.rec.exit.is_none() {
            if let Some(mut exit) = runs::main_exit(live) {
                if let (Some(cg), Some(base)) = (&live.cg, live.oom_base) {
                    exit.oom_killed = cg.memory().oom_kill.is_some_and(|n| n > base);
                }
                let from = live.rec.state;
                machine::on_exit(&mut live.rec, &live.tr, exit, now);
                runs::begin_stop(live, false, false);
                // The leader is gone: whatever else is left gets a few seconds.
                if let Some(s) = live.stop.as_mut() {
                    let grace = cfg.scheduler.stop_grace_s.saturating_sub(3) * 1000;
                    s.since_ms = s.since_ms.saturating_sub(grace);
                }
                d.changed(live, from);
            }
        }
    }
    let finished = {
        let Some(live) = inner.live.get_mut(id) else {
            return;
        };
        live.stop.is_some() && runs::progress_stop(live, cfg.scheduler.stop_grace_s)
    };
    if !fx.is_empty() {
        runs::apply_effects(d, inner, id, fx);
    }
    if let Some(live) = inner.live.get_mut(id) {
        if live.rec.state != live.last_saved || live.dirty {
            let from = live.last_saved;
            d.changed(live, from);
        }
    }
    if finished {
        runs::finalize(d, inner, id);
    }
}

/// Admit at most one queued start, if the facts allow.
fn admit(d: &Daemon, inner: &mut Inner, cfg: &Config) {
    let Some(head) = inner.queue.front().cloned() else {
        return;
    };
    // A head that is no longer Queued was stopped or cancelled while waiting.
    if inner
        .live
        .get(&head)
        .is_none_or(|l| l.rec.state != State::Queued)
    {
        inner.queue.pop_front();
        return;
    }
    let now_ms = monotonic_ms();
    let conc = concurrency(d, cfg);
    let in_flight = inner
        .live
        .values()
        .filter(|l| {
            l.rec.state == State::Starting
                || (l.rec.kind == RunKind::Login
                    && l.rec.state.expects_processes()
                    && l.rec.signals.screen.is_none()
                    // A sign-in that never shows a screen counts as starting for
                    // two minutes, not for its whole timeout.
                    && now_ms.saturating_sub(l.started_ms) < 120_000)
        })
        .count() as u32;
    let est = inner.est.estimate(cfg.scheduler.assumed_start_peak_mib);
    let reserved: u64 = inner
        .live
        .values()
        .filter(|l| l.rec.state == State::Starting)
        .map(|l| est.saturating_sub(l.rec.start_peak_bytes.unwrap_or(0)))
        .sum();
    let facts = Facts {
        mem_available: procfs::read_meminfo().ok().and_then(|m| m.available),
        mem_pressure_avg10: procfs::read_memory_psi().map(|p| p.some_avg10),
        cpu_pressure_avg10: sampler::read_cpu_psi(),
        in_flight,
        reserved,
        live_total: inner
            .live
            .values()
            .filter(|l| l.rec.state.expects_processes())
            .count() as u32,
        since_last_start_ms: now_ms.saturating_sub(inner.last_start_ms),
    };
    match sched::decide(&cfg.scheduler, conc, est, &facts) {
        Verdict::Wait(why) => {
            if let Some(l) = inner.live.get_mut(&head) {
                let r = Some(format!("queued: {why}"));
                if l.rec.reason != r {
                    l.rec.reason = r;
                }
            }
        }
        Verdict::Start => {
            inner.queue.pop_front();
            inner.last_start_ms = now_ms;
            let res = runs::spawn_run(d, inner, &head);
            if let Some(l) = inner.live.get_mut(&head) {
                l.secret_code = None;
                if let Err(e) = res {
                    let from = l.rec.state;
                    machine::set_state(
                        &mut l.rec,
                        State::Failed,
                        Some(format!("could not start: {e}")),
                        now_unix(),
                    );
                    l.rec.process = None;
                    d.changed(l, from);
                }
            }
        }
    }
}

pub fn tick(d: &Daemon) {
    let cfg = d.cfg();
    let now = now_unix();
    let mut guard = d.lock();
    let inner: &mut Inner = &mut guard;
    let ids: Vec<AccountName> = inner
        .live
        .values()
        .filter(|l| l.has_process() || l.stop.is_some())
        .map(|l| l.rec.id.clone())
        .collect();
    for id in ids {
        service(d, inner, &cfg, &id, now);
    }
    admit(d, inner, &cfg);
}

pub fn run(d: Arc<Daemon>) {
    while !d.shutdown.load(Ordering::Relaxed) {
        tick(&d);
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Keep the cached view of each group's network fresh, off the supervisor's
/// thread: a helper that hangs must never delay reading a client's log.
pub fn spawn_net_refresh(d: Arc<Daemon>) {
    std::thread::Builder::new()
        .name("net-refresh".into())
        .spawn(move || {
            while !d.shutdown.load(Ordering::Relaxed) {
                netops::refresh(&d);
                for _ in 0..40 {
                    if d.shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        })
        .ok();
}
