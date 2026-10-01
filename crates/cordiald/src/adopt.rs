//! After a restart: find out what the previous daemon left behind.
//!
//! The registry and one record per account survive on disk. For each account:
//!
//! * `queued` is **not** restored. The queue was an instruction to a daemon that
//!   no longer exists, and this daemon starts clients only in response to
//!   commands it receives (the entry becomes `stopped` and says why).
//! * A run whose processes are still alive is adopted: the process set is found
//!   again by cgroup (or by pid *and* start time), the log is replayed from the
//!   run's banner so the state is derived from what the client said and not from
//!   what was last written, and supervision resumes. A pid whose start time
//!   differs is somebody else's and is never touched.
//! * A run whose processes are gone is closed with an exit status marked
//!   unobserved, and classified by what it had reported.

use hrd_core::ids::AccountName;
use hrd_core::model::{ExitRecord, InstanceRecord, State};
use hrd_core::time::now_unix;
use hrd_proc::{cgroup::Cgroup, procfs};

use crate::logtail::{self, Tail};
use crate::machine::{self, Transient};
use crate::state::{load_record, Daemon, Inner, Live};
use crate::{runs, signals};

fn alive(rec: &InstanceRecord) -> (bool, Option<Cgroup>) {
    let Some(p) = &rec.process else {
        return (false, None);
    };
    let cg = (!p.cgroup.is_empty())
        .then(|| Cgroup::at(p.cgroup.clone().into()))
        .filter(|c| c.exists());
    let main = procfs::read_stat(p.pid)
        .map(|s| s.start_ticks == p.start_ticks && s.state != 'Z')
        .unwrap_or(false);
    let populated = cg
        .as_ref()
        .is_some_and(|c| matches!(c.populated(), Ok(true)));
    // Without a cgroup, orphans of a dead leader are still in its process group.
    let orphans = cg.is_none() && p.pgid.is_some() && !runs::pgid_members(p).is_empty();
    (main || populated || orphans, cg)
}

pub fn adopt_all(d: &Daemon, inner: &mut Inner) {
    let ids: Vec<AccountName> = inner.reg.accounts.keys().cloned().collect();
    let now = now_unix();
    for id in ids {
        let rec =
            load_record(&d.layout, &id).unwrap_or_else(|| InstanceRecord::new(id.clone(), now));
        let mut live = Live::new(rec);
        let from = live.rec.state;
        match live.rec.state {
            State::Queued => {
                machine::set_state(&mut live.rec, State::Stopped, Some("the manager restarted while this was queued; queued starts are not restored".into()), now);
                d.changed(&mut live, from);
            }
            s if s.expects_processes() => {
                let (is_alive, cg) = alive(&live.rec);
                if is_alive {
                    adopt_running(d, &mut live, cg, now);
                    d.changed(&mut live, from);
                } else {
                    let exit = ExitRecord {
                        unobserved: true,
                        ..Default::default()
                    };
                    if let Some(cg) = cg {
                        let _ = cg.remove();
                    }
                    machine::on_exit(&mut live.rec, &Transient::default(), exit, now);
                    live.rec.process = None;
                    let _ = std::fs::remove_dir_all(d.layout.instance_run(&id));
                    d.changed(&mut live, from);
                }
            }
            _ => {
                // The earlier daemon had already decided this run was over
                // (failed, disconnected, stopped...) and was taking its process
                // set down when it went away. If the set is still there, finish
                // the job instead of reporting an ended run that is still running.
                if live.rec.process.is_some() {
                    let (is_alive, cg) = alive(&live.rec);
                    if is_alive {
                        live.cg = cg;
                        live.start_recorded = true;
                        live.proc_tail = None;
                        live.engine_tail = None;
                        runs::begin_stop(&mut live, false, false);
                    } else {
                        if let Some(cg) = cg {
                            let _ = cg.remove();
                        }
                        live.rec.process = None;
                        let _ = std::fs::remove_dir_all(d.layout.instance_run(&id));
                        d.changed(&mut live, from);
                    }
                }
            }
        }
        inner.live.insert(id, live);
    }
}

fn adopt_running(d: &Daemon, live: &mut Live, cg: Option<Cgroup>, now: u64) {
    let id = live.rec.id.clone();
    live.cg = cg;
    live.oom_base = live.cg.as_ref().and_then(|c| c.memory().oom_kill);
    live.started_ms = hrd_core::time::monotonic_ms();
    live.start_recorded = true;
    let log = d.layout.instance_log(&id);
    let banner = format!("=== hrd run {} start", live.rec.run);
    // Re-derive the state from the log, starting from a blank run.
    let saved = live.rec.clone();
    live.rec.signals = Default::default();
    live.rec.exit = None;
    machine::set_state(
        &mut live.rec,
        State::Starting,
        Some("adopted after a manager restart".into()),
        now,
    );
    let mut tr = Transient::default();
    match logtail::offset_of_last_line(&log, &banner, 8 << 20) {
        Some(off) => {
            let mut tail = Tail::from_offset(&log, off);
            for line in tail.poll(8 << 20) {
                if let Some(sig) = signals::parse_line(&line) {
                    // Effects are ignored during replay: a verdict reached here
                    // is recorded by the state itself, and the stop it implies
                    // is requested below.
                    let _ = machine::on_signal(&mut live.rec, &mut tr, sig, now);
                }
            }
            live.proc_tail = Some(tail);
            let elog = runs::engine_log_dir(d, &id);
            if let Some(p) = runs::newest_engine_log(&elog) {
                let mut et = Tail::new(p);
                for line in et.poll(8 << 20) {
                    if let Some(sig) = signals::parse_line(&line) {
                        let _ = machine::on_signal(&mut live.rec, &mut tr, sig, now);
                    }
                }
                live.engine_tail = Some(et);
            } else {
                live.engine_tail = Some(Tail::new(elog.join("none")));
            }
            if live.rec.state == State::Starting && saved.state != State::Starting {
                // Nothing in the log says more than "started": keep what the
                // earlier daemon had established rather than claim less, but
                // say where it came from.
                live.rec.state = saved.state;
                live.rec.reason = Some(format!(
                    "{} (state carried over from before the manager restarted)",
                    saved.reason.unwrap_or_default()
                ));
            }
        }
        None => {
            live.proc_tail = Some(Tail::from_end(&log));
            live.engine_tail = Some(Tail::new(runs::engine_log_dir(d, &id).join("none")));
            machine::set_state(&mut live.rec, State::Unknown, Some("adopted after a manager restart; the log does not show this run, so its state is not known".into()), now);
        }
    }
    // The two logs are replayed one after the other, so a notice in the engine
    // log can be applied after a join in the process log that came later in
    // real time. A pending disconnect is therefore not carried across a restart:
    // if the client really left, the process exit or "left" line says so.
    tr.pending_disconnect_at = None;
    live.tr = tr;
    live.rec.started_at = saved.started_at;
    live.rec.process = saved.process;
    live.rec.runtime = saved.runtime;
    live.rec.kind = saved.kind;
    live.rec.place_id = saved.place_id;
    live.rec.group = saved.group;
    live.rec.mode = saved.mode;
    live.rec.run = saved.run;
    live.rec.queued_at = saved.queued_at;
    if live.rec.kind == hrd_core::model::RunKind::Login {
        live.devctl = Some(d.layout.instance_run(&id).join("devctl.sock"));
    }
    if !live.rec.state.expects_processes() {
        // The replay reached a verdict (for example the client left); release the set.
        runs::begin_stop(live, false, false);
    }
}
