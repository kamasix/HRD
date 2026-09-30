//! The daemon's shared state and what is written to disk.
//!
//! One mutex guards the registry, the per-instance runtime objects and the
//! start queue. Everything done while holding it is cheap (map updates, a few
//! small file operations); anything slow (a helper round trip, a PSS sample, an
//! import) is done with it released.

use std::collections::{BTreeMap, VecDeque};
use std::process::Child;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, RwLock};

use hrd_core::config::Config;
use hrd_core::ids::{AccountName, GroupName};
use hrd_core::layout::Layout;
use hrd_core::model::{InstanceRecord, Registry, State};
use hrd_core::proto::Event;
use hrd_core::time::now_unix;
use hrd_core::{fsutil, Error, Result};
use hrd_net::client::NetdClient;
use hrd_net::proto::GroupStatus;
use hrd_proc::cgroup::{Cgroup, Delegated};

use crate::logtail::Tail;
use crate::machine::Transient;
use crate::sched::Estimator;

#[derive(Debug, Clone, Copy)]
pub struct StopProgress {
    pub since_ms: u64,
    pub termed: bool,
    pub killed: bool,
    /// Kill without the polite phase.
    pub force: bool,
}

/// An instance's runtime side: everything that is not persisted.
pub struct Live {
    pub rec: InstanceRecord,
    pub tr: Transient,
    /// Our direct child, if this daemon started the run; `None` for a run
    /// adopted after a restart.
    pub child: Option<Child>,
    pub cg: Option<Cgroup>,
    pub oom_base: Option<u64>,
    pub proc_tail: Option<Tail>,
    pub engine_tail: Option<Tail>,
    pub stop: Option<StopProgress>,
    pub started_ms: u64,
    pub devctl: Option<std::path::PathBuf>,
    pub last_console_ms: u64,
    pub start_recorded: bool,
    /// The state last written to disk and announced.
    pub last_saved: State,
    /// Private-server code for the next spawn; memory only.
    pub secret_code: Option<String>,
    pub dirty: bool,
}

impl Live {
    pub fn new(rec: InstanceRecord) -> Live {
        let last_saved = rec.state;
        Live {
            rec,
            tr: Transient::default(),
            child: None,
            cg: None,
            oom_base: None,
            proc_tail: None,
            engine_tail: None,
            stop: None,
            started_ms: 0,
            devctl: None,
            last_console_ms: 0,
            start_recorded: false,
            last_saved,
            secret_code: None,
            dirty: false,
        }
    }

    pub fn has_process(&self) -> bool {
        self.rec.process.is_some()
    }
}

pub struct Inner {
    pub reg: Registry,
    pub live: BTreeMap<AccountName, Live>,
    pub queue: VecDeque<AccountName>,
    pub est: Estimator,
    pub last_start_ms: u64,
    pub net_status: BTreeMap<GroupName, (u64, GroupStatus)>,
    pub net_error: Option<(u64, String)>,
    pub spawn_seq: usize,
}

pub struct Events {
    subs: Mutex<Vec<SyncSender<Event>>>,
}

impl Events {
    pub fn new() -> Events {
        Events {
            subs: Mutex::new(Vec::new()),
        }
    }

    pub fn subscribe(&self) -> std::sync::mpsc::Receiver<Event> {
        let (tx, rx) = std::sync::mpsc::sync_channel(256);
        self.subs.lock().unwrap_or_else(|e| e.into_inner()).push(tx);
        rx
    }

    /// Deliver to every subscriber; one that is gone or not keeping up is
    /// dropped rather than allowed to hold up the daemon.
    pub fn emit(&self, ev: Event) {
        let mut subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        subs.retain(|tx| tx.try_send(ev.clone()).is_ok());
    }
}

pub struct Daemon {
    pub layout: Layout,
    pub cfg: RwLock<Arc<Config>>,
    pub inner: Mutex<Inner>,
    pub netd: NetdClient,
    pub deleg: Option<Delegated>,
    pub events: Events,
    pub shutdown: Arc<AtomicBool>,
    /// Set with `shutdown`: stop every instance before exiting.
    pub stop_after_instances: AtomicBool,
    pub started_at: u64,
    pub online_cpus: usize,
    pub samples: Mutex<crate::sampler::Samples>,
    pub secrets: crate::secrets::Secrets,
    pub notes: Mutex<Vec<String>>,
}

impl Daemon {
    pub fn cfg(&self) -> Arc<Config> {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn note(&self, msg: impl Into<String>) {
        let msg = msg.into();
        eprintln!("<5>cordiald: {msg}");
        let mut n = self.notes.lock().unwrap_or_else(|e| e.into_inner());
        if !n.contains(&msg) {
            n.push(msg);
            if n.len() > 50 {
                n.remove(0);
            }
        }
    }

    pub fn save_registry(&self, inner: &Inner) -> Result<()> {
        fsutil::write_json_atomic(&self.layout.registry_file(), &inner.reg, 0o600)
    }

    pub fn save_instance(&self, rec: &InstanceRecord) {
        if let Err(e) = fsutil::write_json_atomic(&self.layout.instance_record(&rec.id), rec, 0o600)
        {
            self.note(format!("could not save the record of {}: {e}", rec.id));
        }
    }

    /// Persist and announce a state change.
    pub fn changed(&self, live: &mut Live, from: hrd_core::model::State) {
        live.dirty = false;
        live.last_saved = live.rec.state;
        self.save_instance(&live.rec);
        if from != live.rec.state {
            self.events.emit(Event::State {
                id: live.rec.id.clone(),
                from,
                to: live.rec.state,
                reason: live.rec.reason.clone(),
                at: now_unix(),
            });
        }
    }
}

/// Load the registry, refusing a newer schema than this build understands.
pub fn load_registry(layout: &Layout) -> Result<Registry> {
    match fsutil::read_limited_opt(&layout.registry_file(), 64 * 1024 * 1024)? {
        None => Ok(Registry::default()),
        Some(b) => {
            let r: Registry = serde_json::from_slice(&b).map_err(|e| {
                Error::invalid(format!(
                    "{} is not a valid registry: {e}",
                    layout.registry_file().display()
                ))
            })?;
            if r.schema > hrd_core::model::REGISTRY_SCHEMA {
                return Err(Error::invalid(format!(
                    "the registry has schema {} and this build understands up to {}; install a newer cordiald",
                    r.schema,
                    hrd_core::model::REGISTRY_SCHEMA
                )));
            }
            Ok(r)
        }
    }
}

pub fn load_record(layout: &Layout, id: &AccountName) -> Option<InstanceRecord> {
    let b = fsutil::read_limited_opt(&layout.instance_record(id), 1024 * 1024).ok()??;
    serde_json::from_slice(&b).ok()
}
