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
use hrd_core::ids::{AccountName, NetworkName, ProxyGroupName};
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

    /// Live, or already decided over but with its process set not yet gone.
    /// Anything that removes or rewires an account must wait for this to be false.
    pub fn busy(&self) -> bool {
        self.rec.state.is_live() || self.has_process() || self.stop.is_some()
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
    pub net_status: BTreeMap<ProxyGroupName, (u64, GroupStatus)>,
    pub net_error: Option<(u64, String)>,
    pub spawn_seq: usize,
    /// Proxies whose key the helper is being asked to let go of. The lock is not
    /// held across that call, so this is what keeps a proxy group from taking the
    /// proxy meanwhile (it would be left pointing at a proxy that is gone).
    pub removing_networks: std::collections::BTreeSet<NetworkName>,
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
    /// Set when a shutdown request said explicitly what to do with the clients;
    /// otherwise a signal uses the configuration as it is at that moment.
    pub shutdown_decided: AtomicBool,
    pub started_at: u64,
    pub online_cpus: usize,
    pub samples: Mutex<crate::sampler::Samples>,
    pub secrets: crate::secrets::Secrets,
    pub notes: Mutex<Vec<String>>,
    pub update: Mutex<hrd_core::proto::UpdateView>,
    /// Set to ask the updater thread to check now.
    pub update_now: AtomicBool,
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
        eprintln!("<5>hrdd: {msg}");
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

/// Load the registry, refusing a newer schema than this build understands. An
/// older one is upgraded and written back at once; the file as it was is kept
/// beside it (`registry.json.schema1`) in case the older build is wanted again.
/// A backup that is already there is never replaced: if the older build was used
/// in between, this file is a different one and goes to `.schema1.1`, `.schema1.2`...
pub fn load_registry(layout: &Layout) -> Result<Registry> {
    let path = layout.registry_file();
    match fsutil::read_limited_opt(&path, 64 * 1024 * 1024)? {
        None => Ok(Registry::default()),
        Some(b) => {
            let (r, from) = Registry::from_slice(&b)
                .map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
            if let Some(old) = from {
                let mut keep = path.with_extension(format!("json.schema{old}"));
                let mut n = 0;
                while keep.exists() {
                    n += 1;
                    keep = path.with_extension(format!("json.schema{old}.{n}"));
                }
                fsutil::atomic_write(&keep, &b, 0o600)?;
                fsutil::write_json_atomic(&path, &r, 0o600)?;
                eprintln!(
                    "<5>hrdd: the registry was upgraded from schema {old} to {} (the old file is kept as {})",
                    r.schema,
                    keep.display()
                );
            }
            Ok(r)
        }
    }
}

pub fn load_record(layout: &Layout, id: &AccountName) -> Option<InstanceRecord> {
    let b = fsutil::read_limited_opt(&layout.instance_record(id), 1024 * 1024).ok()??;
    serde_json::from_slice(&b).ok()
}

/// A daemon over a scratch directory, for tests of the operations that need no
/// helper, no keyring and no client.
#[cfg(test)]
pub mod testing {
    use std::sync::atomic::AtomicBool;

    use super::*;

    pub fn daemon(tag: &str) -> Arc<Daemon> {
        daemon_with(tag, false)
    }

    /// `no_secrets`: `secrets.backend = none`, so removing an account has no stored
    /// session to erase first.
    pub fn daemon_with(tag: &str, no_secrets: bool) -> Arc<Daemon> {
        let root = std::env::temp_dir().join(format!("hrdd-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::under(&root);
        for p in [
            &layout.state_dir,
            &layout.run_dir,
            &layout.log_dir,
            &layout.instances_dir(),
        ] {
            fsutil::ensure_private_dir(p, 0o700).unwrap();
        }
        let mut cfg = Config::default();
        if no_secrets {
            cfg.secrets.backend = hrd_core::config::SecretBackend::None;
        }
        Arc::new(Daemon {
            netd: NetdClient::new(layout.netd_socket()),
            secrets: crate::secrets::Secrets::new(layout.clone(), &cfg),
            layout,
            cfg: RwLock::new(Arc::new(cfg)),
            inner: Mutex::new(Inner {
                reg: Registry::default(),
                live: BTreeMap::new(),
                queue: VecDeque::new(),
                est: Estimator::default(),
                last_start_ms: 0,
                net_status: BTreeMap::new(),
                net_error: None,
                spawn_seq: 0,
                removing_networks: Default::default(),
            }),
            deleg: None,
            events: Events::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            stop_after_instances: AtomicBool::new(false),
            shutdown_decided: AtomicBool::new(false),
            started_at: 0,
            online_cpus: 1,
            samples: Mutex::new(Default::default()),
            notes: Mutex::new(Vec::new()),
            update: Mutex::new(Default::default()),
            update_now: AtomicBool::new(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_older_registry_is_upgraded_on_load_and_no_backup_is_ever_replaced() {
        let d = testing::daemon("upgrade");
        let path = d.layout.registry_file();
        let v1 = br#"{"schema":1,
            "accounts":{"alt-01":{"name":"alt-01","group":"g01","created_at":1,"auth":{}}},
            "groups":{"g01":{"name":"g01","capacity":20,"created_at":2}}}"#;
        std::fs::write(&path, v1).unwrap();

        let r = load_registry(&d.layout).unwrap();
        assert_eq!(r.schema, hrd_core::model::REGISTRY_SCHEMA);
        assert_eq!(r.proxy_groups.len(), 1);
        assert!(r.accounts.values().next().unwrap().proxy_group.is_some());

        // written back in the new shape, with the old file beside it
        let now: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(now["schema"], hrd_core::model::REGISTRY_SCHEMA);
        let keep = path.with_extension("json.schema1");
        assert_eq!(std::fs::read(&keep).unwrap(), v1);

        // loading the upgraded file again changes nothing and writes no backup
        let again = load_registry(&d.layout).unwrap();
        assert_eq!(again.proxy_groups.len(), 1);
        assert_eq!(std::fs::read(&keep).unwrap(), v1);
        assert!(!path.with_extension("json.schema1.1").exists());

        // The older build was used again (its file restored, then changed) and the
        // registry is upgraded a second time: the first backup stays as it was and
        // the file this upgrade replaced is kept as well.
        let v1_later = br#"{"schema":1,
            "accounts":{"alt-02":{"name":"alt-02","group":"g01","created_at":3,"auth":{}}},
            "groups":{"g01":{"name":"g01","capacity":20,"created_at":2}}}"#;
        std::fs::write(&path, v1_later).unwrap();
        let second = load_registry(&d.layout).unwrap();
        assert!(second
            .accounts
            .contains_key(&AccountName::new("alt-02").unwrap()));
        assert_eq!(std::fs::read(&keep).unwrap(), v1);
        assert_eq!(
            std::fs::read(path.with_extension("json.schema1.1")).unwrap(),
            v1_later
        );
    }

    #[test]
    fn a_registry_from_a_newer_build_is_refused_and_left_alone() {
        let d = testing::daemon("future");
        let path = d.layout.registry_file();
        std::fs::write(&path, br#"{"schema":99}"#).unwrap();
        let e = load_registry(&d.layout).unwrap_err().to_string();
        assert!(e.contains("schema 99"), "{e}");
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"schema":99}"#);
    }
}
