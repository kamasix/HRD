//! `cordiald`: the one daemon that owns the fleet.
//!
//! It starts with no clients, starts a client only when a command tells it to,
//! and never starts one again on its own. See docs/architecture.md.

mod adopt;
mod auth;
mod control;
mod devctl;
mod doctor;
mod effective;
mod logtail;
mod machine;
mod netops;
mod ops_instances;
mod ops_registry;
mod runs;
mod runtime;
mod sampler;
mod sched;
mod secrets;
mod signals;
mod spawn;
mod state;
mod supervisor;
mod views;

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use hrd_core::layout::Layout;
use hrd_core::time::now_unix;
use hrd_core::{fsutil, Error, Result};
use hrd_net::client::NetdClient;
use hrd_proc::cgroup;

use crate::sched::Estimator;
use crate::state::{Daemon, Events, Inner};

const USAGE: &str = "\
usage: cordiald [--root DIR] [--check-config] [--version]

  --root DIR       keep everything under DIR instead of /etc, /var, /run
                   (development and tests; a packaged install never uses it)
  --check-config   load and validate the configuration, then exit
  --allow-root     run as root. For tests only: the daemon and every client are
                   meant to run as an unprivileged user
  --version

The daemon is normally started by systemd (cordiald.service).
";

struct Args {
    root: Option<PathBuf>,
    check: bool,
    allow_root: bool,
}

fn parse() -> std::result::Result<Args, String> {
    let mut a = Args {
        root: None,
        check: false,
        allow_root: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--root" => a.root = Some(PathBuf::from(it.next().ok_or("--root needs a directory")?)),
            "--check-config" => a.check = true,
            "--allow-root" => a.allow_root = true,
            "--version" => {
                println!("cordiald {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => return Err(String::new()),
            o => return Err(format!("unknown argument {o}")),
        }
    }
    Ok(a)
}

fn fatal(e: impl std::fmt::Display) -> ExitCode {
    eprintln!("<3>cordiald: {e}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(a) => a,
        Err(m) => {
            if !m.is_empty() {
                eprintln!("cordiald: {m}");
            }
            eprint!("{USAGE}");
            return ExitCode::from(if m.is_empty() { 0 } else { 2 });
        }
    };
    let layout = match &args.root {
        Some(r) => Layout::under(r),
        None => Layout::from_env(),
    };
    match run(args, layout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fatal(e),
    }
}

fn run(args: Args, layout: Layout) -> Result<()> {
    let (cfg, _) = effective::load(&layout)?;
    if args.check {
        println!(
            "configuration is valid ({})",
            layout.config_file().display()
        );
        return Ok(());
    }
    if fsutil::euid() == 0 && !args.allow_root {
        return Err(Error::Denied("refusing to run as root: start the daemon as the service user (the packaged unit does)".into()));
    }
    for (p, mode) in [
        (&layout.state_dir, 0o700),
        (&layout.run_dir, 0o750),
        (&layout.log_dir, 0o700),
        (&layout.instances_dir(), 0o700),
    ] {
        fsutil::ensure_private_dir(p, mode)?;
    }
    let _lock = match fsutil::FileLock::try_acquire(&layout.daemon_lock())? {
        Some(l) => l,
        None => return Err(Error::conflict("another cordiald holds the lock")),
    };

    // Process ownership.
    let mut notes = Vec::new();
    // Under the packaged unit (`DelegateSubgroup=manager`) systemd has already put
    // this process in `<service>/manager`; the delegated subtree is the parent.
    let own = cgroup::own().map(|c| {
        if c.path().file_name().is_some_and(|n| n == "manager") {
            c.parent().unwrap_or(c)
        } else {
            c
        }
    });
    let deleg = match own {
        Some(base) => match cgroup::prepare_delegated(&base, std::process::id()) {
            Ok(d) => Some(d),
            Err(e) => {
                notes.push(format!(
                    "no delegated cgroup at {} ({e}); falling back to process groups",
                    base.path().display()
                ));
                None
            }
        },
        None => {
            notes.push("cgroup v2 is not available; falling back to process groups".to_string());
            None
        }
    };

    let reg = state::load_registry(&layout)?;
    let online = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let d = Arc::new(Daemon {
        netd: NetdClient::new(layout.netd_socket()),
        secrets: secrets::Secrets::new(layout.clone(), &cfg),
        layout: layout.clone(),
        cfg: RwLock::new(Arc::new(cfg.clone())),
        inner: Mutex::new(Inner {
            reg,
            live: BTreeMap::new(),
            queue: VecDeque::new(),
            est: Estimator::default(),
            last_start_ms: 0,
            net_status: BTreeMap::new(),
            net_error: None,
            spawn_seq: 0,
        }),
        deleg,
        events: Events::new(),
        shutdown: Arc::new(AtomicBool::new(false)),
        stop_after_instances: AtomicBool::new(false),
        shutdown_decided: AtomicBool::new(false),
        started_at: now_unix(),
        online_cpus: online,
        samples: Mutex::new(Default::default()),
        notes: Mutex::new(Vec::new()),
    });
    for n in notes {
        d.note(n);
    }
    {
        let mut inner = d.lock();
        adopt::adopt_all(&d, &mut inner);
        let adopted = inner.live.values().filter(|l| l.has_process()).count();
        eprintln!("<6>cordiald: {} accounts, {adopted} running instance(s) adopted; starting with an empty queue", inner.reg.accounts.len());
    }

    let listener = control::bind(&layout, &cfg)?;
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, d.shutdown.clone()).ok();
    }
    sampler::spawn_thread(d.clone());
    auth::spawn_periodic(d.clone());
    {
        let d2 = d.clone();
        std::thread::Builder::new()
            .name("control".into())
            .spawn(move || control::serve(d2, listener))
            .ok();
    }
    supervisor::spawn_net_refresh(d.clone());
    eprintln!(
        "<6>cordiald: listening on {}",
        layout.control_socket().display()
    );

    supervisor::run(d.clone());

    // Shutting down.
    let stop = if d.shutdown_decided.load(Ordering::Relaxed) {
        d.stop_after_instances.load(Ordering::Relaxed)
    } else {
        d.cfg().scheduler.on_daemon_stop == hrd_core::config::OnDaemonStop::Stop
    };
    if stop {
        let _ = ops_instances::stop_all(&d, false);
        let grace = d.cfg().scheduler.stop_grace_s + 10;
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(grace) {
            supervisor::tick(&d);
            if d.lock().live.values().all(|l| !l.has_process()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        d.secrets.stop();
    } else {
        eprintln!("<6>cordiald: leaving running instances alone (scheduler.on_daemon_stop = keep)");
    }
    control::remove_socket(&layout);
    Ok(())
}
