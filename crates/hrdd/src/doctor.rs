//! What the daemon can say about itself: `daemon_info` and its part of `doctor`.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use hrd_core::proto::{Check, CheckStatus};
use hrd_core::time::now_unix;
use hrd_core::Result;
use hrd_proc::hostcheck;

use crate::secrets::SecretsState;
use crate::state::Daemon;

pub fn info(d: &Daemon) -> Result<Value> {
    let inner = d.lock();
    let mut by_state: BTreeMap<String, u32> = BTreeMap::new();
    for l in inner.live.values() {
        *by_state.entry(l.rec.state.to_string()).or_default() += 1;
    }
    let cfg = d.cfg();
    let runtime = crate::runtime::current(&d.layout).map(|b| b.version).ok();
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "uptime_s": now_unix().saturating_sub(d.started_at),
        "accounts": inner.reg.accounts.len(),
        "groups": inner.reg.groups.len(),
        "networks": inner.reg.networks.len(),
        "queued": inner.queue.len(),
        "states": by_state,
        "process_ownership": if d.deleg.is_some() { "cgroup v2 (delegated subtree)" } else { "process group only (no delegated cgroup)" },
        "runtime_current": runtime,
        "max_instances": cfg.scheduler.max_instances,
        "concurrent_starts": crate::supervisor::concurrency(d, &cfg),
        "start_estimate_mib": inner.est.estimate(cfg.scheduler.assumed_start_peak_mib) / 1048576,
        "start_estimate_from_measurements": inner.est.samples(),
        "notes": d.notes.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    }))
}

fn chk(
    id: &str,
    title: &str,
    status: CheckStatus,
    detail: impl Into<String>,
    fix: Option<&str>,
) -> Check {
    Check {
        id: id.into(),
        title: title.into(),
        status,
        detail: detail.into(),
        fix: fix.map(str::to_string),
    }
}

pub fn checks(d: &Daemon) -> Vec<Check> {
    let cfg = d.cfg();
    let mut v = hostcheck::host_checks(&d.layout, &cfg);
    v.push(match &d.deleg {
        Some(dl) => chk("ownership", "process ownership", CheckStatus::Ok, format!("cgroup v2: instances under {}; controllers: {}", dl.instances.path().display(), dl.controllers.join(" ")), None),
        None => chk("ownership", "process ownership", CheckStatus::Warn, "no delegated cgroup subtree: process sets are tracked by process group, which a program can leave; per-instance memory.current and limits are unavailable", Some("run under systemd with Delegate=yes (the packaged unit does)")),
    });
    v.push(match d.netd.ping() {
        Ok(()) => chk(
            "netd",
            "network helper",
            CheckStatus::Ok,
            format!("answering on {}", d.netd.path().display()),
            None,
        ),
        Err(e) => chk(
            "netd",
            "network helper",
            CheckStatus::Warn,
            e.to_string(),
            Some("systemctl start hrd-netd (only needed for network groups)"),
        ),
    });
    let s = d.secrets.status();
    v.push(chk(
        "secrets",
        "secret store",
        match s.state {
            SecretsState::Ready => CheckStatus::Ok,
            SecretsState::Disabled => CheckStatus::Fail,
            _ => CheckStatus::Warn,
        },
        s.detail,
        (s.state != SecretsState::Ready).then_some("hrdctl secrets unlock [--create]"),
    ));
    v.push(match crate::runtime::current(&d.layout) {
        Ok(b) => chk(
            "runtime",
            "runtime",
            CheckStatus::Ok,
            format!("build {} is current", b.version),
            None,
        ),
        Err(e) => chk(
            "runtime",
            "runtime",
            CheckStatus::Warn,
            e.to_string(),
            Some("hrdctl runtime import --apk PATH"),
        ),
    });
    // A session stored as a plain file would mean the upstream client ignored
    // CORDIAL_SECRET_STORE=keyring; say so loudly.
    let inner = d.lock();
    let leaks: Vec<String> = inner
        .reg
        .accounts
        .keys()
        .filter(|a| {
            let p = d.layout.account_profile(a, crate::spawn::PROFILE);
            ["cookies", "identity"].iter().any(|f| p.join(f).is_file())
        })
        .map(|a| a.to_string())
        .take(20)
        .collect();
    v.push(if leaks.is_empty() {
        chk("plaintext", "plaintext sessions", CheckStatus::Ok, "no account has a cookies or identity file in its profile", None)
    } else {
        chk("plaintext", "plaintext sessions", CheckStatus::Fail, format!("plain session files exist for: {}", leaks.join(", ")), Some("`hrdctl account logout NAME` erases them; report it, because the client was told to use only the keyring"))
    });
    for n in d.notes.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        v.push(chk("note", "note", CheckStatus::Info, n.clone(), None));
    }
    v
}
