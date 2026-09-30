//! Operations on instances: start, stop, queue, status, sign-in sessions.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

use serde_json::{json, Value};

use hrd_core::ids::{AccountName, GroupName, PlaceId};
use hrd_core::model::{AuthStatus, Readiness, ResourceMode, RunKind, State};
use hrd_core::proto::{Filter, ImportFile, InstanceDetail, InstanceView, LoginAction, LoginView};
use hrd_core::redact::scrub;
use hrd_core::time::{monotonic_ms, now_unix};
use hrd_core::{Error, Result};

use crate::machine::set_state;
use crate::ops_registry::to;
use crate::state::{Daemon, Inner};
use crate::{devctl, logtail, netops, runs, runtime, secrets::SecretsState, spawn, views};

fn refresh_network_if_stale(d: &Daemon, group: &GroupName) {
    let stale = {
        let i = d.lock();
        i.net_status
            .get(group)
            .map(|(at, _)| now_unix().saturating_sub(*at) > 15)
            .unwrap_or(true)
    };
    if stale {
        netops::refresh(d);
    }
}

struct Ask {
    kind: RunKind,
    place: Option<PlaceId>,
    code: Option<String>,
    mode: Option<ResourceMode>,
    explicit_group: Option<GroupName>,
}

/// All the refusals that can be decided before anything is created, then the
/// queue entry.
fn enqueue(d: &Daemon, account: &AccountName, ask: Ask) -> Result<InstanceView> {
    let cfg = d.cfg();
    if let Some(p) = ask.place {
        spawn::join_url(p, ask.code.as_deref())?;
    }
    if ask.code.is_some() && cfg.engine.join_url_via == hrd_core::config::JoinVia::Argv {
        return Err(Error::invalid("a private server code needs engine.join_url_via = \"env\" (patched cordial-run); in arguments it would be readable by every local user"));
    }
    // Facts that need other components are gathered before the lock is taken.
    let group_name = {
        let i = d.lock();
        let acc = i
            .reg
            .accounts
            .get(account)
            .ok_or_else(|| Error::not_found(format!("no account {account}")))?;
        match (&ask.explicit_group, &acc.group) {
            (Some(e), Some(g)) if e != g => {
                return Err(Error::conflict(format!(
                    "{account} is assigned to group {g}, not {e}; use `group assign` to move it"
                )))
            }
            (Some(e), _) => Some(e.clone()),
            (None, g) => g.clone(),
        }
    };
    if let Some(g) = &group_name {
        refresh_network_if_stale(d, g);
    }
    runtime::current(&d.layout)?;
    let secrets = d.secrets.status();
    if secrets.state != SecretsState::Ready {
        return Err(Error::unavailable(format!(
            "the secret store is not ready: {} ({})",
            secrets.detail,
            format!("{:?}", secrets.state).to_lowercase()
        )));
    }

    let mut guard = d.lock();
    let inner: &mut Inner = &mut guard;
    let now = now_unix();
    // Group, capacity, route.
    let mut assign = false;
    if let Some(g) = &group_name {
        let gr = inner
            .reg
            .groups
            .get(g)
            .ok_or_else(|| Error::not_found(format!("no group {g}")))?
            .clone();
        let acc = inner
            .reg
            .accounts
            .get(account)
            .ok_or_else(|| Error::not_found(format!("no account {account}")))?;
        if acc.group.as_ref() != Some(g) {
            let members = inner
                .reg
                .accounts
                .values()
                .filter(|a| a.group.as_ref() == Some(g))
                .count();
            if members as u32 >= gr.capacity {
                return Err(Error::conflict(format!(
                    "group {g} is full ({members} of {})",
                    gr.capacity
                )));
            }
            assign = true;
        }
        match &gr.network {
            None if !cfg.network.allow_unrouted => {
                return Err(Error::unavailable(format!("group {g} has no network; attach one (`group create --network`) or set network.allow_unrouted (the client would then use the server's own address)")))
            }
            None => {}
            Some(n) => {
                let (ready, why) = netops::readiness(inner, cfg.network.handshake_max_age_s, g);
                if matches!(ready, Readiness::NotApplied | Readiness::Broken | Readiness::Unknown) {
                    return Err(Error::unavailable(format!(
                        "the network of group {g} ({n}) is not usable: {} ({}); the client was not started because it would not be routed",
                        why.unwrap_or_default(),
                        format!("{ready:?}").to_lowercase()
                    )));
                }
                if let Some(max) = inner.reg.networks.get(n).and_then(|n| n.max_clients) {
                    let live: usize = inner
                        .live
                        .values()
                        .filter(|l| l.rec.state.is_live() && l.rec.group.as_ref().is_some_and(|lg| inner.reg.groups.get(lg).and_then(|x| x.network.as_ref()) == Some(n)))
                        .count();
                    if live as u32 >= max {
                        return Err(Error::conflict(format!("network {n} already carries {live} live clients (max_clients = {max})")));
                    }
                }
            }
        }
    } else if !cfg.network.allow_unrouted {
        return Err(Error::unavailable(format!(
            "{account} has no group: `group assign` it, or set network.allow_unrouted"
        )));
    }
    // Session.
    if ask.kind == RunKind::Play {
        let auth = inner
            .reg
            .accounts
            .get(account)
            .ok_or_else(|| Error::not_found(format!("no account {account}")))?
            .auth
            .clone();
        if matches!(auth.status, AuthStatus::None | AuthStatus::Required) {
            let why = auth.detail.unwrap_or_else(|| "no session stored".into());
            let l = inner
                .live
                .get_mut(account)
                .ok_or_else(|| Error::not_found(format!("no account {account}")))?;
            let from = l.rec.state;
            if l.rec.state.can_start() && !l.has_process() && l.stop.is_none() {
                set_state(
                    &mut l.rec,
                    State::AuthRequired,
                    Some(format!("{why}; run `cordialctl account login {account}`")),
                    now,
                );
                d.changed(l, from);
            }
            return Err(Error::AuthRequired(format!(
                "{account} has no usable session ({why}); run `cordialctl account login {account}`"
            )));
        }
    }
    // State and ceiling.
    let live_total = inner
        .live
        .values()
        .filter(|l| l.rec.state.is_live())
        .count() as u32;
    let l = inner
        .live
        .get(account)
        .ok_or_else(|| Error::not_found(format!("no account {account}")))?;
    if !l.rec.state.can_start() {
        return Err(Error::conflict(format!(
            "{account} is {} and cannot be started; stop it first",
            l.rec.state
        )));
    }
    if l.has_process() || l.stop.is_some() {
        return Err(Error::conflict(format!(
            "the previous process set of {account} is still being stopped; try again in a few seconds"
        )));
    }
    if live_total >= cfg.scheduler.max_instances {
        return Err(Error::unavailable(format!(
            "{live_total} instances are live, the configured maximum (scheduler.max_instances)"
        )));
    }

    if assign {
        if let Some(a) = inner.reg.accounts.get_mut(account) {
            a.group = group_name.clone();
        }
        d.save_registry(inner)?;
    }
    let mode = runs::default_mode(
        &cfg,
        inner.reg.accounts.get(account).and_then(|a| a.mode),
        ask.mode,
    );
    let l = inner
        .live
        .get_mut(account)
        .ok_or_else(|| Error::not_found(format!("no account {account}")))?;
    let from = l.rec.state;
    l.rec.run += 1;
    l.rec.kind = ask.kind;
    l.rec.place_id = ask.place;
    l.rec.group = group_name;
    l.rec.mode = mode;
    l.rec.queued_at = Some(now);
    l.rec.started_at = None;
    l.rec.ended_at = None;
    l.rec.exit = None;
    l.rec.signals = Default::default();
    l.secret_code = ask.code;
    set_state(
        &mut l.rec,
        State::Queued,
        Some("waiting for a start slot".into()),
        now,
    );
    d.changed(l, from);
    if ask.kind == RunKind::Login {
        inner.queue.push_front(account.clone());
    } else {
        inner.queue.push_back(account.clone());
    }
    let samples = d.samples.lock().unwrap_or_else(|e| e.into_inner());
    let l = inner
        .live
        .get(account)
        .ok_or_else(|| Error::not_found(format!("no account {account}")))?;
    Ok(views::instance(inner, &samples, l))
}

pub fn instance_start(
    d: &Daemon,
    account: AccountName,
    place: PlaceId,
    group: Option<GroupName>,
    code: Option<String>,
    mode: Option<ResourceMode>,
) -> Result<Value> {
    to(&enqueue(
        d,
        &account,
        Ask {
            kind: RunKind::Play,
            place: Some(place),
            code,
            mode,
            explicit_group: group,
        },
    )?)
}

pub fn group_start(
    d: &Daemon,
    group: GroupName,
    place: PlaceId,
    code: Option<String>,
    mode: Option<ResourceMode>,
) -> Result<Value> {
    let members: Vec<AccountName> = {
        let i = d.lock();
        if !i.reg.groups.contains_key(&group) {
            return Err(Error::not_found(format!("no group {group}")));
        }
        i.reg
            .accounts
            .values()
            .filter(|a| a.group.as_ref() == Some(&group))
            .map(|a| a.name.clone())
            .collect()
    };
    let (mut queued, mut skipped) = (Vec::new(), Vec::new());
    for a in members {
        match enqueue(
            d,
            &a,
            Ask {
                kind: RunKind::Play,
                place: Some(place),
                code: code.clone(),
                mode,
                explicit_group: Some(group.clone()),
            },
        ) {
            Ok(_) => queued.push(a.to_string()),
            Err(e) => {
                skipped.push(json!({ "account": a, "code": e.code(), "reason": e.to_string() }))
            }
        }
    }
    Ok(json!({ "group": group, "queued": queued, "skipped": skipped }))
}

pub fn instance_stop(d: &Daemon, id: AccountName, force: bool) -> Result<Value> {
    let mut guard = d.lock();
    let inner: &mut Inner = &mut guard;
    stop_locked(d, inner, &id, force)
}

fn stop_locked(d: &Daemon, inner: &mut Inner, id: &AccountName, force: bool) -> Result<Value> {
    let l = inner
        .live
        .get_mut(id)
        .ok_or_else(|| Error::not_found(format!("no instance {id}")))?;
    let now = now_unix();
    let from = l.rec.state;
    if l.rec.state == State::Queued {
        inner.queue.retain(|q| q != id);
        let l = inner.live.get_mut(id).expect("present");
        l.secret_code = None;
        set_state(
            &mut l.rec,
            State::Stopped,
            Some("cancelled while queued".into()),
            now,
        );
        d.changed(l, from);
        return Ok(json!({ "id": id, "state": "stopped", "was": "queued" }));
    }
    if l.has_process() {
        runs::begin_stop(l, force, true);
        return Ok(json!({ "id": id, "state": l.rec.state, "stopping": true, "force": force }));
    }
    Ok(
        json!({ "id": id, "state": l.rec.state, "stopping": false, "note": "nothing is running for this instance" }),
    )
}

pub fn stop_all(d: &Daemon, force: bool) -> Result<Value> {
    let mut guard = d.lock();
    let inner: &mut Inner = &mut guard;
    let ids: Vec<AccountName> = inner
        .live
        .values()
        .filter(|l| l.rec.state.is_live())
        .map(|l| l.rec.id.clone())
        .collect();
    for id in &ids {
        let _ = stop_locked(d, inner, id, force);
    }
    Ok(json!({ "stopping": ids.len(), "force": force }))
}

pub fn queue_list(d: &Daemon) -> Result<Value> {
    let inner = d.lock();
    let samples = d.samples.lock().unwrap_or_else(|e| e.into_inner());
    let v: Vec<InstanceView> = inner
        .queue
        .iter()
        .filter_map(|id| inner.live.get(id))
        .map(|l| views::instance(&inner, &samples, l))
        .collect();
    to(&v)
}

pub fn queue_cancel(d: &Daemon, ids: Vec<AccountName>, all: bool) -> Result<Value> {
    let mut guard = d.lock();
    let inner: &mut Inner = &mut guard;
    let targets: Vec<AccountName> = if all {
        inner.queue.iter().cloned().collect()
    } else {
        ids
    };
    let mut cancelled = 0;
    for id in targets {
        if inner.queue.contains(&id) {
            stop_locked(d, inner, &id, false)?;
            cancelled += 1;
        }
    }
    Ok(json!({ "cancelled": cancelled }))
}

fn matches_filter(inner: &Inner, l: &crate::state::Live, f: &Filter) -> bool {
    let acc = inner.reg.accounts.get(&l.rec.id);
    (f.states.is_empty() || f.states.contains(&l.rec.state))
        && (f.group.is_none()
            || acc.and_then(|a| a.group.as_ref()) == f.group.as_ref()
            || l.rec.group == f.group)
        && f.label
            .as_ref()
            .is_none_or(|lb| acc.is_some_and(|a| a.labels.contains(lb)))
        && (f.accounts.is_empty() || f.accounts.contains(&l.rec.id))
}

pub fn status(d: &Daemon, f: Filter) -> Result<Value> {
    let inner = d.lock();
    let samples = d.samples.lock().unwrap_or_else(|e| e.into_inner());
    let v: Vec<InstanceView> = inner
        .live
        .values()
        .filter(|l| matches_filter(&inner, l, &f))
        .map(|l| views::instance(&inner, &samples, l))
        .collect();
    to(&v)
}

pub fn instance_show(d: &Daemon, id: AccountName) -> Result<Value> {
    let inner = d.lock();
    let l = inner
        .live
        .get(&id)
        .ok_or_else(|| Error::not_found(format!("no instance {id}")))?;
    let samples = d.samples.lock().unwrap_or_else(|e| e.into_inner());
    let view = views::instance(&inner, &samples, l);
    let members = samples
        .per
        .get(&id)
        .map(|s| s.members.clone())
        .unwrap_or_default();
    let log_tail = tail_lines(d, &id, 20);
    to(&InstanceDetail {
        view,
        record: l.rec.clone(),
        log_tail,
        members,
    })
}

pub fn tail_lines(d: &Daemon, id: &AccountName, n: usize) -> Vec<String> {
    logtail::last_lines(&d.layout.instance_log(id), n.min(2000), 1 << 20)
        .into_iter()
        .map(|l| scrub(&l).into_owned())
        .collect()
}

pub fn logs(d: &Daemon, id: AccountName, lines: usize) -> Result<Value> {
    if !d.lock().live.contains_key(&id) {
        return Err(Error::not_found(format!("no instance {id}")));
    }
    to(&tail_lines(d, &id, lines.max(1)))
}

pub fn stats(d: &Daemon) -> Result<Value> {
    let s = d.samples.lock().unwrap_or_else(|e| e.into_inner());
    to(&s.stats)
}

// ---------------------------------------------------------------- sign-in

pub fn login_start(d: &Daemon, name: AccountName) -> Result<Value> {
    let v = enqueue(
        d,
        &name,
        Ask {
            kind: RunKind::Login,
            place: None,
            code: None,
            mode: None,
            explicit_group: None,
        },
    )?;
    let _ = v;
    login_status(d, name)
}

fn login_view(d: &Daemon, inner: &Inner, name: &AccountName) -> Result<LoginView> {
    let l = inner
        .live
        .get(name)
        .ok_or_else(|| Error::not_found(format!("no account {name}")))?;
    let running = l.rec.kind == RunKind::Login && l.rec.state.is_live();
    let cfg = d.cfg();
    Ok(LoginView {
        account: name.clone(),
        running,
        state: l.rec.state,
        started_at: l.rec.started_at,
        expires_at: l
            .rec
            .started_at
            .filter(|_| running)
            .map(|t| t + cfg.login.timeout_s),
        screen: l.rec.signals.screen.clone(),
        signed_in: l.rec.signals.signed_in_at.is_some(),
        console: cfg.login.console && running,
        detail: l.rec.reason.clone(),
    })
}

pub fn login_status(d: &Daemon, name: AccountName) -> Result<Value> {
    let inner = d.lock();
    to(&login_view(d, &inner, &name)?)
}

pub fn login_cancel(d: &Daemon, name: AccountName) -> Result<Value> {
    {
        let i = d.lock();
        let l = i
            .live
            .get(&name)
            .ok_or_else(|| Error::not_found(format!("no account {name}")))?;
        if l.rec.kind != RunKind::Login || !l.rec.state.is_live() {
            return Err(Error::conflict(format!(
                "no sign-in session is running for {name}"
            )));
        }
    }
    instance_stop(d, name, false)
}

fn console_socket(d: &Daemon, name: &AccountName) -> Result<(PathBuf, u64)> {
    let cfg = d.cfg();
    if !cfg.login.console {
        return Err(Error::Denied(
            "the sign-in console is switched off (login.console = false)".into(),
        ));
    }
    let inner = d.lock();
    let l = inner
        .live
        .get(name)
        .ok_or_else(|| Error::not_found(format!("no account {name}")))?;
    // Only a sign-in run has a control surface, and only while it is live.
    if l.rec.kind != RunKind::Login
        || !matches!(
            l.rec.state,
            State::Starting | State::Joining | State::Unknown
        )
    {
        return Err(Error::conflict(format!("no sign-in session is running for {name}; start one with `cordialctl account login {name}`")));
    }
    let sock = l
        .devctl
        .clone()
        .ok_or_else(|| Error::unavailable("the sign-in client has no control surface"))?;
    Ok((sock, cfg.login.max_text_len as u64))
}

pub fn login_shot(d: &Daemon, name: AccountName) -> Result<Value> {
    let (sock, _) = console_socket(d, &name)?;
    let file = d.layout.instance_run(&name).join("shot.png");
    to(&devctl::screenshot(&sock, &file)?)
}

pub fn login_input(d: &Daemon, name: AccountName, action: LoginAction) -> Result<Value> {
    let (sock, max) = console_socket(d, &name)?;
    // One human action at a time: at most ten a second per session.
    {
        let mut inner = d.lock();
        let l = inner
            .live
            .get_mut(&name)
            .ok_or_else(|| Error::not_found("no such instance"))?;
        let now = monotonic_ms();
        if now.saturating_sub(l.last_console_ms) < 100 {
            return Err(Error::unavailable(
                "too fast: the console takes one action per 100 ms",
            ));
        }
        l.last_console_ms = now;
    }
    devctl::perform(&sock, &action, max as usize)?;
    Ok(json!({ "ok": true }))
}

// ------------------------------------------------------------------ runtime

fn importer(d: &Daemon) -> std::process::Command {
    let mut c = std::process::Command::new(&d.cfg().engine.importer);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null());
    c
}

fn run_importer(mut c: std::process::Command) -> Result<Value> {
    let out = c
        .output()
        .map_err(|e| Error::unavailable(format!("cannot run cordial-import: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        let msg = stderr
            .lines()
            .last()
            .or_else(|| stdout.lines().last())
            .unwrap_or("the importer failed");
        return Err(Error::invalid(
            msg.trim_start_matches("cordial-import: ").to_string(),
        ));
    }
    serde_json::from_str(stdout.trim()).or_else(|_| Ok(json!({ "output": stdout.trim() })))
}

pub fn runtime_list(d: &Daemon) -> Result<Value> {
    let mut c = importer(d);
    c.args(["list", "--store"])
        .arg(d.layout.runtime_store())
        .arg("--json");
    let mut v = run_importer(c)?;
    let inner = d.lock();
    let is_top = v.is_array();
    let arr = if is_top {
        v.as_array_mut()
    } else {
        v.get_mut("builds").and_then(|b| b.as_array_mut())
    };
    if let Some(arr) = arr {
        for b in arr {
            let ver = b
                .get("version")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let users: Vec<&AccountName> = inner
                .live
                .values()
                .filter(|l| {
                    l.rec.runtime.as_deref() == Some(&ver) && l.rec.state.expects_processes()
                })
                .map(|l| &l.rec.id)
                .collect();
            if let Some(o) = b.as_object_mut() {
                o.insert("in_use_by".into(), json!(users));
            }
        }
    }
    Ok(v)
}

pub fn runtime_use(d: &Daemon, version: String) -> Result<Value> {
    check_version(&version)?;
    let mut c = importer(d);
    c.args(["use", "--store"])
        .arg(d.layout.runtime_store())
        .arg(&version);
    run_importer(c)?;
    Ok(json!({ "current": version, "note": "running instances keep the build they started with" }))
}

pub fn runtime_remove(d: &Daemon, version: String) -> Result<Value> {
    check_version(&version)?;
    let in_use: Vec<String> = d
        .lock()
        .live
        .values()
        .filter(|l| l.rec.state.expects_processes() || l.rec.state == State::Queued)
        .filter_map(|l| l.rec.runtime.clone())
        .collect();
    let mut c = importer(d);
    c.args(["remove", "--store"])
        .arg(d.layout.runtime_store())
        .arg(&version);
    for v in in_use {
        c.arg("--in-use").arg(v);
    }
    run_importer(c)?;
    Ok(json!({ "removed": version }))
}

fn check_version(v: &str) -> Result<()> {
    if v.is_empty()
        || v.len() > 64
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        || v.starts_with('.')
        || v.starts_with('-')
    {
        Err(Error::invalid("not a runtime version"))
    } else {
        Ok(())
    }
}

/// Run the importer with the operator's files as inherited descriptors.
pub fn runtime_import(
    d: &Daemon,
    files: Vec<ImportFile>,
    label: Option<String>,
    make_current: bool,
    fds: Vec<OwnedFd>,
) -> Result<Value> {
    if files.is_empty() || files.len() != fds.len() {
        return Err(Error::invalid(
            "the request must name and carry at least one file",
        ));
    }
    let mut c = importer(d);
    c.args(["import", "--store"]).arg(d.layout.runtime_store());
    let mut highs = Vec::new();
    for (i, (f, fd)) in files.iter().zip(fds).enumerate() {
        // Move each descriptor out of the low range so that placing it at its
        // final number in the child cannot overwrite another one.
        let high = rustix::io::fcntl_dupfd_cloexec(&fd, 100)
            .map_err(|e| Error::io("duplicate a descriptor", std::io::Error::from(e)))?;
        let name: String = f
            .name
            .chars()
            .filter(|c| c.is_ascii_graphic() && *c != ':')
            .take(96)
            .collect();
        c.arg("--fd").arg(format!("{}:{name}", 3 + i));
        highs.push(high);
    }
    if let Some(l) = label {
        c.arg("--label").arg(
            l.chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect::<String>(),
        );
    }
    if make_current {
        c.arg("--make-current");
    }
    c.arg("--json");
    spawn::place_descriptors(&mut c, &highs);
    let r = run_importer(c);
    drop(highs);
    r
}
