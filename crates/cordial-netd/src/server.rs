//! The socket, the peer check and the request dispatch.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use hrd_core::ids::GroupName;
use hrd_core::proto::{encode_line, ResponseEnvelope, MAX_LINE};
use hrd_core::{Error, Result};
use hrd_net::plan::{self, Action, GroupSpec, Plan};
use hrd_net::proto::{ApplyOutcome, NetdEnvelope, NetdRequest, PlanReply};

use crate::apply::{self, Env};
use crate::{nsops, probe, status};

pub struct Shared {
    pub env: Env,
    /// Serialises every request that changes anything. Planning, applying and
    /// tearing down the same group concurrently would race on the same
    /// namespace.
    pub write_lock: Mutex<()>,
    pub allowed_uids: Vec<u32>,
}

pub fn bind(path: &Path, gid: Option<u32>, mode: u32) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::io(format!("create {}", dir.display()), e))?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::io(
                format!("remove the stale socket {}", path.display()),
                e,
            ))
        }
    }
    let l =
        UnixListener::bind(path).map_err(|e| Error::io(format!("bind {}", path.display()), e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io("chmod the socket", e))?;
    if let Some(gid) = gid {
        rustix::fs::chown(path, None, Some(rustix::fs::Gid::from_raw(gid)))
            .map_err(|e| Error::io("chown the socket", std::io::Error::from(e)))?;
    }
    Ok(l)
}

pub fn serve(listener: UnixListener, shared: Arc<Shared>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle(stream, &shared) {
                        eprintln!("<4>cordial-netd: connection ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("<4>cordial-netd: accept: {e}"),
        }
    }
}

fn handle(stream: UnixStream, shared: &Shared) -> Result<()> {
    let cred = rustix::net::sockopt::socket_peercred(&stream)
        .map_err(|e| Error::io("read the peer credentials", std::io::Error::from(e)))?;
    let uid = cred.uid.as_raw();
    if uid != 0 && !shared.allowed_uids.contains(&uid) {
        return Err(Error::Denied(format!(
            "uid {uid} is not allowed to use the network helper"
        )));
    }
    let mut writer = stream
        .try_clone()
        .map_err(|e| Error::io("clone the stream", e))?;
    let mut reader = BufReader::new(stream.take(MAX_LINE as u64));
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| Error::io("read a request", e))?;
        if n == 0 {
            return Ok(());
        }
        if !line.ends_with('\n') {
            return Err(Error::Protocol("request longer than the line limit".into()));
        }
        reader.get_mut().set_limit(MAX_LINE as u64);
        let reply = match serde_json::from_str::<NetdEnvelope>(&line) {
            Ok(env) => match dispatch(shared, env.req) {
                Ok(v) => ResponseEnvelope::ok(env.id, v),
                Err(e) => ResponseEnvelope::err(env.id, &e),
            },
            Err(e) => {
                ResponseEnvelope::err(0, &Error::Protocol(format!("unreadable request: {e}")))
            }
        };
        writer
            .write_all(&encode_line(&reply)?)
            .map_err(|e| Error::io("write a reply", e))?;
    }
}

fn check_specs(specs: &[GroupSpec]) -> Result<()> {
    for (i, a) in specs.iter().enumerate() {
        for b in &specs[i + 1..] {
            if a.group == b.group {
                return Err(Error::invalid(format!("group {} is listed twice", a.group)));
            }
            if a.network == b.network {
                return Err(Error::invalid(format!(
                    "network {} is used by both {} and {}. Two interfaces with one key fight over the gateway's endpoint for that key; a network belongs to one group",
                    a.network, a.group, b.group
                )));
            }
        }
    }
    Ok(())
}

fn build_plan(
    shared: &Shared,
    specs: &[GroupSpec],
    prune: bool,
) -> Result<(Plan, Vec<(GroupSpec, crate::store::StoredNetwork)>)> {
    check_specs(specs)?;
    let mut resolved = Vec::new();
    for s in specs {
        resolved.push((s.clone(), shared.env.store.get(&s.network)?));
    }
    let with_facts: Vec<_> = resolved
        .iter()
        .map(|(s, n)| (s.clone(), n.facts()))
        .collect();
    let manifest = shared.env.store.manifest();
    let env = &shared.env;
    let p = plan::diff(
        &with_facts,
        &manifest,
        &|g: &GroupName| nsops::is_nsfs(&env.ns_path(g)),
        prune,
        &apply::fresh_ifname,
    );
    Ok((p, resolved))
}

pub fn dispatch_public(shared: &Shared, req: NetdRequest) -> Result<serde_json::Value> {
    dispatch(shared, req)
}

fn dispatch(shared: &Shared, req: NetdRequest) -> Result<serde_json::Value> {
    let env = &shared.env;
    let to = |v: &dyn erased::Ser| v.value();
    match req {
        NetdRequest::Ping => {
            Ok(serde_json::json!({ "pong": true, "version": env!("CARGO_PKG_VERSION") }))
        }
        NetdRequest::PutNetwork { name, config, dns } => {
            let _g = shared.write_lock.lock().unwrap_or_else(|e| e.into_inner());
            to(&env.store.put(&name, &config, &dns)?)
        }
        NetdRequest::DeleteNetwork { name } => {
            let _g = shared.write_lock.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((g, _)) = env
                .store
                .manifest()
                .groups
                .iter()
                .find(|(_, a)| a.network == name)
            {
                return Err(Error::conflict(format!(
                    "network {name} is applied to group {g}; tear that group down first"
                )));
            }
            env.store.delete(&name)?;
            Ok(serde_json::json!({ "deleted": name }))
        }
        NetdRequest::ListNetworks => to(&env.store.list()),
        NetdRequest::Plan { groups, prune } => {
            let (p, resolved) = build_plan(shared, &groups, prune)?;
            let dir = env.layout.netns_dir();
            let dir = dir.to_string_lossy();
            let mut text = Vec::new();
            for gp in &p.groups {
                text.push(format!(
                    "group {}: {:?} ({})",
                    gp.group, gp.action, gp.reason
                ));
                for s in &gp.steps {
                    text.push(format!("    {}", s.describe(&dir)));
                }
            }
            let ipv6 = resolved
                .iter()
                .map(|(s, _)| (s.group.clone(), s.ipv6))
                .collect();
            to(&PlanReply {
                plan: p,
                text,
                ipv6,
            })
        }
        NetdRequest::Apply {
            groups,
            prune,
            allow_disruptive,
        } => {
            let _g = shared.write_lock.lock().unwrap_or_else(|e| e.into_inner());
            let (p, resolved) = build_plan(shared, &groups, prune)?;
            let mut out: Vec<ApplyOutcome> = Vec::new();
            for gp in &p.groups {
                let outcome = |ok: bool, message: String| ApplyOutcome {
                    group: gp.group.clone(),
                    ok,
                    action: gp.action,
                    message,
                };
                if gp.action == Action::Unchanged {
                    out.push(outcome(true, "already applied; nothing to do".into()));
                    continue;
                }
                if gp.disruptive && !allow_disruptive.contains(&gp.group) {
                    out.push(outcome(false, format!("{:?} would interrupt clients that may be running in {}; stop them or allow it explicitly", gp.action, gp.group)));
                    continue;
                }
                let result = match gp.action {
                    Action::Remove => apply::remove_group(env, &gp.group),
                    _ => {
                        let Some((spec, net)) = resolved.iter().find(|(s, _)| s.group == gp.group)
                        else {
                            out.push(outcome(
                                false,
                                "internal: no resolved network for the group".into(),
                            ));
                            continue;
                        };
                        apply::apply_group(env, gp, spec, net)
                    }
                };
                out.push(match result {
                    Ok(()) => outcome(true, format!("{:?} done", gp.action)),
                    Err(e) => outcome(false, e.to_string()),
                });
            }
            to(&out)
        }
        NetdRequest::Teardown {
            group,
            allow_disruptive,
        } => {
            let _g = shared.write_lock.lock().unwrap_or_else(|e| e.into_inner());
            if !allow_disruptive {
                return Err(Error::conflict(
                    "tearing a group down interrupts its clients; pass allow_disruptive",
                ));
            }
            apply::remove_group(env, &group)?;
            Ok(serde_json::json!({ "removed": group }))
        }
        NetdRequest::Status { groups } => {
            let statuses: Vec<_> = groups
                .iter()
                .map(|g| status::group_status(env, g))
                .collect();
            to(&statuses)
        }
        NetdRequest::ProbeStun { group, server } => to(&probe::stun_probe(env, &group, &server)?),
    }
}

/// A tiny shim so `dispatch` can turn any `Serialize` into a `Value` with `?`.
mod erased {
    pub trait Ser {
        fn value(&self) -> hrd_core::Result<serde_json::Value>;
    }
    impl<T: serde::Serialize> Ser for T {
        fn value(&self) -> hrd_core::Result<serde_json::Value> {
            serde_json::to_value(self)
                .map_err(|e| hrd_core::Error::Internal(format!("serialise a reply: {e}")))
        }
    }
}
