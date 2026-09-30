//! The control socket: who may connect, and what a request does.
//!
//! Newline-delimited JSON over a Unix socket (hrd-core `proto`). The socket's
//! mode and group decide who can connect at all; on top of that every
//! connection is checked with `SO_PEERCRED`: root, the daemon's own user, the
//! configured extra uids, or a member of the socket's group. Anyone admitted can
//! do everything the manager can do, which is what the service user can do
//! anyway; nothing here is a boundary against that user.

use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use hrd_core::config::Config;
use hrd_core::layout::Layout;
use hrd_core::proto::{Event, Request, RequestEnvelope, ResponseEnvelope, PROTOCOL_VERSION};
use hrd_core::redact::scrub;
use hrd_core::wire::{Conn, PeerCred};
use hrd_core::{fsutil, Error, Result};

use crate::state::Daemon;
use crate::{doctor, logtail, ops_instances as oi, ops_registry as or};

const MAX_CONNECTIONS: usize = 64;

pub fn bind(layout: &Layout, cfg: &Config) -> Result<UnixListener> {
    let path = layout.control_socket();
    if let Some(dir) = path.parent() {
        fsutil::ensure_private_dir(dir, 0o750)?;
    }
    if path.exists() {
        // Only a socket nobody answers on is stale.
        if UnixStream::connect(&path).is_ok() {
            return Err(Error::conflict(format!(
                "another cordiald is already listening on {}",
                path.display()
            )));
        }
        std::fs::remove_file(&path).map_err(|e| Error::io("remove the stale control socket", e))?;
    }
    let l =
        UnixListener::bind(&path).map_err(|e| Error::io(format!("bind {}", path.display()), e))?;
    let mode =
        u32::from_str_radix(cfg.control.socket_mode.trim_start_matches('0'), 8).unwrap_or(0o660);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io("chmod the control socket", e))?;
    if let Some(gid) = lookup_gid(&cfg.service.group) {
        if let Err(e) = rustix::fs::chown(&path, None, Some(rustix::fs::Gid::from_raw(gid))) {
            eprintln!(
                "<4>cordiald: cannot set the control socket's group to {}: {}",
                cfg.service.group,
                std::io::Error::from(e)
            );
        }
    }
    Ok(l)
}

pub fn lookup_gid(group: &str) -> Option<u32> {
    std::fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next()? == group).then(|| f.nth(1)?.parse().ok())?
        })
}

fn groups_of(pid: u32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("Groups:").map(|g| {
                    g.split_whitespace()
                        .filter_map(|x| x.parse().ok())
                        .collect()
                })
            })
        })
        .unwrap_or_default()
}

fn allowed(cred: &PeerCred, cfg: &Config, socket_gid: Option<u32>) -> bool {
    cred.uid == 0
        || cred.uid == rustix::process::getuid().as_raw()
        || cfg.control.allowed_uids.contains(&cred.uid)
        || socket_gid.is_some_and(|g| cred.gid == g || groups_of(cred.pid).contains(&g))
}

pub fn serve(d: Arc<Daemon>, listener: UnixListener) {
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    listener.set_nonblocking(true).ok();
    while !d.shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).ok();
                if ACTIVE.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    continue;
                }
                ACTIVE.fetch_add(1, Ordering::Relaxed);
                let d = d.clone();
                std::thread::Builder::new()
                    .name("control".into())
                    .spawn(move || {
                        if let Err(e) = handle(&d, s) {
                            if !matches!(e, Error::Io { .. }) {
                                eprintln!("<6>cordiald: control connection ended: {e}");
                            }
                        }
                        ACTIVE.fetch_sub(1, Ordering::Relaxed);
                    })
                    .ok();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => {
                eprintln!("<4>cordiald: accept: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn handle(d: &Arc<Daemon>, stream: UnixStream) -> Result<()> {
    let mut conn = Conn::new(stream);
    let cred = conn.peer_cred()?;
    let cfg = d.cfg();
    let sock_gid = std::fs::metadata(d.layout.control_socket())
        .ok()
        .map(|m| std::os::unix::fs::MetadataExt::gid(&m));
    if !allowed(&cred, &cfg, sock_gid) {
        let e = Error::Denied(format!(
            "uid {} may not use the control socket (join the {} group)",
            cred.uid, cfg.service.group
        ));
        conn.send_json(&ResponseEnvelope::err(0, &e))?;
        return Ok(());
    }
    while let Some(line) = conn.read_line()? {
        if line.is_empty() {
            continue;
        }
        let env: RequestEnvelope = match serde_json::from_slice(&line) {
            Ok(e) => e,
            Err(e) => {
                conn.send_json(&ResponseEnvelope::err(
                    0,
                    &Error::Protocol(format!("unreadable request: {e}")),
                ))?;
                conn.drop_unclaimed_fds();
                continue;
            }
        };
        let id = env.id;
        match env.request {
            Request::Subscribe => return stream_events(d, conn, id),
            Request::Logs {
                id: acct,
                lines,
                follow: true,
            } => return stream_logs(d, conn, id, acct, lines),
            req => {
                let reply = match dispatch(d, &mut conn, req) {
                    Ok(v) => ResponseEnvelope::ok(id, v),
                    Err(e) => ResponseEnvelope::err(id, &e),
                };
                conn.drop_unclaimed_fds();
                conn.send_json(&reply)?;
            }
        }
    }
    Ok(())
}

fn dispatch(d: &Arc<Daemon>, conn: &mut Conn, req: Request) -> Result<Value> {
    use Request::*;
    match req {
        Hello { protocol, .. } => {
            if protocol != PROTOCOL_VERSION {
                return Err(Error::Protocol(format!(
                    "client speaks protocol {protocol}, daemon speaks {PROTOCOL_VERSION}"
                )));
            }
            Ok(json!({ "version": env!("CARGO_PKG_VERSION"), "protocol": PROTOCOL_VERSION }))
        }
        DaemonInfo => doctor::info(d),
        DaemonDoctor => or::to(&doctor::checks(d)),
        Shutdown { stop_instances } => {
            let stop = stop_instances.unwrap_or(
                d.cfg().scheduler.on_daemon_stop == hrd_core::config::OnDaemonStop::Stop,
            );
            if stop {
                oi::stop_all(d, false)?;
            }
            d.stop_after_instances.store(stop, Ordering::Relaxed);
            d.shutdown.store(true, Ordering::Relaxed);
            Ok(json!({ "shutting_down": true, "stopping_instances": stop }))
        }
        AccountAdd {
            name,
            labels,
            note,
            group,
        } => or::account_add(d, name, labels, note, group),
        AccountList => or::account_list(d),
        AccountSet {
            name,
            labels,
            note,
            mode,
        } => or::account_set(d, name, labels, note, mode),
        AccountRemove { name, confirm } => or::account_remove(d, name, confirm),
        AccountLogout { name } => or::account_logout(d, name),
        LoginStart { name } => oi::login_start(d, name),
        LoginStatus { name } => oi::login_status(d, name),
        LoginCancel { name } => oi::login_cancel(d, name),
        LoginShot { name } => oi::login_shot(d, name),
        LoginInput { name, action } => oi::login_input(d, name, action),
        AccountExport => or::account_export(d),
        AccountImport { accounts, replace } => or::account_import(d, accounts, replace),
        GroupCreate {
            name,
            network,
            capacity,
            note,
        } => or::group_create(d, name, network, capacity, note),
        GroupList => or::group_list(d),
        GroupAssign {
            group,
            accounts,
            create_missing,
        } => or::group_assign(d, group, accounts, create_missing),
        GroupRemove { name } => or::group_remove(d, name),
        GroupSet {
            name,
            capacity,
            network,
            clear_network,
            note,
        } => or::group_set(d, name, capacity, network, clear_network, note),
        NetworkRegister { network } => or::network_register(d, *network),
        NetworkList => or::network_list(d),
        NetworkRemove { name } => or::network_remove(d, name),
        NetworkPlan => or::network_plan(d),
        NetworkApply { prune } => or::network_apply(d, prune),
        NetworkCheck { name } => crate::netops::check(d, &name),
        NetworkSet {
            name,
            configured_exit,
            stun_server,
            max_clients,
        } => or::network_set(d, name, configured_exit, stun_server, max_clients),
        InstanceStart {
            account,
            place_id,
            group,
            private_server_code,
            mode,
        } => oi::instance_start(d, account, place_id, group, private_server_code, mode),
        InstanceStop { id, force } => oi::instance_stop(d, id, force),
        GroupStart {
            group,
            place_id,
            private_server_code,
            mode,
        } => oi::group_start(d, group, place_id, private_server_code, mode),
        StopAll { force } => oi::stop_all(d, force),
        QueueList => oi::queue_list(d),
        QueueCancel { ids, all } => oi::queue_cancel(d, ids, all),
        Status { filter } => oi::status(d, filter),
        InstanceShow { id } => oi::instance_show(d, id),
        Stats { .. } => oi::stats(d),
        Logs { id, lines, .. } => oi::logs(d, id, lines),
        Subscribe => unreachable!("handled before dispatch"),
        RuntimeImport {
            files,
            label,
            make_current,
        } => {
            let fds = conn.take_fds(files.len())?;
            oi::runtime_import(d, files, label, make_current, fds)
        }
        RuntimeList => oi::runtime_list(d),
        RuntimeUse { version } => oi::runtime_use(d, version),
        RuntimeRemove { version } => oi::runtime_remove(d, version),
        ConfigGet => or::config_get(d),
        ConfigSet { changes } => or::config_set(d, changes),
        SecretsStatus => or::to(&d.secrets.status()),
        SecretsLock => {
            if d.lock().live.values().any(|l| l.rec.state.is_live()) {
                return Err(Error::conflict("clients are running or queued; stop them first (they keep their session in the keyring while they run)"));
            }
            d.secrets.stop();
            or::to(&d.secrets.status())
        }
        SecretsUnlock { passphrase, create } => {
            let st = d.secrets.unlock(&passphrase, create)?;
            crate::auth::refresh_in_background(d.clone());
            or::to(&st)
        }
    }
}

/// Wait until the peer closes or `ms` passes; true if the peer has gone.
fn peer_gone(conn: &Conn, ms: i32) -> bool {
    use rustix::event::{poll, PollFd, PollFlags};
    let borrowed = conn.stream().as_fd();
    let mut fds = [PollFd::new(&borrowed, PollFlags::IN | PollFlags::RDHUP)];
    let ts = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: i64::from(ms) * 1_000_000,
    };
    match poll(&mut fds, Some(&ts)) {
        Ok(n) if n > 0 => {
            let ev = fds[0].revents();
            if ev.intersects(PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR) {
                return true;
            }
            // Readable: anything the client sends while streaming is ignored,
            // except that end-of-file ends the stream.
            let mut b = [0u8; 256];
            matches!(
                rustix::net::recv(conn.stream(), &mut b, rustix::net::RecvFlags::DONTWAIT),
                Ok((0, _))
            )
        }
        _ => false,
    }
}

fn stream_events(d: &Arc<Daemon>, mut conn: Conn, id: u64) -> Result<()> {
    let rx = d.events.subscribe();
    conn.send_json(&ResponseEnvelope::ok(id, json!({ "subscribed": true })))?;
    while !d.shutdown.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ev) => conn.send_json(&ResponseEnvelope::event(id, ev))?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if peer_gone(&conn, 0) {
                    return Ok(());
                }
            }
            Err(_) => break,
        }
    }
    conn.send_json(&ResponseEnvelope::end(id))
}

fn stream_logs(
    d: &Arc<Daemon>,
    mut conn: Conn,
    id: u64,
    acct: hrd_core::ids::AccountName,
    lines: usize,
) -> Result<()> {
    let first = oi::logs(d, acct.clone(), lines)?;
    conn.send_json(&ResponseEnvelope::ok(id, first))?;
    let mut tail = logtail::Tail::from_end(d.layout.instance_log(&acct));
    while !d.shutdown.load(Ordering::Relaxed) {
        for l in tail.poll(512 * 1024) {
            conn.send_json(&ResponseEnvelope::event(
                id,
                Event::Log {
                    id: acct.clone(),
                    line: scrub(&l).into_owned(),
                },
            ))?;
        }
        if peer_gone(&conn, 500) {
            return Ok(());
        }
    }
    conn.send_json(&ResponseEnvelope::end(id))
}

pub fn remove_socket(layout: &Layout) {
    let _: &Path = &layout.control_socket();
    let _ = std::fs::remove_file(layout.control_socket());
}
