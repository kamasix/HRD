//! `hrd-netd`: the privileged half of proxy groups.
//!
//! In this program and in `hrd-net`, whose protocol it speaks, a *group* is a
//! proxy group: the one unit that owns a network namespace and a tunnel.
//!
//! It does four things: stores WireGuard configurations the operator imported,
//! creates a namespace per proxy group with a tunnel and a default-drop firewall in
//! it, reports how they are, and removes them. It runs as root because those
//! need `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`; everything else about it is
//! chosen to keep that from being a way in:
//!
//! * the request vocabulary names proxy groups and networks and nothing else;
//! * the three tools it executes are found in system directories and refused if
//!   they are not root-owned;
//! * commands are argument vectors with a cleared environment, never a shell;
//! * peers are checked with `SO_PEERCRED` against one service user;
//! * it never reads a value that affects a command from the manager.
//!
//! Start it only through systemd (`packaging/systemd/hrd-netd.service`
//! restricts its capabilities, address families and filesystem).

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use hrd_core::layout::Layout;
use hrd_core::{Error, Result};

mod apply;
mod config;
mod exec;
mod nsops;
mod probe;
#[cfg(test)]
mod rootcheck;
mod server;
mod status;
mod store;

const USAGE: &str = "usage: hrd-netd [--root DIR] [--config FILE]\n\n  --root DIR     keep everything under DIR instead of /etc, /var, /run (development)\n  --config FILE  read this configuration instead of <root>/etc/cordial-hrd/netd.toml\n";

fn run() -> Result<()> {
    let mut layout = Layout::from_env();
    let mut config_path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => {
                layout = Layout::under(std::path::Path::new(
                    &args
                        .next()
                        .ok_or_else(|| Error::invalid("--root needs a directory"))?,
                ))
            }
            "--config" => {
                config_path = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| Error::invalid("--config needs a file"))?,
                ))
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(());
            }
            other => {
                return Err(Error::invalid(format!(
                    "unknown argument {other:?}\n{USAGE}"
                )))
            }
        }
    }
    let cfg = config::NetdConfig::load(
        &config_path.unwrap_or_else(|| layout.config_dir.join("netd.toml")),
    )?;

    let caps = rustix::thread::capabilities(None)
        .map_err(|e| Error::io("read capabilities", std::io::Error::from(e)))?;
    use rustix::thread::CapabilitySet as C;
    if !caps.effective.contains(C::NET_ADMIN) || !caps.effective.contains(C::SYS_ADMIN) {
        return Err(Error::Denied("hrd-netd needs CAP_NET_ADMIN and CAP_SYS_ADMIN (run it from its systemd unit, or as root)".into()));
    }

    let tools = exec::Tools::locate()?;
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let (uid, _) = config::lookup_user(&passwd, &cfg.service_user).ok_or_else(|| {
        Error::unavailable(format!(
            "user {:?} does not exist; create it (the package does) or set service_user",
            cfg.service_user
        ))
    })?;
    if uid == 0 {
        return Err(Error::invalid("service_user must not be root"));
    }
    let gid = config::lookup_group(&groups, &cfg.service_group);
    let store = store::NetStore::new(layout.netd_state_dir.clone());
    store.ensure()?;

    let shared = Arc::new(server::Shared {
        env: apply::Env {
            layout: layout.clone(),
            tools,
            store,
        },
        write_lock: Mutex::new(()),
        allowed_uids: vec![uid],
        service_may_define: cfg.allow_service_define,
    });

    if cfg.apply_on_start {
        reapply_recorded(&shared);
    }

    let listener = server::bind(&layout.netd_socket(), gid, 0o660)?;
    eprintln!(
        "<6>hrd-netd {}: listening on {}",
        env!("CARGO_PKG_VERSION"),
        layout.netd_socket().display()
    );
    server::serve(listener, shared);
    Ok(())
}

/// With `apply_on_start`, rebuild the proxy groups the last `apply` recorded. It
/// only ever re-creates what the operator had already applied.
fn reapply_recorded(shared: &Arc<server::Shared>) {
    use hrd_net::plan::GroupSpec;
    let m = shared.env.store.manifest();
    let specs: Vec<GroupSpec> = m
        .groups
        .iter()
        .map(|(g, a)| GroupSpec {
            group: g.clone(),
            network: a.network.clone(),
            ipv6: if a.ipv6_blocked {
                hrd_core::model::Ipv6Policy::Block
            } else {
                hrd_core::model::Ipv6Policy::Auto
            },
        })
        .collect();
    if specs.is_empty() {
        return;
    }
    eprintln!(
        "<6>hrd-netd: apply_on_start: re-applying {} recorded proxy group(s)",
        specs.len()
    );
    let req = hrd_net::proto::NetdRequest::Apply {
        groups: specs,
        prune: false,
        allow_disruptive: vec![],
    };
    match server_dispatch(shared, req) {
        Ok(v) => eprintln!("<6>hrd-netd: apply_on_start: {v}"),
        Err(e) => eprintln!("<3>hrd-netd: apply_on_start failed: {e}"),
    }
}

fn server_dispatch(
    shared: &server::Shared,
    req: hrd_net::proto::NetdRequest,
) -> Result<serde_json::Value> {
    server::dispatch_public(shared, req)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("<3>hrd-netd: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
