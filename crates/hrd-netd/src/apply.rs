//! Executing a group's plan.
//!
//! One `match` over [`Step`] is the whole of what this helper can do to the
//! system. There is no step that takes a path, an address, a command or a
//! script from the requester; the values come from the stored configuration and
//! from the group's name, which is validated to a lowercase slug.

use std::fs::File;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use hrd_core::fsutil;
use hrd_core::ids::ProxyGroupName;
use hrd_core::layout::Layout;
use hrd_core::time::now_unix;
use hrd_core::{Error, Result};
use hrd_net::plan::{self, Action, AppliedGroup, GroupPlan, GroupSpec, Step, IFACE};
use hrd_net::wg::Endpoint;

use crate::exec::{self, Tools};
use crate::nsops;
use crate::store::{NetStore, StoredNetwork};

pub struct Env {
    pub layout: Layout,
    pub tools: Tools,
    pub store: NetStore,
}

impl Env {
    pub fn ns_path(&self, g: &ProxyGroupName) -> PathBuf {
        self.layout.netns_file(g)
    }

    fn open_ns(&self, g: &ProxyGroupName) -> Result<File> {
        nsops::open(&self.ns_path(g))
    }

    fn ip(&self, g: &ProxyGroupName, args: &[&str]) -> Result<()> {
        let ns = self.open_ns(g)?;
        exec::run_ok(&self.tools.ip, args, None, Some(&ns)).map(|_| ())
    }

    pub fn iface_exists(&self, g: &ProxyGroupName) -> bool {
        let Ok(ns) = self.open_ns(g) else {
            return false;
        };
        exec::run(
            &self.tools.ip,
            &["-o", "link", "show", "dev", IFACE],
            None,
            Some(&ns),
            std::time::Duration::from_secs(10),
        )
        .map(|o| o.ok())
        .unwrap_or(false)
    }
}

pub fn resolve_endpoint(e: &Endpoint) -> Result<SocketAddr> {
    match e {
        Endpoint::Ip(a) => Ok(*a),
        Endpoint::Host { host, port } => {
            let addrs: Vec<SocketAddr> = (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(|err| {
                    Error::unavailable(format!("cannot resolve the endpoint {host}: {err}"))
                })?
                .collect();
            addrs
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| addrs.first())
                .copied()
                .ok_or_else(|| Error::unavailable(format!("{host} has no address")))
        }
    }
}

/// A name for the interface while it exists in the host namespace, between
/// creation and the move. Unique enough not to collide with anything there.
pub fn fresh_ifname() -> String {
    let mut b = [0u8; 4];
    if let Ok(mut f) = File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    format!("hrdw{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
}

pub fn exec_step(
    env: &Env,
    step: &Step,
    spec: &GroupSpec,
    net: &StoredNetwork,
    endpoint: SocketAddr,
) -> Result<()> {
    let facts = net.facts();
    let blocked = plan::ipv6_blocked(spec.ipv6, &facts);
    match step {
        Step::CreateNetns { group } => nsops::create(&env.layout.netns_dir(), group),
        Step::LoopbackUp { group } => env.ip(group, &["link", "set", "lo", "up"]),
        Step::CreateWireguard { group, tmp } => {
            if env.iface_exists(group) {
                return Ok(());
            }
            exec::run_ok(&env.tools.ip, &["link", "add", tmp, "type", "wireguard"], None, None).map(|_| ()).map_err(|e| {
                Error::unavailable(format!("{e}. If the message says the link type is not supported, the kernel has no WireGuard: Debian's kernels (5.6 and later) include it; check `modprobe wireguard`"))
            })
        }
        Step::MoveWireguard { tmp, group } => {
            if env.iface_exists(group) {
                return Ok(());
            }
            let ns = env.ns_path(group);
            let ns = ns
                .to_str()
                .ok_or_else(|| Error::Internal("namespace path is not UTF-8".into()))?;
            // A path (it contains a slash) is read by `ip` as a namespace file
            // rather than a name under /var/run/netns.
            exec::run_ok(
                &env.tools.ip,
                &["link", "set", tmp, "netns", ns, "name", IFACE],
                None,
                None,
            )
            .map(|_| ())
        }
        Step::ConfigureWireguard { group, .. } => {
            let conf = net.wg.render_setconf(endpoint);
            let ns = env.open_ns(group)?;
            exec::run_ok(
                &env.tools.wg,
                &["setconf", IFACE, "/dev/stdin"],
                Some(conf.expose().as_bytes()),
                Some(&ns),
            )
            .map(|_| ())
        }
        Step::FlushAddresses { group } => env.ip(group, &["addr", "flush", "dev", IFACE]),
        Step::AddAddress { group, addr } => {
            env.ip(group, &["addr", "add", &addr.to_string(), "dev", IFACE])
        }
        Step::SetMtu { group, mtu } => {
            env.ip(group, &["link", "set", IFACE, "mtu", &mtu.to_string()])
        }
        Step::LinkUp { group } => env.ip(group, &["link", "set", IFACE, "up"]),
        Step::ReplaceDefaultRoute { group, v6 } => {
            if *v6 {
                env.ip(group, &["-6", "route", "replace", "default", "dev", IFACE])
            } else {
                env.ip(group, &["route", "replace", "default", "dev", IFACE])
            }
        }
        Step::DisableIpv6 { group } => {
            let ns = env.open_ns(group)?;
            for key in [
                "net.ipv6.conf.all.disable_ipv6",
                "net.ipv6.conf.default.disable_ipv6",
            ] {
                match nsops::sysctl(&ns, key, "1") {
                    Ok(()) => {}
                    // Kernel booted with ipv6.disable=1: nothing to disable.
                    Err(Error::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
        Step::InstallFirewall { group } => {
            let ns = env.open_ns(group)?;
            exec::run_ok(
                &env.tools.nft,
                &["-f", "-"],
                Some(plan::nft_ruleset(blocked).as_bytes()),
                Some(&ns),
            )
            .map(|_| ())
        }
        Step::WriteResolver { group, servers } => fsutil::atomic_write(
            &env.layout.netns_resolv(group),
            plan::resolv_conf(servers).as_bytes(),
            0o644,
        ),
        Step::WriteNsswitch { group } => {
            let orig = std::fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
            fsutil::atomic_write(
                &env.layout.netns_nsswitch(group),
                plan::nsswitch_with_dns_only(&orig).as_bytes(),
                0o644,
            )
        }
        Step::RemoveNetns { group } => nsops::remove(&env.layout.netns_dir(), group),
    }
}

/// Apply one group. On failure of a `Create`, what was made is removed again;
/// on failure of a `Reconfigure` the namespace is left as it is (the firewall
/// is the first step, so it is at worst closed) and the recorded hash is
/// cleared so the next plan shows the work still to do.
pub fn apply_group(env: &Env, gp: &GroupPlan, spec: &GroupSpec, net: &StoredNetwork) -> Result<()> {
    let endpoint = resolve_endpoint(&net.wg.peer.endpoint)?;
    let facts = net.facts();
    for step in &gp.steps {
        if let Err(e) = exec_step(env, step, spec, net, endpoint) {
            let mut m = env.store.manifest();
            match gp.action {
                Action::Create => {
                    let _ = nsops::remove(&env.layout.netns_dir(), &spec.group);
                    m.groups.remove(&spec.group);
                }
                _ => {
                    if let Some(a) = m.groups.get_mut(&spec.group) {
                        a.hash.clear();
                    }
                }
            }
            let _ = env.store.save_manifest(&m);
            return Err(Error::unavailable(format!(
                "group {}: {}: {e}",
                spec.group,
                step.describe("")
            )));
        }
    }
    let mut m = env.store.manifest();
    m.groups.insert(
        spec.group.clone(),
        AppliedGroup {
            network: spec.network.clone(),
            hash: plan::desired_hash(spec, &facts),
            applied_at: now_unix(),
            endpoint: endpoint.to_string(),
            ipv6_blocked: plan::ipv6_blocked(spec.ipv6, &facts),
        },
    );
    env.store.save_manifest(&m)
}

pub fn remove_group(env: &Env, group: &ProxyGroupName) -> Result<()> {
    nsops::remove(&env.layout.netns_dir(), group)?;
    let mut m = env.store.manifest();
    m.groups.remove(group);
    env.store.save_manifest(&m)
}
