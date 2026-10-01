//! The daemon's side of proxy groups: turning the registry into requests for
//! the helper, and the helper's status into a readiness the operator can read.
//!
//! The daemon only ever *names* things to the helper: which proxy group leaves
//! through which network. Addresses, keys, routes and commands are derived
//! inside the helper from what it stored itself. (In the helper's own protocol
//! the word for a proxy group is "group": one namespace and one tunnel.)

use std::path::Path;

use hrd_core::ids::{NetworkName, ProxyGroupName};
use hrd_core::layout::Layout;
use hrd_core::model::Readiness;
use hrd_core::time::now_unix;
use hrd_core::{Error, Result};
use hrd_net::plan::GroupSpec;
use hrd_net::proto::{ApplyOutcome, GroupStatus, NetdRequest, PlanReply, StunResult};

use crate::state::{Daemon, Inner};

/// Is there a live namespace handle for the proxy group? The helper creates it;
/// the entry wrapper re-checks it before every start.
pub fn namespace_present(layout: &Layout, g: &ProxyGroupName) -> bool {
    is_nsfs(&layout.netns_file(g))
}

fn is_nsfs(p: &Path) -> bool {
    rustix::fs::statfs(p)
        .map(|s| s.f_type as u64 == 0x6e73_6673)
        .unwrap_or(false)
}

pub fn specs(inner: &Inner) -> Vec<GroupSpec> {
    inner
        .reg
        .proxy_groups
        .values()
        .filter_map(|g| {
            let n = g.network.as_ref()?;
            let net = inner.reg.networks.get(n)?;
            Some(GroupSpec {
                group: g.name.clone(),
                network: n.clone(),
                ipv6: net.ipv6,
            })
        })
        .collect()
}

fn live_in_group(inner: &Inner, g: &ProxyGroupName) -> usize {
    inner
        .live
        .values()
        .filter(|l| l.rec.proxy_group.as_ref() == Some(g) && l.busy())
        .count()
}

pub fn plan(d: &Daemon) -> Result<PlanReply> {
    let specs = specs(&d.lock());
    d.netd.call(NetdRequest::Plan {
        groups: specs,
        prune: true,
    })
}

pub fn apply(d: &Daemon, prune: bool) -> Result<Vec<ApplyOutcome>> {
    let (specs, disruptive) = {
        let inner = d.lock();
        let specs = specs(&inner);
        // A rebuild cuts live clients off; only groups with none may be rebuilt.
        let ok: Vec<ProxyGroupName> = specs
            .iter()
            .filter(|s| live_in_group(&inner, &s.group) == 0)
            .map(|s| s.group.clone())
            .collect();
        (specs, ok)
    };
    let out: Vec<ApplyOutcome> = d.netd.call(NetdRequest::Apply {
        groups: specs,
        prune,
        allow_disruptive: disruptive,
    })?;
    refresh(d);
    Ok(out)
}

pub fn status_of(d: &Daemon, groups: Vec<ProxyGroupName>) -> Result<Vec<GroupStatus>> {
    // A short timeout: a hung helper must not stall whoever asks.
    d.netd
        .clone()
        .with_timeout(std::time::Duration::from_secs(5))
        .call(NetdRequest::Status { groups })
}

/// Ask the helper about every proxy group and cache the answer. Never called with the
/// state lock held.
pub fn refresh(d: &Daemon) {
    let groups: Vec<ProxyGroupName> = d.lock().reg.proxy_groups.keys().cloned().collect();
    if groups.is_empty() {
        return;
    }
    let res = status_of(d, groups);
    let mut inner = d.lock();
    let now = now_unix();
    match res {
        Ok(list) => {
            inner.net_error = None;
            for st in list {
                if let Some(g) = st.group.clone() {
                    inner.net_status.insert(g, (now, st));
                }
            }
        }
        Err(e) => inner.net_error = Some((now, e.to_string())),
    }
}

pub fn readiness(
    inner: &Inner,
    handshake_max_age_s: u64,
    g: &ProxyGroupName,
) -> (Readiness, Option<String>) {
    let Some(group) = inner.reg.proxy_groups.get(g) else {
        return (Readiness::Unknown, None);
    };
    if group.network.is_none() {
        return (
            Readiness::NotApplied,
            Some("the proxy group has no proxy".into()),
        );
    }
    if let Some((at, e)) = &inner.net_error {
        if now_unix().saturating_sub(*at) < 120 && !inner.net_status.contains_key(g) {
            return (
                Readiness::Unknown,
                Some(format!("the network helper could not be asked: {e}")),
            );
        }
    }
    match inner.net_status.get(g) {
        None => (Readiness::Unknown, Some("not checked yet".into())),
        Some((_, st)) if !st.namespace_present => (
            Readiness::NotApplied,
            Some("the namespace does not exist: run `hrdctl proxy apply`".into()),
        ),
        Some((_, st)) if !st.interface_present || !st.link_up || !st.problems.is_empty() => (
            Readiness::Broken,
            Some(if st.problems.is_empty() {
                "the tunnel interface is missing or down".into()
            } else {
                st.problems.join("; ")
            }),
        ),
        Some((_, st)) => match st.latest_handshake {
            Some(t) if now_unix().saturating_sub(t) <= handshake_max_age_s => {
                (Readiness::Ready, None)
            }
            Some(t) => (
                Readiness::Unverified,
                Some(format!(
                    "last handshake {} s ago",
                    now_unix().saturating_sub(t)
                )),
            ),
            None => (
                Readiness::Unverified,
                Some("no handshake yet: the tunnel may not reach its peer".into()),
            ),
        },
    }
}

/// Probe a network from inside its proxy group's namespace and record what the
/// far end saw as the *observed* exit, alongside (never replacing) the configured one.
pub fn check(d: &Daemon, name: &NetworkName) -> Result<serde_json::Value> {
    let (group, server) = {
        let inner = d.lock();
        let net = inner
            .reg
            .networks
            .get(name)
            .ok_or_else(|| Error::not_found(format!("no network {name}")))?;
        let group = inner
            .reg
            .proxy_groups
            .values()
            .find(|g| g.network.as_ref() == Some(name))
            .map(|g| g.name.clone())
            .ok_or_else(|| Error::conflict(format!("proxy {name} is not used by any proxy group; give it one with `hrdctl proxy-group create --proxy {name}`")))?;
        let server = net.stun_server.clone().ok_or_else(|| {
            Error::invalid(format!("proxy {name} has no stun_server: the manager contacts only servers you name (`hrdctl proxy set {name} --stun-server HOST:PORT`)"))
        })?;
        (group, server)
    };
    let r: StunResult = d.netd.call(NetdRequest::ProbeStun {
        group: group.clone(),
        server,
    })?;
    let mut inner = d.lock();
    let net = inner
        .reg
        .networks
        .get_mut(name)
        .ok_or_else(|| Error::not_found("network vanished"))?;
    net.exit.observed = Some(hrd_core::model::ObservedExit {
        address: r.address,
        via: hrd_core::model::ProbeKind::Stun,
        at: now_unix(),
        server: r.server.clone(),
    });
    let configured = net.exit.configured;
    d.save_registry(&inner)?;
    let matches = configured.map(|c| c == r.address);
    Ok(serde_json::json!({
        "network": name, "proxy_group": group,
        "observed": r.address.to_string(), "via": "stun (UDP)", "server": r.server,
        "configured": configured.map(|c| c.to_string()),
        "matches_configured": matches,
        "note": "a STUN reply proves the UDP path out of this namespace; it does not prove a game server will accept the address",
    }))
}
