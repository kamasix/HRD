//! Turning daemon state into the views the protocol returns.

use hrd_core::config::Config;
use hrd_core::ids::{AccountName, GroupName, ProxyGroupName};
use hrd_core::model::{Account, AuthStatus, Network, State};
use hrd_core::proto::{
    AccountView, GroupNode, GroupView, InstanceView, NetworkView, OverviewView, ProxyGroupNode,
    ProxyGroupView,
};
use hrd_core::time::now_unix;

use crate::netops;
use crate::sampler::Samples;
use crate::state::{Inner, Live};

pub fn queue_position(inner: &Inner, id: &AccountName) -> Option<u32> {
    inner
        .queue
        .iter()
        .position(|q| q == id)
        .map(|p| p as u32 + 1)
}

pub fn auth_of(inner: &Inner, id: &AccountName) -> AuthStatus {
    inner
        .reg
        .accounts
        .get(id)
        .map(|a| a.auth.status)
        .unwrap_or_default()
}

/// The proxy group an account is in *now*. A run's record keeps the one it used,
/// but an account that was moved or unassigned since belongs to where it is.
fn proxy_group_of(inner: &Inner, l: &Live) -> Option<ProxyGroupName> {
    match inner.reg.accounts.get(&l.rec.id) {
        Some(a) => a.proxy_group.clone(),
        None => l.rec.proxy_group.clone(),
    }
}

fn group_of(inner: &Inner, pg: Option<&ProxyGroupName>) -> Option<GroupName> {
    inner.reg.proxy_groups.get(pg?).map(|p| p.group.clone())
}

pub fn instance(inner: &Inner, samples: &Samples, l: &Live) -> InstanceView {
    let r = &l.rec;
    let now = now_unix();
    let s = samples.per.get(&r.id);
    let proxy_group = proxy_group_of(inner, l);
    InstanceView {
        id: r.id.clone(),
        state: r.state,
        reason: r.reason.clone(),
        group: group_of(inner, proxy_group.as_ref()),
        proxy_group,
        place_id: r.place_id,
        run: r.run,
        runtime: r.runtime.clone(),
        mode: r.mode,
        auth: auth_of(inner, &r.id),
        state_since: r.state_since,
        started_at: r.started_at,
        uptime_s: r
            .started_at
            .filter(|_| r.state.expects_processes())
            .map(|t| now.saturating_sub(t)),
        queue_position: queue_position(inner, &r.id),
        pid: r.process.as_ref().map(|p| p.pid),
        mem: s.map(|s| s.mem.clone()),
        cpu_percent: s.and_then(|s| s.cpu_percent),
        processes: s.map(|s| s.processes),
        threads: s.map(|s| s.threads),
        kind: r.kind,
        labels: inner
            .reg
            .accounts
            .get(&r.id)
            .map(|a| a.labels.clone())
            .unwrap_or_default(),
    }
}

pub fn account(inner: &Inner, a: &Account) -> AccountView {
    AccountView {
        name: a.name.clone(),
        labels: a.labels.clone(),
        group: group_of(inner, a.proxy_group.as_ref()),
        proxy_group: a.proxy_group.clone(),
        note: a.note.clone(),
        auth: a.auth.status,
        auth_detail: a.auth.detail.clone(),
        auth_checked_at: a.auth.checked_at,
        state: inner
            .live
            .get(&a.name)
            .map(|l| l.rec.state)
            .unwrap_or(State::Configured),
        mode: a.mode,
        created_at: a.created_at,
    }
}

fn live_count(inner: &Inner, ids: impl Iterator<Item = AccountName>) -> u32 {
    ids.filter(|id| inner.live.get(id).is_some_and(|l| l.rec.state.is_live()))
        .count() as u32
}

/// Accounts in any proxy group of `g`, in name order.
pub fn members_of_group(inner: &Inner, g: &GroupName) -> Vec<AccountName> {
    inner
        .reg
        .accounts
        .values()
        .filter(|a| {
            a.proxy_group
                .as_ref()
                .and_then(|pg| inner.reg.proxy_groups.get(pg))
                .is_some_and(|p| &p.group == g)
        })
        .map(|a| a.name.clone())
        .collect()
}

/// Accounts in one proxy group, in name order.
pub fn members_of_proxy_group(inner: &Inner, pg: &ProxyGroupName) -> Vec<AccountName> {
    inner
        .reg
        .accounts
        .values()
        .filter(|a| a.proxy_group.as_ref() == Some(pg))
        .map(|a| a.name.clone())
        .collect()
}

pub fn group(inner: &Inner, g: &GroupName) -> Option<GroupView> {
    let gr = inner.reg.groups.get(g)?;
    let members = members_of_group(inner, g);
    Some(GroupView {
        name: gr.name.clone(),
        place_id: gr.place_id,
        mode: gr.mode,
        note: gr.note.clone(),
        proxy_groups: inner
            .reg
            .proxy_groups
            .values()
            .filter(|p| &p.group == g)
            .count() as u32,
        accounts: members.len() as u32,
        live: live_count(inner, members.into_iter()),
        created_at: gr.created_at,
    })
}

pub fn proxy_group(inner: &Inner, cfg: &Config, pg: &ProxyGroupName) -> Option<ProxyGroupView> {
    let p = inner.reg.proxy_groups.get(pg)?;
    let members = members_of_proxy_group(inner, pg);
    let ready = p
        .network
        .as_ref()
        .map(|_| netops::readiness(inner, cfg.network.handshake_max_age_s, pg));
    Some(ProxyGroupView {
        name: p.name.clone(),
        group: p.group.clone(),
        network: p.network.clone(),
        capacity: p.capacity,
        assigned: members.len() as u32,
        live: live_count(inner, members.into_iter()),
        network_ready: ready.as_ref().map(|r| r.0),
        network_reason: ready.and_then(|r| r.1),
        note: p.note.clone(),
    })
}

pub fn network(inner: &Inner, cfg: &Config, n: &Network) -> NetworkView {
    let proxy_groups: Vec<ProxyGroupName> = inner
        .reg
        .proxy_groups
        .values()
        .filter(|p| p.network.as_ref() == Some(&n.name))
        .map(|p| p.name.clone())
        .collect();
    let assigned: u32 = proxy_groups
        .iter()
        .map(|pg| members_of_proxy_group(inner, pg).len() as u32)
        .sum();
    let (readiness, reason, hs, rx, tx) = match proxy_groups.first() {
        Some(pg) => {
            let (r, why) = netops::readiness(inner, cfg.network.handshake_max_age_s, pg);
            let st = inner.net_status.get(pg).map(|(_, s)| s);
            (
                r,
                why,
                st.and_then(|s| s.latest_handshake)
                    .map(|t| now_unix().saturating_sub(t)),
                st.and_then(|s| s.rx_bytes),
                st.and_then(|s| s.tx_bytes),
            )
        }
        None => (
            hrd_core::model::Readiness::NotApplied,
            Some("no proxy group uses this proxy".into()),
            None,
            None,
            None,
        ),
    };
    NetworkView {
        network: n.clone(),
        readiness,
        reason,
        proxy_groups,
        assigned_clients: assigned,
        latest_handshake_age_s: hs,
        rx_bytes: rx,
        tx_bytes: tx,
    }
}

/// The whole hierarchy under one lock: every account appears exactly once,
/// either in its proxy group or in `unassigned`.
pub fn overview(inner: &Inner, samples: &Samples, cfg: &Config) -> OverviewView {
    let instance_of = |id: &AccountName| inner.live.get(id).map(|l| instance(inner, samples, l));
    let groups = inner
        .reg
        .groups
        .keys()
        .filter_map(|g| {
            let proxy_groups = inner
                .reg
                .proxy_groups
                .values()
                .filter(|p| &p.group == g)
                .filter_map(|p| {
                    Some(ProxyGroupNode {
                        proxy_group: proxy_group(inner, cfg, &p.name)?,
                        network: p
                            .network
                            .as_ref()
                            .and_then(|n| inner.reg.networks.get(n))
                            .map(|n| network(inner, cfg, n)),
                        accounts: members_of_proxy_group(inner, &p.name)
                            .iter()
                            .filter_map(instance_of)
                            .collect(),
                    })
                })
                .collect();
            Some(GroupNode {
                group: group(inner, g)?,
                proxy_groups,
            })
        })
        .collect();
    let unassigned = inner
        .reg
        .accounts
        .values()
        .filter(|a| a.proxy_group.is_none())
        .filter_map(|a| instance_of(&a.name))
        .collect();
    let free_networks = inner
        .reg
        .networks
        .values()
        .filter(|n| {
            !inner
                .reg
                .proxy_groups
                .values()
                .any(|p| p.network.as_ref() == Some(&n.name))
        })
        .map(|n| network(inner, cfg, n))
        .collect();
    OverviewView {
        groups,
        unassigned,
        free_networks,
    }
}
