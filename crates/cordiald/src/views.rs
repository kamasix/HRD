//! Turning daemon state into the views the protocol returns.

use hrd_core::config::Config;
use hrd_core::ids::{AccountName, GroupName};
use hrd_core::model::{Account, AuthStatus, Network, State};
use hrd_core::proto::{AccountView, GroupView, InstanceView, NetworkView};
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

pub fn instance(inner: &Inner, samples: &Samples, l: &Live) -> InstanceView {
    let r = &l.rec;
    let now = now_unix();
    let s = samples.per.get(&r.id);
    InstanceView {
        id: r.id.clone(),
        state: r.state,
        reason: r.reason.clone(),
        group: r
            .group
            .clone()
            .or_else(|| inner.reg.accounts.get(&r.id).and_then(|a| a.group.clone())),
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
        group: a.group.clone(),
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

pub fn group(inner: &Inner, cfg: &Config, g: &GroupName) -> Option<GroupView> {
    let gr = inner.reg.groups.get(g)?;
    let assigned = inner
        .reg
        .accounts
        .values()
        .filter(|a| a.group.as_ref() == Some(g))
        .count() as u32;
    let live = inner
        .live
        .values()
        .filter(|l| l.rec.group.as_ref() == Some(g) && l.rec.state.is_live())
        .count() as u32;
    let ready = gr
        .network
        .as_ref()
        .map(|_| netops::readiness(inner, cfg.network.handshake_max_age_s, g).0);
    Some(GroupView {
        name: gr.name.clone(),
        network: gr.network.clone(),
        capacity: gr.capacity,
        assigned,
        live,
        network_ready: ready,
        note: gr.note.clone(),
    })
}

pub fn network(inner: &Inner, cfg: &Config, n: &Network) -> NetworkView {
    let groups: Vec<GroupName> = inner
        .reg
        .groups
        .values()
        .filter(|g| g.network.as_ref() == Some(&n.name))
        .map(|g| g.name.clone())
        .collect();
    let assigned: u32 = groups
        .iter()
        .map(|g| {
            inner
                .reg
                .accounts
                .values()
                .filter(|a| a.group.as_ref() == Some(g))
                .count() as u32
        })
        .sum();
    let (readiness, reason, hs, rx, tx) = match groups.first() {
        Some(g) => {
            let (r, why) = netops::readiness(inner, cfg.network.handshake_max_age_s, g);
            let st = inner.net_status.get(g).map(|(_, s)| s);
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
            Some("no group uses this network".into()),
            None,
            None,
            None,
        ),
    };
    NetworkView {
        network: n.clone(),
        readiness,
        reason,
        groups,
        assigned_clients: assigned,
        latest_handshake_age_s: hs,
        rx_bytes: rx,
        tx_bytes: tx,
    }
}
