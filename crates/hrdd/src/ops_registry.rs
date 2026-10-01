//! Operations on accounts, groups, networks and configuration.

use std::net::IpAddr;

use serde_json::{json, Value};

use hrd_core::ids::{check_label, AccountName, GroupName, NetworkName, PlaceId, ProxyGroupName};
use hrd_core::model::{
    Account, AuthInfo, AuthStatus, Group, Network, ProxyGroup, Registry, ResourceMode, State,
};
use hrd_core::proto::{
    AccountView, ConfigApplied, ConfigChange, ConfigView, ExportedAccount, GroupView, NetworkView,
    ProxyGroupView,
};
use hrd_core::time::now_unix;
use hrd_core::{fsutil, Error, Result};
use hrd_net::proto::NetdRequest;

use crate::state::{Daemon, Inner, Live};
use crate::views::{members_of_group, members_of_proxy_group};
use crate::{effective, netops, views};

pub fn to<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| Error::Internal(format!("encode: {e}")))
}

fn labels_ok(labels: &[String]) -> Result<()> {
    if labels.len() > 16 {
        return Err(Error::invalid("at most 16 labels per account"));
    }
    labels.iter().try_for_each(|l| check_label(l))
}

fn note_ok(note: &Option<String>) -> Result<()> {
    match note {
        Some(n) if n.chars().count() > 200 || n.chars().any(|c| c.is_control()) => Err(
            Error::invalid("a note is at most 200 characters without control characters"),
        ),
        _ => Ok(()),
    }
}

pub fn note_auth(
    d: &Daemon,
    inner: &mut Inner,
    id: &AccountName,
    status: AuthStatus,
    detail: String,
) {
    if let Some(a) = inner.reg.accounts.get_mut(id) {
        a.auth = AuthInfo {
            status,
            checked_at: Some(now_unix()),
            detail: Some(detail),
        };
        if let Err(e) = d.save_registry(inner) {
            d.note(format!("could not save the registry: {e}"));
        }
    }
}

fn assigned(inner: &Inner, pg: &ProxyGroupName) -> usize {
    members_of_proxy_group(inner, pg).len()
}

/// Change the registry and write it. If the change is refused or the write
/// fails, the registry is put back as it was, so that memory and disk never
/// disagree about what exists.
fn commit<T>(
    d: &Daemon,
    inner: &mut Inner,
    change: impl FnOnce(&mut Registry) -> Result<T>,
) -> Result<T> {
    let before = inner.reg.clone();
    let out = change(&mut inner.reg).and_then(|v| d.save_registry(inner).map(|_| v));
    if out.is_err() {
        inner.reg = before;
    }
    out
}

fn is_busy(inner: &Inner, a: &AccountName) -> bool {
    inner.live.get(a).is_some_and(|l| l.busy())
}

fn internal<T>(what: &str) -> Result<T> {
    Err(Error::Internal(format!(
        "{what} vanished while it was being changed"
    )))
}

/// Make an account's directories and its runtime object. The caller has already
/// put the account in the registry and saved it.
fn bring_up_account(d: &Daemon, inner: &mut Inner, name: &AccountName, now: u64) {
    let rec = hrd_core::model::InstanceRecord::new(name.clone(), now);
    d.save_instance(&rec);
    inner.live.insert(name.clone(), Live::new(rec));
}

fn make_account_dirs(d: &Daemon, name: &AccountName) -> Result<()> {
    let l = &d.layout;
    for p in [
        l.state_dir.join("acct"),
        l.account_home(name),
        l.account_data(name),
        l.account_config(name),
        l.account_cache(name),
        l.account_state(name),
    ] {
        fsutil::ensure_private_dir(&p, 0o700)?;
    }
    Ok(())
}

// ----------------------------------------------------------------- accounts

fn new_account(name: &AccountName, now: u64, proxy_group: Option<ProxyGroupName>) -> Account {
    Account {
        name: name.clone(),
        labels: vec![],
        proxy_group,
        note: None,
        created_at: now,
        auth: AuthInfo {
            status: AuthStatus::None,
            checked_at: Some(now),
            detail: Some("no session stored yet: `hrdctl account login`".into()),
        },
        mode: None,
    }
}

pub fn account_add(
    d: &Daemon,
    name: AccountName,
    labels: Vec<String>,
    note: Option<String>,
    proxy_group: Option<ProxyGroupName>,
) -> Result<Value> {
    labels_ok(&labels)?;
    note_ok(&note)?;
    let mut inner = d.lock();
    if inner.reg.accounts.contains_key(&name) {
        return Err(Error::conflict(format!("account {name} already exists")));
    }
    if let Some(g) = &proxy_group {
        let gr = inner
            .reg
            .proxy_groups
            .get(g)
            .ok_or_else(|| Error::not_found(format!("no proxy group {g}")))?;
        if assigned(&inner, g) as u32 >= gr.capacity {
            return Err(Error::conflict(format!(
                "proxy group {g} is full ({} of {})",
                assigned(&inner, g),
                gr.capacity
            )));
        }
    }
    let now = now_unix();
    make_account_dirs(d, &name)?;
    let mut acct = new_account(&name, now, proxy_group);
    acct.labels = labels;
    acct.note = note.filter(|n| !n.is_empty());
    commit(d, &mut inner, |reg| {
        reg.accounts.insert(name.clone(), acct.clone());
        Ok(())
    })?;
    bring_up_account(d, &mut inner, &name, now);
    to(&views::account(&inner, &acct))
}

pub fn account_list(d: &Daemon) -> Result<Value> {
    let inner = d.lock();
    let v: Vec<AccountView> = inner
        .reg
        .accounts
        .values()
        .map(|a| views::account(&inner, a))
        .collect();
    to(&v)
}

pub fn account_set(
    d: &Daemon,
    name: AccountName,
    labels: Option<Vec<String>>,
    note: Option<String>,
    mode: Option<ResourceMode>,
) -> Result<Value> {
    if let Some(l) = &labels {
        labels_ok(l)?;
    }
    note_ok(&note)?;
    let mut inner = d.lock();
    let a = inner
        .reg
        .accounts
        .get_mut(&name)
        .ok_or_else(|| Error::not_found(format!("no account {name}")))?;
    if let Some(l) = labels {
        a.labels = l;
    }
    if note.is_some() {
        a.note = note.filter(|n| !n.is_empty());
    }
    if mode.is_some() {
        a.mode = mode;
    }
    let a = a.clone();
    d.save_registry(&inner)?;
    to(&views::account(&inner, &a))
}

pub fn account_remove(d: &Daemon, name: AccountName, confirm: String) -> Result<Value> {
    if confirm != name.as_str() {
        return Err(Error::invalid(format!(
            "to remove {name} and everything stored for it, repeat its name as the confirmation"
        )));
    }
    {
        let inner = d.lock();
        if !inner.reg.accounts.contains_key(&name) {
            return Err(Error::not_found(format!("no account {name}")));
        }
        if inner.live.get(&name).is_some_and(|l| l.busy()) {
            return Err(Error::conflict(format!(
                "{name} is running or queued; stop it first"
            )));
        }
    }
    // The stored session goes first. If it cannot be erased the account stays,
    // because a session left behind in the keyring under a path nothing owns
    // any more would be a secret nobody can find.
    let erased = erase_session(d, &name)?;
    let mut inner = d.lock();
    if inner.live.get(&name).is_some_and(|l| l.busy()) {
        return Err(Error::conflict(format!(
            "{name} was started while it was being removed"
        )));
    }
    inner.reg.accounts.remove(&name);
    inner.live.remove(&name);
    d.save_registry(&inner)?;
    let _ = std::fs::remove_file(d.layout.instance_record(&name));
    fsutil::remove_dir_all_if_exists(&d.layout.account_home(&name))?;
    let log = d.layout.instance_log(&name);
    let _ = std::fs::remove_file(&log);
    let _ = std::fs::remove_file(log.with_extension("log.1"));
    Ok(json!({ "removed": name, "stored_items_erased": erased }))
}

fn erase_session(d: &Daemon, name: &AccountName) -> Result<usize> {
    let profile = d.layout.account_profile(name, crate::spawn::PROFILE);
    // Also remove any plaintext copy a mis-set client may have written.
    for f in ["cookies", "identity"] {
        let p = profile.join(f);
        if p.exists() {
            std::fs::remove_file(&p)
                .map_err(|e| Error::io(format!("remove {}", p.display()), e))?;
        }
    }
    if d.secrets.status().state == crate::secrets::SecretsState::Disabled {
        return Ok(0);
    }
    d.secrets.erase(&profile)
}

pub fn account_logout(d: &Daemon, name: AccountName) -> Result<Value> {
    {
        let inner = d.lock();
        if !inner.reg.accounts.contains_key(&name) {
            return Err(Error::not_found(format!("no account {name}")));
        }
        if inner.live.get(&name).is_some_and(|l| l.busy()) {
            return Err(Error::conflict(format!(
                "{name} is running or queued; stop it first"
            )));
        }
    }
    let erased = erase_session(d, &name)?;
    let mut inner = d.lock();
    note_auth(
        d,
        &mut inner,
        &name,
        AuthStatus::None,
        "logged out by the operator; the stored session was erased".into(),
    );
    if let Some(l) = inner.live.get_mut(&name) {
        if l.rec.state == State::AuthRequired {
            l.rec.reason = Some("logged out".into());
        }
    }
    Ok(json!({ "account": name, "stored_items_erased": erased }))
}

pub fn account_export(d: &Daemon) -> Result<Value> {
    let inner = d.lock();
    let v: Vec<ExportedAccount> = inner
        .reg
        .accounts
        .values()
        .map(|a| ExportedAccount {
            name: a.name.clone(),
            labels: a.labels.clone(),
            proxy_group: a.proxy_group.clone(),
            note: a.note.clone(),
            mode: a.mode,
        })
        .collect();
    to(&v)
}

pub fn account_import(d: &Daemon, list: Vec<ExportedAccount>, replace: bool) -> Result<Value> {
    if list.len() > 10_000 {
        return Err(Error::invalid("at most 10000 accounts per import"));
    }
    let (mut added, mut updated, mut skipped) = (0, 0, Vec::new());
    for e in list {
        labels_ok(&e.labels)?;
        note_ok(&e.note)?;
        let exists = d.lock().reg.accounts.contains_key(&e.name);
        if exists {
            if !replace {
                skipped.push(e.name.to_string());
                continue;
            }
            account_set(d, e.name.clone(), Some(e.labels), e.note, e.mode)?;
            updated += 1;
        } else {
            // A proxy group that does not exist here is dropped, not created.
            let proxy_group = e
                .proxy_group
                .filter(|g| d.lock().reg.proxy_groups.contains_key(g));
            account_add(d, e.name.clone(), e.labels, e.note, proxy_group)?;
            if e.mode.is_some() {
                account_set(d, e.name.clone(), None, None, e.mode)?;
            }
            added += 1;
        }
    }
    Ok(json!({ "added": added, "updated": updated, "skipped_existing": skipped }))
}

// ------------------------------------------------------------------- groups

pub fn group_create(
    d: &Daemon,
    name: GroupName,
    place_id: Option<PlaceId>,
    mode: Option<ResourceMode>,
    note: Option<String>,
) -> Result<Value> {
    note_ok(&note)?;
    let mut inner = d.lock();
    commit(d, &mut inner, |reg| {
        if reg.groups.contains_key(&name) {
            return Err(Error::conflict(format!("group {name} already exists")));
        }
        reg.groups.insert(
            name.clone(),
            Group {
                name: name.clone(),
                place_id,
                mode,
                note: note.clone().filter(|n| !n.is_empty()),
                created_at: now_unix(),
            },
        );
        Ok(())
    })?;
    match views::group(&inner, &name) {
        Some(v) => to(&v),
        None => internal("the group"),
    }
}

pub fn group_list(d: &Daemon) -> Result<Value> {
    let inner = d.lock();
    let v: Vec<GroupView> = inner
        .reg
        .groups
        .keys()
        .filter_map(|g| views::group(&inner, g))
        .collect();
    to(&v)
}

pub fn group_set(
    d: &Daemon,
    name: GroupName,
    place_id: Option<PlaceId>,
    clear_place_id: bool,
    mode: Option<ResourceMode>,
    clear_mode: bool,
    note: Option<String>,
) -> Result<Value> {
    note_ok(&note)?;
    if place_id.is_some() && clear_place_id {
        return Err(Error::invalid(
            "give a place id or ask to clear it, not both",
        ));
    }
    if mode.is_some() && clear_mode {
        return Err(Error::invalid("give a mode or ask to clear it, not both"));
    }
    let mut inner = d.lock();
    commit(d, &mut inner, |reg| {
        let g = reg
            .groups
            .get_mut(&name)
            .ok_or_else(|| Error::not_found(format!("no group {name}")))?;
        // A place changed here applies to the next start; a client already
        // running keeps the place it joined.
        if place_id.is_some() {
            g.place_id = place_id;
        } else if clear_place_id {
            g.place_id = None;
        }
        if mode.is_some() {
            g.mode = mode;
        } else if clear_mode {
            g.mode = None;
        }
        if note.is_some() {
            g.note = note.clone().filter(|n| !n.is_empty());
        }
        Ok(())
    })?;
    match views::group(&inner, &name) {
        Some(v) => to(&v),
        None => internal("the group"),
    }
}

pub fn group_remove(d: &Daemon, name: GroupName, cascade: bool) -> Result<Value> {
    let mut inner = d.lock();
    if !inner.reg.groups.contains_key(&name) {
        return Err(Error::not_found(format!("no group {name}")));
    }
    let proxy_groups: Vec<ProxyGroupName> = inner
        .reg
        .proxy_groups
        .values()
        .filter(|p| p.group == name)
        .map(|p| p.name.clone())
        .collect();
    if !proxy_groups.is_empty() && !cascade {
        return Err(Error::conflict(format!(
            "group {name} holds {} proxy group(s); remove them first, or remove the group with --cascade (their accounts stay registered, their proxies stay defined)",
            proxy_groups.len()
        )));
    }
    let members = members_of_group(&inner, &name);
    if members.iter().any(|a| is_busy(&inner, a)) {
        return Err(Error::conflict(format!(
            "accounts of group {name} are running or queued; stop them first"
        )));
    }
    commit(d, &mut inner, |reg| {
        for a in &members {
            if let Some(acc) = reg.accounts.get_mut(a) {
                acc.proxy_group = None;
            }
        }
        for pg in &proxy_groups {
            reg.proxy_groups.remove(pg);
        }
        reg.groups.remove(&name);
        Ok(())
    })?;
    for pg in &proxy_groups {
        inner.net_status.remove(pg);
    }
    Ok(json!({
        "removed": name,
        "proxy_groups_removed": proxy_groups,
        "accounts_unassigned": members.len(),
        "note": if proxy_groups.is_empty() {
            "removed"
        } else {
            "run `hrdctl proxy apply` to tear down the namespaces of its proxy groups"
        },
    }))
}

// ------------------------------------------------------------- proxy groups

fn check_capacity(capacity: u32) -> Result<()> {
    if capacity == 0 || capacity > 10_000 {
        return Err(Error::invalid(
            "capacity must be 1..=10000 (your own organisational limit, not a platform number)",
        ));
    }
    Ok(())
}

pub fn proxy_group_create(
    d: &Daemon,
    name: ProxyGroupName,
    group: GroupName,
    network: Option<NetworkName>,
    capacity: u32,
    note: Option<String>,
) -> Result<Value> {
    note_ok(&note)?;
    check_capacity(capacity)?;
    let mut inner = d.lock();
    commit(d, &mut inner, |reg| {
        if !reg.groups.contains_key(&group) {
            return Err(Error::not_found(format!("no group {group}")));
        }
        // Names are unique across every group: the name is also the namespace.
        if reg.proxy_groups.contains_key(&name) {
            return Err(Error::conflict(format!(
                "a proxy group named {name} already exists (in group {})",
                reg.proxy_groups[&name].group
            )));
        }
        check_network_free(reg, &network, None)?;
        reg.proxy_groups.insert(
            name.clone(),
            ProxyGroup {
                name: name.clone(),
                group: group.clone(),
                network: network.clone(),
                capacity,
                note: note.clone().filter(|n| !n.is_empty()),
                created_at: now_unix(),
            },
        );
        Ok(())
    })?;
    match views::proxy_group(&inner, &d.cfg(), &name) {
        Some(v) => to(&v),
        None => internal("the proxy group"),
    }
}

fn check_network_free(
    reg: &Registry,
    network: &Option<NetworkName>,
    except: Option<&ProxyGroupName>,
) -> Result<()> {
    let Some(n) = network else { return Ok(()) };
    if !reg.networks.contains_key(n) {
        return Err(Error::not_found(format!(
            "no proxy {n}; define it with `hrdctl proxy add` (or in the panel)"
        )));
    }
    if let Some(other) = reg
        .proxy_groups
        .values()
        .find(|g| g.network.as_ref() == Some(n) && Some(&g.name) != except)
    {
        return Err(Error::conflict(format!(
            "proxy {n} already carries proxy group {}; one tunnel belongs to one proxy group (two interfaces with one key fight over the gateway's endpoint)",
            other.name
        )));
    }
    Ok(())
}

pub fn proxy_group_list(d: &Daemon, group: Option<GroupName>) -> Result<Value> {
    let inner = d.lock();
    let cfg = d.cfg();
    let v: Vec<ProxyGroupView> = inner
        .reg
        .proxy_groups
        .values()
        .filter(|p| group.as_ref().is_none_or(|g| &p.group == g))
        .filter_map(|p| views::proxy_group(&inner, &cfg, &p.name))
        .collect();
    to(&v)
}

pub fn proxy_group_set(
    d: &Daemon,
    name: ProxyGroupName,
    group: Option<GroupName>,
    capacity: Option<u32>,
    network: Option<NetworkName>,
    clear_network: bool,
    note: Option<String>,
) -> Result<Value> {
    note_ok(&note)?;
    if network.is_some() && clear_network {
        return Err(Error::invalid("give a proxy or ask to clear it, not both"));
    }
    let mut inner = d.lock();
    if !inner.reg.proxy_groups.contains_key(&name) {
        return Err(Error::not_found(format!("no proxy group {name}")));
    }
    let live = members_of_proxy_group(&inner, &name)
        .iter()
        .any(|a| is_busy(&inner, a));
    if let Some(c) = capacity {
        check_capacity(c)?;
        if (c as usize) < assigned(&inner, &name) {
            return Err(Error::conflict(format!(
                "{} accounts are assigned; move some out before lowering the capacity",
                assigned(&inner, &name)
            )));
        }
    }
    if (network.is_some() || clear_network) && live {
        return Err(Error::conflict("the proxy group has running or queued instances; changing its proxy would move them to another exit"));
    }
    commit(d, &mut inner, |reg| {
        if let Some(g) = &group {
            if !reg.groups.contains_key(g) {
                return Err(Error::not_found(format!("no group {g}")));
            }
        }
        if network.is_some() {
            check_network_free(reg, &network, Some(&name))?;
        }
        let p = reg
            .proxy_groups
            .get_mut(&name)
            .ok_or_else(|| Error::not_found(format!("no proxy group {name}")))?;
        if let Some(g) = &group {
            p.group = g.clone();
        }
        if let Some(c) = capacity {
            p.capacity = c;
        }
        if network.is_some() {
            p.network = network.clone();
        } else if clear_network {
            p.network = None;
        }
        if note.is_some() {
            p.note = note.clone().filter(|n| !n.is_empty());
        }
        Ok(())
    })?;
    match views::proxy_group(&inner, &d.cfg(), &name) {
        Some(v) => to(&v),
        None => internal("the proxy group"),
    }
}

pub fn proxy_group_remove(d: &Daemon, name: ProxyGroupName, unassign: bool) -> Result<Value> {
    let mut inner = d.lock();
    if !inner.reg.proxy_groups.contains_key(&name) {
        return Err(Error::not_found(format!("no proxy group {name}")));
    }
    let members = members_of_proxy_group(&inner, &name);
    if !members.is_empty() {
        if !unassign {
            return Err(Error::conflict(format!(
                "{} accounts are assigned to {name}; move them first, or remove it with --unassign (they stay registered)",
                members.len()
            )));
        }
        if members.iter().any(|a| is_busy(&inner, a)) {
            return Err(Error::conflict(format!(
                "accounts of {name} are running or queued; stop them first"
            )));
        }
    }
    commit(d, &mut inner, |reg| {
        for a in &members {
            if let Some(acc) = reg.accounts.get_mut(a) {
                acc.proxy_group = None;
            }
        }
        reg.proxy_groups.remove(&name);
        Ok(())
    })?;
    inner.net_status.remove(&name);
    Ok(json!({
        "removed": name,
        "accounts_unassigned": members.len(),
        "note": "run `hrdctl proxy apply` to tear down its namespace",
    }))
}

/// Put accounts into a proxy group, or (`proxy_group: None`) take them out of
/// theirs. Everything is checked first and nothing changes unless all of it
/// holds: the capacity, that every account exists, that none is running.
pub fn account_assign(
    d: &Daemon,
    accounts: Vec<AccountName>,
    proxy_group: Option<ProxyGroupName>,
    create_missing: bool,
) -> Result<Value> {
    let mut uniq = accounts;
    uniq.sort();
    uniq.dedup();
    if uniq.is_empty() {
        return Err(Error::invalid("name at least one account"));
    }
    let mut inner = d.lock();
    if let Some(pg) = &proxy_group {
        let cap = inner
            .reg
            .proxy_groups
            .get(pg)
            .ok_or_else(|| Error::not_found(format!("no proxy group {pg}")))?
            .capacity as usize;
        let already: std::collections::BTreeSet<AccountName> =
            members_of_proxy_group(&inner, pg).into_iter().collect();
        let new_members = uniq.iter().filter(|a| !already.contains(*a)).count();
        if already.len() + new_members > cap {
            return Err(Error::conflict(format!("proxy group {pg} holds {} of {cap}; {new_members} more would exceed the capacity. Nothing was changed", already.len())));
        }
    }
    let mut missing = Vec::new();
    for a in &uniq {
        match inner.reg.accounts.get(a) {
            None if proxy_group.is_none() || !create_missing => missing.push(a.to_string()),
            Some(acc) => {
                if acc.proxy_group != proxy_group && is_busy(&inner, a) {
                    return Err(Error::conflict(format!(
                        "{a} is running or queued; stop it before moving it to another proxy group"
                    )));
                }
            }
            None => {}
        }
    }
    if !missing.is_empty() {
        return Err(Error::not_found(format!(
            "unknown accounts: {} (use --create-missing to add them)",
            missing.join(", ")
        )));
    }
    let now = now_unix();
    let created: Vec<AccountName> = uniq
        .iter()
        .filter(|a| !inner.reg.accounts.contains_key(*a))
        .cloned()
        .collect();
    for a in &created {
        make_account_dirs(d, a)?;
    }
    let (moved, unchanged) = commit(d, &mut inner, |reg| {
        let (mut moved, mut unchanged) = (0, 0);
        for a in &uniq {
            let acc = reg
                .accounts
                .entry(a.clone())
                .or_insert_with(|| new_account(a, now, None));
            if acc.proxy_group == proxy_group {
                unchanged += 1;
            } else {
                acc.proxy_group = proxy_group.clone();
                moved += 1;
            }
        }
        Ok((moved, unchanged))
    })?;
    for a in &created {
        bring_up_account(d, &mut inner, a, now);
    }
    Ok(json!({
        "proxy_group": proxy_group,
        "created": created.len(),
        "assigned": moved,
        "unchanged": unchanged,
        "members": proxy_group.as_ref().map(|pg| assigned(&inner, pg)),
    }))
}

// ----------------------------------------------------------------- networks

pub fn network_register(d: &Daemon, n: Network) -> Result<Value> {
    if n.endpoint.is_empty() || n.peer_public_key.is_empty() || n.addresses.is_empty() {
        return Err(Error::invalid(
            "a network needs an endpoint, a peer key and an address",
        ));
    }
    if n.secret_ref != format!("netd:{}", n.name) {
        return Err(Error::invalid(
            "secret_ref must be netd:<name>: keys live in the privileged helper",
        ));
    }
    let mut inner = d.lock();
    let mut n = n;
    if let Some(old) = inner.reg.networks.get(&n.name) {
        // Re-importing the file keeps what the operator said about the exit.
        n.exit = old.exit.clone();
        n.stun_server = n.stun_server.or_else(|| old.stun_server.clone());
        n.max_clients = n.max_clients.or(old.max_clients);
        n.created_at = old.created_at;
    } else {
        n.created_at = now_unix();
    }
    let name = n.name.clone();
    inner.reg.networks.insert(name.clone(), n);
    d.save_registry(&inner)?;
    let cfg = d.cfg();
    let n = inner
        .reg
        .networks
        .get(&name)
        .expect("just inserted")
        .clone();
    to(&views::network(&inner, &cfg, &n))
}

pub fn network_list(d: &Daemon) -> Result<Value> {
    let inner = d.lock();
    let cfg = d.cfg();
    let v: Vec<NetworkView> = inner
        .reg
        .networks
        .values()
        .map(|n| views::network(&inner, &cfg, n))
        .collect();
    to(&v)
}

pub fn network_remove(d: &Daemon, name: NetworkName) -> Result<Value> {
    {
        let inner = d.lock();
        if !inner.reg.networks.contains_key(&name) {
            return Err(Error::not_found(format!("no proxy {name}")));
        }
        if let Some(g) = inner
            .reg
            .proxy_groups
            .values()
            .find(|g| g.network.as_ref() == Some(&name))
        {
            return Err(Error::conflict(format!(
                "proxy group {} uses proxy {name}; detach it or remove the proxy group first",
                g.name
            )));
        }
    }
    // The key goes first; the registry entry only when the helper has let go.
    match d
        .netd
        .call_value(NetdRequest::DeleteNetwork { name: name.clone() })
    {
        Ok(_) => {}
        Err(Error::NotFound(_)) => {}
        Err(e) => return Err(e),
    }
    let mut inner = d.lock();
    inner.reg.networks.remove(&name);
    d.save_registry(&inner)?;
    Ok(json!({ "removed": name }))
}

pub fn network_set(
    d: &Daemon,
    name: NetworkName,
    configured_exit: Option<String>,
    stun: Option<String>,
    max_clients: Option<u32>,
) -> Result<Value> {
    let exit: Option<IpAddr> = match configured_exit.as_deref() {
        None => None,
        Some("") => None,
        Some(s) => Some(
            s.parse()
                .map_err(|_| Error::invalid(format!("{s:?} is not an IP address")))?,
        ),
    };
    if let Some(s) = &stun {
        if !s.is_empty()
            && (s.len() > 255
                || !s.contains(':')
                || s.chars().any(|c| c.is_whitespace() || c.is_control()))
        {
            return Err(Error::invalid("stun_server must look like host:port"));
        }
    }
    let mut inner = d.lock();
    let n = inner
        .reg
        .networks
        .get_mut(&name)
        .ok_or_else(|| Error::not_found(format!("no proxy {name}")))?;
    if configured_exit.is_some() {
        n.exit.configured = exit;
    }
    if let Some(s) = stun {
        n.stun_server = (!s.is_empty()).then_some(s);
    }
    if max_clients.is_some() {
        n.max_clients = max_clients.filter(|m| *m > 0);
    }
    d.save_registry(&inner)?;
    let n = inner.reg.networks.get(&name).expect("present").clone();
    to(&views::network(&inner, &d.cfg(), &n))
}

pub fn network_plan(d: &Daemon) -> Result<Value> {
    to(&netops::plan(d)?)
}

pub fn network_apply(d: &Daemon, prune: bool) -> Result<Value> {
    to(&netops::apply(d, prune)?)
}

// ------------------------------------------------------------------- config

pub fn config_get(d: &Daemon) -> Result<Value> {
    let (cfg, over) = effective::load(&d.layout)?;
    to(&ConfigView {
        problems: cfg.problems(),
        effective: cfg,
        overrides: over,
        file: d.layout.config_file().display().to_string(),
        overrides_file: effective::overrides_file(&d.layout).display().to_string(),
    })
}

pub fn config_set(d: &Daemon, changes: Vec<ConfigChange>) -> Result<Value> {
    if changes.is_empty() || changes.len() > 64 {
        return Err(Error::invalid("give between 1 and 64 changes"));
    }
    // One change at a time: two concurrent calls would each start from the same
    // overrides file and the second would lose the first's changes.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut over = effective::load_overrides(&d.layout)?;
    let mut applied = ConfigApplied {
        live: vec![],
        next_start: vec![],
        restart: vec![],
    };
    for c in &changes {
        effective::apply_change(&mut over, &c.key, c.value.clone())?;
        match effective::effect_of(&c.key) {
            effective::Effect::Live => applied.live.push(c.key.clone()),
            effective::Effect::NextStart => applied.next_start.push(c.key.clone()),
            effective::Effect::Restart => applied.restart.push(c.key.clone()),
        }
    }
    // Validate the whole result before anything is written.
    let base = {
        let (_, _) = (0, 0);
        match fsutil::read_limited_opt(&d.layout.config_file(), 256 * 1024)? {
            None => Value::Object(Default::default()),
            Some(b) => {
                let t: toml::Value = toml::from_str(
                    std::str::from_utf8(&b)
                        .map_err(|_| Error::invalid("configuration is not UTF-8"))?,
                )
                .map_err(|e| Error::invalid(e.to_string()))?;
                serde_json::to_value(t).map_err(|e| Error::Internal(e.to_string()))?
            }
        }
    };
    let cfg = effective::build(base, &over)?;
    // Only the sections that take effect without a restart are swapped in. The
    // others keep the values the daemon started with, so editing the file by
    // hand and then running `config set` does not silently apply those edits.
    let cfg = {
        let mut next = serde_json::to_value(&cfg).map_err(|e| Error::Internal(e.to_string()))?;
        let cur = serde_json::to_value(&*d.cfg()).map_err(|e| Error::Internal(e.to_string()))?;
        if let (Some(n), Some(c)) = (next.as_object_mut(), cur.as_object()) {
            for (k, v) in c {
                if !effective::is_live_section(k) {
                    n.insert(k.clone(), v.clone());
                }
            }
        }
        serde_json::from_value::<hrd_core::config::Config>(next)
            .map_err(|e| Error::Internal(e.to_string()))?
    };
    fsutil::write_json_atomic(&effective::overrides_file(&d.layout), &over, 0o600)?;
    *d.cfg.write().unwrap_or_else(|e| e.into_inner()) = std::sync::Arc::new(cfg);
    to(&applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testing::daemon;
    use hrd_core::model::{ExitInfo, Ipv6Policy, NetBackend};
    use hrd_core::proto::OverviewView;

    fn g(s: &str) -> GroupName {
        GroupName::new(s).unwrap()
    }
    fn pg(s: &str) -> ProxyGroupName {
        ProxyGroupName::new(s).unwrap()
    }
    fn ac(s: &str) -> AccountName {
        AccountName::new(s).unwrap()
    }
    fn place() -> PlaceId {
        PlaceId::new(920587237).unwrap()
    }

    fn overview(d: &Daemon) -> OverviewView {
        let inner = d.lock();
        let samples = d.samples.lock().unwrap();
        views::overview(&inner, &samples, &d.cfg())
    }

    fn define_proxy(d: &Daemon, name: &str) {
        d.lock().reg.networks.insert(
            NetworkName::new(name).unwrap(),
            Network {
                name: NetworkName::new(name).unwrap(),
                backend: NetBackend::WireguardNetns,
                secret_ref: format!("netd:{name}"),
                endpoint: "203.0.113.1:51820".into(),
                peer_public_key: "AAAA".into(),
                addresses: vec!["10.0.0.2/32".into()],
                dns: vec![],
                allowed_ips: vec!["0.0.0.0/0".into()],
                mtu: None,
                persistent_keepalive: None,
                ipv6: Ipv6Policy::Auto,
                exit: ExitInfo::default(),
                stun_server: None,
                max_clients: None,
                created_at: 0,
            },
        );
    }

    /// Mark an account as running, as the supervisor would.
    fn make_busy(d: &Daemon, a: &str) {
        let mut inner = d.lock();
        let l = inner.live.get_mut(&ac(a)).unwrap();
        l.rec.state = State::Connected;
    }

    fn names<T, N: ToString>(v: &[T], f: impl Fn(&T) -> N) -> Vec<String> {
        v.iter().map(|x| f(x).to_string()).collect()
    }

    #[test]
    fn the_hierarchy_is_groups_then_proxy_groups_then_accounts() {
        let d = daemon("hierarchy");
        group_create(&d, g("adopt"), Some(place()), None, None).unwrap();
        group_create(&d, g("pets"), None, Some(ResourceMode::Minimal), None).unwrap();
        proxy_group_create(&d, pg("de-1"), g("adopt"), None, 2, None).unwrap();
        proxy_group_create(&d, pg("nl-1"), g("adopt"), None, 2, None).unwrap();
        account_assign(&d, vec![ac("a1"), ac("a2")], Some(pg("de-1")), true).unwrap();
        account_assign(&d, vec![ac("b1")], Some(pg("nl-1")), true).unwrap();
        account_add(&d, ac("loose"), vec![], None, None).unwrap();

        let o = overview(&d);
        assert_eq!(
            names(&o.groups, |n| n.group.name.clone()),
            ["adopt", "pets"]
        );
        let adopt = &o.groups[0];
        assert_eq!(adopt.group.place_id, Some(place()));
        assert_eq!((adopt.group.proxy_groups, adopt.group.accounts), (2, 3));
        assert_eq!(
            names(&adopt.proxy_groups, |n| n.proxy_group.name.clone()),
            ["de-1", "nl-1"]
        );
        let de = &adopt.proxy_groups[0];
        assert_eq!(names(&de.accounts, |a| a.id.clone()), ["a1", "a2"]);
        assert_eq!((de.proxy_group.assigned, de.proxy_group.capacity), (2, 2));
        // every account says where it is, at both levels
        assert_eq!(de.accounts[0].group, Some(g("adopt")));
        assert_eq!(de.accounts[0].proxy_group, Some(pg("de-1")));
        // an empty group is still listed, with its mode
        let pets = &o.groups[1];
        assert_eq!(pets.group.mode, Some(ResourceMode::Minimal));
        assert!(pets.proxy_groups.is_empty());
        // an account in no proxy group is not lost
        assert_eq!(names(&o.unassigned, |a| a.id.clone()), ["loose"]);
        assert_eq!(o.unassigned[0].group, None);
    }

    #[test]
    fn what_was_changed_is_what_is_on_disk() {
        let d = daemon("persist");
        group_create(&d, g("one"), Some(place()), None, Some("note".into())).unwrap();
        proxy_group_create(&d, pg("p1"), g("one"), None, 5, None).unwrap();
        account_assign(&d, vec![ac("x")], Some(pg("p1")), true).unwrap();
        let on_disk = crate::state::load_registry(&d.layout).unwrap();
        let live = d.lock().reg.clone();
        assert_eq!(
            serde_json::to_value(&on_disk).unwrap(),
            serde_json::to_value(&live).unwrap()
        );
        assert_eq!(on_disk.groups[&g("one")].note.as_deref(), Some("note"));
        assert_eq!(on_disk.accounts[&ac("x")].proxy_group, Some(pg("p1")));
    }

    #[test]
    fn a_write_that_fails_leaves_the_registry_as_it_was() {
        let d = daemon("rollback");
        group_create(&d, g("keep"), None, None, None).unwrap();
        // Something that is not a file where the registry belongs: the atomic
        // rename onto it fails.
        let path = d.layout.registry_file();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(group_create(&d, g("lost"), None, None, None).is_err());
        assert!(account_assign(&d, vec![ac("ghost")], None, true).is_err());
        let inner = d.lock();
        assert_eq!(
            names(&inner.reg.groups.keys().collect::<Vec<_>>(), |k| (*k)
                .clone()),
            ["keep"]
        );
        assert!(inner.reg.accounts.is_empty() && inner.live.is_empty());
    }

    #[test]
    fn names_and_capacity_are_enforced_across_groups() {
        let d = daemon("names");
        group_create(&d, g("a"), None, None, None).unwrap();
        group_create(&d, g("b"), None, None, None).unwrap();
        assert!(group_create(&d, g("a"), None, None, None).is_err());
        proxy_group_create(&d, pg("p"), g("a"), None, 1, None).unwrap();
        // the same proxy group name in another group would be the same namespace
        let e = proxy_group_create(&d, pg("p"), g("b"), None, 1, None).unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        assert!(proxy_group_create(&d, pg("q"), g("nope"), None, 1, None).is_err());
        assert!(proxy_group_create(&d, pg("q"), g("a"), None, 0, None).is_err());
        account_assign(&d, vec![ac("one")], Some(pg("p")), true).unwrap();
        let e = account_assign(&d, vec![ac("two")], Some(pg("p")), true).unwrap_err();
        assert!(e.to_string().contains("exceed the capacity"), "{e}");
        assert!(account_add(&d, ac("three"), vec![], None, Some(pg("p"))).is_err());
        assert!(proxy_group_set(&d, pg("p"), None, Some(0), None, false, None).is_err());
    }

    #[test]
    fn an_assignment_that_is_refused_changes_nothing() {
        let d = daemon("atomic");
        group_create(&d, g("g"), None, None, None).unwrap();
        proxy_group_create(&d, pg("p"), g("g"), None, 3, None).unwrap();
        account_add(&d, ac("known"), vec![], None, None).unwrap();
        // one account does not exist and was not asked to be created
        let e =
            account_assign(&d, vec![ac("known"), ac("unknown")], Some(pg("p")), false).unwrap_err();
        assert!(e.to_string().contains("unknown accounts"), "{e}");
        assert_eq!(d.lock().reg.accounts[&ac("known")].proxy_group, None);
        // creating accounts only makes sense in order to put them somewhere
        assert!(account_assign(&d, vec![ac("fresh")], None, true).is_err());
        assert!(!d.lock().reg.accounts.contains_key(&ac("fresh")));
        // over capacity: nobody moves
        let e = account_assign(
            &d,
            vec![ac("known"), ac("n1"), ac("n2"), ac("n3")],
            Some(pg("p")),
            true,
        )
        .unwrap_err();
        assert!(e.to_string().contains("Nothing was changed"), "{e}");
        let inner = d.lock();
        assert_eq!(inner.reg.accounts[&ac("known")].proxy_group, None);
        assert!(!inner.reg.accounts.contains_key(&ac("n1")));
    }

    #[test]
    fn accounts_can_be_taken_out_of_a_proxy_group_and_moved_between_them() {
        let d = daemon("move");
        group_create(&d, g("g"), None, None, None).unwrap();
        proxy_group_create(&d, pg("p1"), g("g"), None, 5, None).unwrap();
        proxy_group_create(&d, pg("p2"), g("g"), None, 5, None).unwrap();
        account_assign(&d, vec![ac("a"), ac("b")], Some(pg("p1")), true).unwrap();
        let r = account_assign(&d, vec![ac("a")], Some(pg("p2")), false).unwrap();
        assert_eq!(
            (r["assigned"].as_u64(), r["unchanged"].as_u64()),
            (Some(1), Some(0))
        );
        let r = account_assign(&d, vec![ac("b")], None, false).unwrap();
        assert_eq!(r["assigned"], 1);
        let o = overview(&d);
        assert_eq!(o.groups[0].proxy_groups[1].accounts[0].id, ac("a"));
        assert_eq!(o.unassigned[0].id, ac("b"));
        // saying it again is not an error and not a change
        let r = account_assign(&d, vec![ac("a")], Some(pg("p2")), false).unwrap();
        assert_eq!(
            (r["assigned"].as_u64(), r["unchanged"].as_u64()),
            (Some(0), Some(1))
        );
    }

    #[test]
    fn a_running_account_is_neither_moved_nor_unassigned_nor_removed_with_its_proxy_group() {
        let d = daemon("busy");
        group_create(&d, g("g"), None, None, None).unwrap();
        proxy_group_create(&d, pg("p1"), g("g"), None, 5, None).unwrap();
        proxy_group_create(&d, pg("p2"), g("g"), None, 5, None).unwrap();
        account_assign(&d, vec![ac("a")], Some(pg("p1")), true).unwrap();
        make_busy(&d, "a");
        for r in [
            account_assign(&d, vec![ac("a")], Some(pg("p2")), false),
            account_assign(&d, vec![ac("a")], None, false),
            proxy_group_remove(&d, pg("p1"), true),
            group_remove(&d, g("g"), true),
        ] {
            let e = r.unwrap_err();
            assert!(e.to_string().contains("running or queued"), "{e}");
        }
        // nothing moved
        assert_eq!(d.lock().reg.accounts[&ac("a")].proxy_group, Some(pg("p1")));
        // its proxy cannot be swapped under it either
        define_proxy(&d, "n1");
        let e = proxy_group_set(
            &d,
            pg("p1"),
            None,
            None,
            Some(NetworkName::new("n1").unwrap()),
            false,
            None,
        )
        .unwrap_err();
        assert!(e.to_string().contains("running or queued"), "{e}");
    }

    #[test]
    fn removing_a_group_or_a_proxy_group_keeps_the_accounts_and_the_proxies() {
        let d = daemon("remove");
        define_proxy(&d, "de-1");
        group_create(&d, g("g"), None, None, None).unwrap();
        proxy_group_create(
            &d,
            pg("de-1"),
            g("g"),
            Some(NetworkName::new("de-1").unwrap()),
            5,
            None,
        )
        .unwrap();
        account_assign(&d, vec![ac("a"), ac("b")], Some(pg("de-1")), true).unwrap();

        // not without saying so
        assert!(group_remove(&d, g("g"), false)
            .unwrap_err()
            .to_string()
            .contains("--cascade"));
        assert!(proxy_group_remove(&d, pg("de-1"), false)
            .unwrap_err()
            .to_string()
            .contains("--unassign"));
        // a proxy cannot be deleted while a proxy group uses it
        assert!(network_remove_check(&d, "de-1"));

        let r = group_remove(&d, g("g"), true).unwrap();
        assert_eq!(r["accounts_unassigned"], 2);
        let o = overview(&d);
        assert!(o.groups.is_empty());
        assert_eq!(names(&o.unassigned, |a| a.id.clone()), ["a", "b"]);
        // the proxy is still defined, and now free to be used again
        assert_eq!(
            names(&o.free_networks, |n| n.network.name.clone()),
            ["de-1"]
        );
    }

    /// `network_remove` refuses while a proxy group uses the proxy. (The helper
    /// is not running here, so it is only asked once that check has passed.)
    fn network_remove_check(d: &Daemon, name: &str) -> bool {
        network_remove(d, NetworkName::new(name).unwrap())
            .err()
            .is_some_and(|e| e.to_string().contains("uses proxy"))
    }

    #[test]
    fn a_proxy_belongs_to_one_proxy_group_and_a_proxy_group_can_change_group() {
        let d = daemon("proxies");
        define_proxy(&d, "n1");
        let n1 = NetworkName::new("n1").unwrap();
        group_create(&d, g("a"), None, None, None).unwrap();
        group_create(&d, g("b"), None, None, None).unwrap();
        proxy_group_create(&d, pg("x"), g("a"), Some(n1.clone()), 2, None).unwrap();
        let e = proxy_group_create(&d, pg("y"), g("a"), Some(n1.clone()), 2, None).unwrap_err();
        assert!(e.to_string().contains("already carries"), "{e}");
        assert!(proxy_group_create(
            &d,
            pg("y"),
            g("a"),
            Some(NetworkName::new("ghost").unwrap()),
            2,
            None
        )
        .is_err());
        // moving it to another group keeps its proxy and its name (its namespace)
        let v = proxy_group_set(&d, pg("x"), Some(g("b")), None, None, false, None).unwrap();
        assert_eq!(v["group"], "b");
        assert_eq!(v["network"], "n1");
        assert!(proxy_group_set(&d, pg("x"), Some(g("nope")), None, None, false, None).is_err());
        // detaching the proxy frees it
        proxy_group_set(&d, pg("x"), None, None, None, true, None).unwrap();
        proxy_group_create(&d, pg("y"), g("a"), Some(n1), 2, None).unwrap();
    }

    #[test]
    fn a_groups_settings_can_be_set_and_cleared() {
        let d = daemon("settings");
        group_create(&d, g("s"), None, None, None).unwrap();
        let v = group_set(
            &d,
            g("s"),
            Some(place()),
            false,
            Some(ResourceMode::Aggressive),
            false,
            Some("hello".into()),
        )
        .unwrap();
        assert_eq!(
            (
                v["place_id"].as_u64(),
                v["mode"].as_str(),
                v["note"].as_str()
            ),
            (Some(920587237), Some("aggressive"), Some("hello"))
        );
        let v = group_set(&d, g("s"), None, true, None, true, Some(String::new())).unwrap();
        assert!(v["place_id"].is_null() && v["mode"].is_null() && v["note"].is_null());
        assert!(group_set(&d, g("s"), Some(place()), true, None, false, None).is_err());
        assert!(group_set(&d, g("nope"), None, false, None, false, None).is_err());
    }

    #[test]
    fn listing_proxy_groups_can_be_narrowed_to_one_group() {
        let d = daemon("list");
        group_create(&d, g("a"), None, None, None).unwrap();
        group_create(&d, g("b"), None, None, None).unwrap();
        proxy_group_create(&d, pg("pa"), g("a"), None, 1, None).unwrap();
        proxy_group_create(&d, pg("pb"), g("b"), None, 1, None).unwrap();
        assert_eq!(
            proxy_group_list(&d, None)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let only_a = proxy_group_list(&d, Some(g("a"))).unwrap();
        assert_eq!(only_a[0]["name"], "pa");
        assert_eq!(only_a.as_array().unwrap().len(), 1);
    }

    #[test]
    fn exported_accounts_keep_their_proxy_group_and_an_import_into_a_registry_without_it_drops_it()
    {
        let d = daemon("export");
        group_create(&d, g("g"), None, None, None).unwrap();
        proxy_group_create(&d, pg("p"), g("g"), None, 5, None).unwrap();
        account_assign(&d, vec![ac("a")], Some(pg("p")), true).unwrap();
        let exported = account_export(&d).unwrap();
        assert_eq!(exported[0]["proxy_group"], "p");
        // an export made before the split said `group`; it reads the same
        let old: Vec<ExportedAccount> =
            serde_json::from_str(r#"[{"name":"z","group":"p"}]"#).unwrap();
        assert_eq!(old[0].proxy_group, Some(pg("p")));

        let other = daemon("export-other");
        let list: Vec<ExportedAccount> = serde_json::from_value(exported).unwrap();
        account_import(&other, list, false).unwrap();
        assert_eq!(other.lock().reg.accounts[&ac("a")].proxy_group, None);
    }
}
