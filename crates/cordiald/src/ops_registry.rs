//! Operations on accounts, groups, networks and configuration.

use std::net::IpAddr;

use serde_json::{json, Value};

use hrd_core::ids::{check_label, AccountName, GroupName, NetworkName};
use hrd_core::model::{Account, AuthInfo, AuthStatus, Group, Network, ResourceMode, State};
use hrd_core::proto::{
    AccountView, ConfigApplied, ConfigChange, ConfigView, ExportedAccount, GroupView, NetworkView,
};
use hrd_core::time::now_unix;
use hrd_core::{fsutil, Error, Result};
use hrd_net::proto::NetdRequest;

use crate::state::{Daemon, Inner, Live};
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

fn assigned(inner: &Inner, g: &GroupName) -> usize {
    inner
        .reg
        .accounts
        .values()
        .filter(|a| a.group.as_ref() == Some(g))
        .count()
}

// ----------------------------------------------------------------- accounts

pub fn account_add(
    d: &Daemon,
    name: AccountName,
    labels: Vec<String>,
    note: Option<String>,
    group: Option<GroupName>,
) -> Result<Value> {
    labels_ok(&labels)?;
    note_ok(&note)?;
    let mut inner = d.lock();
    if inner.reg.accounts.contains_key(&name) {
        return Err(Error::conflict(format!("account {name} already exists")));
    }
    if let Some(g) = &group {
        let gr = inner
            .reg
            .groups
            .get(g)
            .ok_or_else(|| Error::not_found(format!("no group {g}")))?;
        if assigned(&inner, g) as u32 >= gr.capacity {
            return Err(Error::conflict(format!(
                "group {g} is full ({} of {})",
                assigned(&inner, g),
                gr.capacity
            )));
        }
    }
    let now = now_unix();
    let acct = Account {
        name: name.clone(),
        labels,
        group,
        note,
        created_at: now,
        auth: AuthInfo {
            status: AuthStatus::None,
            checked_at: Some(now),
            detail: Some("no session stored yet: `cordialctl account login`".into()),
        },
        mode: None,
    };
    let l = &d.layout;
    for p in [
        l.state_dir.join("acct"),
        l.account_home(&name),
        l.account_data(&name),
        l.account_config(&name),
        l.account_cache(&name),
        l.account_state(&name),
    ] {
        fsutil::ensure_private_dir(&p, 0o700)?;
    }
    // Memory and registry change together: a failed write leaves neither.
    let rec = hrd_core::model::InstanceRecord::new(name.clone(), now);
    inner.reg.accounts.insert(name.clone(), acct.clone());
    if let Err(e) = d.save_registry(&inner) {
        inner.reg.accounts.remove(&name);
        return Err(e);
    }
    d.save_instance(&rec);
    inner.live.insert(name.clone(), Live::new(rec));
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
            group: a.group.clone(),
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
            // A group that does not exist here is dropped, not created.
            let group = e.group.filter(|g| d.lock().reg.groups.contains_key(g));
            account_add(d, e.name.clone(), e.labels, e.note, group)?;
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
    network: Option<NetworkName>,
    capacity: u32,
    note: Option<String>,
) -> Result<Value> {
    note_ok(&note)?;
    if capacity == 0 || capacity > 10_000 {
        return Err(Error::invalid(
            "capacity must be 1..=10000 (your own organisational limit, not a platform number)",
        ));
    }
    let mut inner = d.lock();
    if inner.reg.groups.contains_key(&name) {
        return Err(Error::conflict(format!("group {name} already exists")));
    }
    check_network_free(&inner, &network, None)?;
    inner.reg.groups.insert(
        name.clone(),
        Group {
            name: name.clone(),
            network,
            capacity,
            note,
            created_at: now_unix(),
        },
    );
    d.save_registry(&inner)?;
    to(&views::group(&inner, &d.cfg(), &name))
}

fn check_network_free(
    inner: &Inner,
    network: &Option<NetworkName>,
    except: Option<&GroupName>,
) -> Result<()> {
    let Some(n) = network else { return Ok(()) };
    if !inner.reg.networks.contains_key(n) {
        return Err(Error::not_found(format!(
            "no network {n}; import it with `cordialctl network add`"
        )));
    }
    if let Some(other) = inner
        .reg
        .groups
        .values()
        .find(|g| g.network.as_ref() == Some(n) && Some(&g.name) != except)
    {
        return Err(Error::conflict(format!(
            "network {n} already carries group {}; one tunnel belongs to one group (two interfaces with one key fight over the gateway's endpoint)",
            other.name
        )));
    }
    Ok(())
}

pub fn group_list(d: &Daemon) -> Result<Value> {
    let inner = d.lock();
    let cfg = d.cfg();
    let v: Vec<GroupView> = inner
        .reg
        .groups
        .keys()
        .filter_map(|g| views::group(&inner, &cfg, g))
        .collect();
    to(&v)
}

pub fn group_set(
    d: &Daemon,
    name: GroupName,
    capacity: Option<u32>,
    network: Option<NetworkName>,
    clear_network: bool,
    note: Option<String>,
) -> Result<Value> {
    note_ok(&note)?;
    let mut inner = d.lock();
    if !inner.reg.groups.contains_key(&name) {
        return Err(Error::not_found(format!("no group {name}")));
    }
    let live = inner
        .live
        .values()
        .any(|l| l.rec.group.as_ref() == Some(&name) && l.busy());
    if let Some(c) = capacity {
        if c == 0 || c > 10_000 {
            return Err(Error::invalid("capacity must be 1..=10000"));
        }
        if (c as usize) < assigned(&inner, &name) {
            return Err(Error::conflict(format!(
                "{} accounts are assigned; move some out before lowering the capacity",
                assigned(&inner, &name)
            )));
        }
    }
    if network.is_some() || clear_network {
        if live {
            return Err(Error::conflict("the group has running or queued instances; changing its network would move them to another exit"));
        }
        if network.is_some() {
            check_network_free(&inner, &network, Some(&name))?;
        }
    }
    let g = inner.reg.groups.get_mut(&name).expect("checked");
    if let Some(c) = capacity {
        g.capacity = c;
    }
    if network.is_some() {
        g.network = network;
    } else if clear_network {
        g.network = None;
    }
    if note.is_some() {
        g.note = note.filter(|n| !n.is_empty());
    }
    d.save_registry(&inner)?;
    to(&views::group(&inner, &d.cfg(), &name))
}

pub fn group_assign(
    d: &Daemon,
    group: GroupName,
    accounts: Vec<AccountName>,
    create_missing: bool,
) -> Result<Value> {
    let mut inner = d.lock();
    let cap = inner
        .reg
        .groups
        .get(&group)
        .ok_or_else(|| Error::not_found(format!("no group {group}")))?
        .capacity as usize;
    let mut uniq = accounts.clone();
    uniq.sort();
    uniq.dedup();
    let already = inner
        .reg
        .accounts
        .values()
        .filter(|a| a.group.as_ref() == Some(&group))
        .map(|a| a.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let new_members = uniq.iter().filter(|a| !already.contains(*a)).count();
    if already.len() + new_members > cap {
        return Err(Error::conflict(format!("group {group} holds {} of {cap}; {new_members} more would exceed the capacity. Nothing was changed", already.len())));
    }
    let mut missing = Vec::new();
    for a in &uniq {
        match inner.reg.accounts.get(a) {
            None if !create_missing => missing.push(a.to_string()),
            Some(acc) => {
                if acc.group.as_ref() != Some(&group) && inner.live.get(a).is_some_and(|l| l.busy())
                {
                    return Err(Error::conflict(format!(
                        "{a} is running or queued; stop it before moving it to another group"
                    )));
                }
            }
            _ => {}
        }
    }
    if !missing.is_empty() {
        return Err(Error::not_found(format!(
            "unknown accounts: {} (use --create-missing to add them)",
            missing.join(", ")
        )));
    }
    let (mut created, mut moved, mut unchanged) = (0, 0, 0);
    let now = now_unix();
    for a in uniq {
        if !inner.reg.accounts.contains_key(&a) {
            let l = &d.layout;
            for p in [
                l.state_dir.join("acct"),
                l.account_home(&a),
                l.account_data(&a),
                l.account_config(&a),
                l.account_cache(&a),
                l.account_state(&a),
            ] {
                fsutil::ensure_private_dir(&p, 0o700)?;
            }
            inner.reg.accounts.insert(
                a.clone(),
                Account {
                    name: a.clone(),
                    labels: vec![],
                    group: None,
                    note: None,
                    created_at: now,
                    auth: AuthInfo {
                        status: AuthStatus::None,
                        checked_at: Some(now),
                        detail: Some("no session stored yet".into()),
                    },
                    mode: None,
                },
            );
            let rec = hrd_core::model::InstanceRecord::new(a.clone(), now);
            d.save_instance(&rec);
            inner.live.insert(a.clone(), Live::new(rec));
            created += 1;
        }
        let acc = inner.reg.accounts.get_mut(&a).expect("present");
        if acc.group.as_ref() == Some(&group) {
            unchanged += 1;
        } else {
            acc.group = Some(group.clone());
            moved += 1;
        }
    }
    d.save_registry(&inner)?;
    Ok(
        json!({ "group": group, "created": created, "assigned": moved, "unchanged": unchanged, "members": assigned(&inner, &group) }),
    )
}

pub fn group_remove(d: &Daemon, name: GroupName) -> Result<Value> {
    let mut inner = d.lock();
    if !inner.reg.groups.contains_key(&name) {
        return Err(Error::not_found(format!("no group {name}")));
    }
    if assigned(&inner, &name) > 0 {
        return Err(Error::conflict(format!(
            "{} accounts are assigned to {name}; assign them elsewhere first",
            assigned(&inner, &name)
        )));
    }
    inner.reg.groups.remove(&name);
    inner.net_status.remove(&name);
    d.save_registry(&inner)?;
    Ok(
        json!({ "removed": name, "note": "run `cordialctl network apply` to tear down its namespace" }),
    )
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
            return Err(Error::not_found(format!("no network {name}")));
        }
        if let Some(g) = inner
            .reg
            .groups
            .values()
            .find(|g| g.network.as_ref() == Some(&name))
        {
            return Err(Error::conflict(format!(
                "group {} uses network {name}; detach or remove the group first",
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
        .ok_or_else(|| Error::not_found(format!("no network {name}")))?;
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
    fsutil::write_json_atomic(&effective::overrides_file(&d.layout), &over, 0o600)?;
    *d.cfg.write().unwrap_or_else(|e| e.into_inner()) = std::sync::Arc::new(cfg);
    to(&applied)
}
