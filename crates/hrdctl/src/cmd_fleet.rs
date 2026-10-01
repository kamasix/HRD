//! Groups, instances, status, stats, logs, the queue.

use serde_json::Value;

use hrd_core::ids::AccountName;
use hrd_core::model::State;
use hrd_core::proto::{
    ClassStats, Event, Filter, GroupView, InstanceDetail, InstanceView, OverviewView,
    ProxyGroupView, Request, StatsView,
};
use hrd_core::time::{human_duration, now_unix, rfc3339};
use hrd_core::{fsutil, Error, Result};

use crate::util::{age, mib, mib_long, opt, pct, table, NM};
use crate::{Ctx, GroupCmd, InstanceCmd, ProxyGroupCmd, QueueCmd, StatusArgs};

pub fn group(ctx: &Ctx, c: GroupCmd) -> Result<()> {
    let mut cl = ctx.client()?;
    match c {
        GroupCmd::Create {
            name,
            place_id,
            mode,
            note,
        } => {
            let v: GroupView = cl.call(Request::GroupCreate {
                name,
                place_id,
                mode,
                note,
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!(
                    "group {} created (place {}). Next: hrdctl proxy-group create NAME --group {} --capacity N",
                    v.name,
                    opt(&v.place_id),
                    v.name
                );
            }
        }
        GroupCmd::List => {
            let v: Vec<GroupView> = cl.call(Request::GroupList)?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                let rows: Vec<Vec<String>> = v
                    .iter()
                    .map(|g| {
                        vec![
                            g.name.to_string(),
                            opt(&g.place_id),
                            g.mode
                                .map(|m| m.as_str().to_string())
                                .unwrap_or_else(|| "-".into()),
                            g.proxy_groups.to_string(),
                            g.accounts.to_string(),
                            g.live.to_string(),
                            g.note.clone().unwrap_or_default(),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    table(
                        &[
                            "GROUP",
                            "PLACE",
                            "MODE",
                            "PROXY GROUPS",
                            "ACCOUNTS",
                            "LIVE",
                            "NOTE"
                        ],
                        &rows,
                        &[3, 4, 5]
                    )
                );
            }
        }
        GroupCmd::Set {
            name,
            place_id,
            clear_place_id,
            mode,
            clear_mode,
            note,
        } => {
            let v: GroupView = cl.call(Request::GroupSet {
                name,
                place_id,
                clear_place_id,
                mode,
                clear_mode,
                note,
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!(
                    "group {}: place {}, mode {}",
                    v.name,
                    opt(&v.place_id),
                    v.mode.map(|m| m.as_str()).unwrap_or("-")
                );
            }
        }
        GroupCmd::Remove { name, cascade } => {
            let v: Value = cl.call(Request::GroupRemove { name, cascade })?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                println!("{}", v["note"].as_str().unwrap_or("removed"));
            }
        }
        GroupCmd::Start {
            name,
            place_id,
            private_server_code,
            mode,
        } => {
            let v: Value = cl.call(Request::GroupStart {
                group: name,
                place_id,
                private_server_code,
                mode,
            })?;
            print_start(ctx, &v, "group", "group");
        }
        GroupCmd::Stop { name, force } => {
            let v: Value = cl.call(Request::GroupStop { name, force })?;
            print_stop(ctx, &v);
        }
    }
    Ok(())
}

/// What a group or proxy-group start reports: how many were queued, and each
/// account that was left out with the reason.
fn print_start(ctx: &Ctx, v: &Value, key: &str, what: &str) {
    if ctx.out.json {
        ctx.out.value(v);
        return;
    }
    let q = v["queued"].as_array().map(|a| a.len()).unwrap_or(0);
    println!(
        "{q} queued in {what} {}; starts are paced by the scheduler (see `hrdctl status`)",
        v[key].as_str().unwrap_or("")
    );
    for s in v["skipped"].as_array().into_iter().flatten() {
        println!(
            "  skipped {}: {}",
            s["account"].as_str().unwrap_or("?"),
            s["reason"].as_str().unwrap_or("?")
        );
    }
}

fn print_stop(ctx: &Ctx, v: &Value) {
    if ctx.out.json {
        ctx.out.value(v);
    } else {
        println!(
            "stopping {} instance(s){}",
            v["stopping"],
            if v["force"].as_bool() == Some(true) {
                " (killing)"
            } else {
                ""
            }
        );
    }
}

pub fn proxy_group(ctx: &Ctx, c: ProxyGroupCmd) -> Result<()> {
    let mut cl = ctx.client()?;
    match c {
        ProxyGroupCmd::Create {
            name,
            group,
            proxy,
            capacity,
            note,
        } => {
            let v: ProxyGroupView = cl.call(Request::ProxyGroupCreate {
                name,
                group,
                network: proxy,
                capacity,
                note,
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!(
                    "proxy group {} created in group {} (capacity {}, proxy {})",
                    v.name,
                    v.group,
                    v.capacity,
                    opt(&v.network)
                );
            }
        }
        ProxyGroupCmd::Assign {
            name,
            accounts,
            create_missing,
        } => {
            let text = String::from_utf8(fsutil::read_limited(&accounts, 4 << 20)?)
                .map_err(|_| Error::invalid("the account list is not UTF-8"))?;
            let mut names = Vec::new();
            for (i, l) in text.lines().enumerate() {
                let l = l.split('#').next().unwrap_or("").trim();
                if l.is_empty() {
                    continue;
                }
                names.push(l.parse::<AccountName>().map_err(|e| {
                    Error::invalid(format!("{} line {}: {e}", accounts.display(), i + 1))
                })?);
            }
            let v: Value = cl.call(Request::AccountAssign {
                accounts: names,
                proxy_group: Some(name),
                create_missing,
            })?;
            print_assign(ctx, &v);
        }
        ProxyGroupCmd::List { group } => {
            let v: Vec<ProxyGroupView> = cl.call(Request::ProxyGroupList { group })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                let rows: Vec<Vec<String>> = v
                    .iter()
                    .map(|g| {
                        vec![
                            g.name.to_string(),
                            g.group.to_string(),
                            opt(&g.network),
                            format!("{}/{}", g.assigned, g.capacity),
                            g.live.to_string(),
                            g.network_ready
                                .map(|r| format!("{r:?}").to_lowercase())
                                .unwrap_or_else(|| "no proxy".into()),
                            g.note.clone().unwrap_or_default(),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    table(
                        &[
                            "PROXY GROUP",
                            "GROUP",
                            "PROXY",
                            "ACCOUNTS",
                            "LIVE",
                            "PROXY STATE",
                            "NOTE"
                        ],
                        &rows,
                        &[3, 4]
                    )
                );
            }
        }
        ProxyGroupCmd::Set {
            name,
            group,
            capacity,
            proxy,
            clear_proxy,
            note,
        } => {
            let v: ProxyGroupView = cl.call(Request::ProxyGroupSet {
                name,
                group,
                capacity,
                network: proxy,
                clear_network: clear_proxy,
                note,
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!(
                    "proxy group {}: group {}, capacity {}, proxy {}",
                    v.name,
                    v.group,
                    v.capacity,
                    opt(&v.network)
                );
            }
        }
        ProxyGroupCmd::Remove { name, unassign } => {
            let v: Value = cl.call(Request::ProxyGroupRemove { name, unassign })?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                println!("{}", v["note"].as_str().unwrap_or("removed"));
            }
        }
        ProxyGroupCmd::Start {
            name,
            place_id,
            private_server_code,
            mode,
        } => {
            let v: Value = cl.call(Request::ProxyGroupStart {
                name,
                place_id,
                private_server_code,
                mode,
            })?;
            print_start(ctx, &v, "proxy_group", "proxy group");
        }
        ProxyGroupCmd::Stop { name, force } => {
            let v: Value = cl.call(Request::ProxyGroupStop { name, force })?;
            print_stop(ctx, &v);
        }
    }
    Ok(())
}

pub fn print_assign(ctx: &Ctx, v: &Value) {
    if ctx.out.json {
        ctx.out.value(v);
    } else if v["proxy_group"].is_null() {
        println!(
            "{} account(s) taken out of their proxy group",
            v["assigned"]
        );
    } else {
        println!(
            "proxy group {}: {} assigned, {} already there, {} registered, {} members now",
            v["proxy_group"].as_str().unwrap_or(""),
            v["assigned"],
            v["unchanged"],
            v["created"],
            v["members"]
        );
    }
}

/// The hierarchy, indented: each group with its place, the proxy groups in it,
/// the accounts in those, and then the accounts that are in none.
pub fn tree(ctx: &Ctx) -> Result<()> {
    let o: OverviewView = ctx.client()?.call(Request::Overview)?;
    if ctx.out.json {
        ctx.out.data(&o);
        return Ok(());
    }
    if o.groups.is_empty() && o.unassigned.is_empty() {
        println!("nothing yet: hrdctl group create NAME --place-id N");
    }
    for g in &o.groups {
        let v = &g.group;
        println!(
            "{}  place {}  mode {}  ({} account(s), {} live)",
            v.name,
            opt(&v.place_id),
            v.mode.map(|m| m.as_str()).unwrap_or("-"),
            v.accounts,
            v.live
        );
        if g.proxy_groups.is_empty() {
            println!(
                "  (no proxy groups: hrdctl proxy-group create NAME --group {} --capacity N)",
                v.name
            );
        }
        for p in &g.proxy_groups {
            let pv = &p.proxy_group;
            println!(
                "  {}  proxy {}  {}  {}/{} account(s)",
                pv.name,
                opt(&pv.network),
                pv.network_ready
                    .map(|r| format!("{r:?}").to_lowercase())
                    .unwrap_or_else(|| "no proxy".into()),
                pv.assigned,
                pv.capacity
            );
            for a in &p.accounts {
                println!("    {}  {}", a.id, a.state);
            }
        }
    }
    if !o.unassigned.is_empty() {
        println!("(in no group)");
        for a in &o.unassigned {
            println!("  {}  {}", a.id, a.state);
        }
    }
    if !o.free_networks.is_empty() {
        let free: Vec<String> = o
            .free_networks
            .iter()
            .map(|n| n.network.name.to_string())
            .collect();
        println!("proxies not used by any proxy group: {}", free.join(", "));
    }
    Ok(())
}

pub fn instance(ctx: &Ctx, c: InstanceCmd) -> Result<()> {
    let mut cl = ctx.client()?;
    match c {
        InstanceCmd::Start {
            account,
            place_id,
            proxy_group,
            private_server_code,
            mode,
        } => {
            let v: InstanceView = cl.call(Request::InstanceStart {
                account,
                place_id,
                proxy_group,
                private_server_code,
                mode,
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!(
                    "{}: {} (position {} in the queue)",
                    v.id,
                    v.state,
                    v.queue_position
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".into())
                );
            }
        }
        InstanceCmd::Stop { id, force } => {
            let v: Value = cl.call(Request::InstanceStop { id, force })?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else if v["stopping"].as_bool() == Some(true) {
                println!(
                    "{}: stopping{}",
                    v["id"].as_str().unwrap_or(""),
                    if force { " (killing)" } else { "" }
                );
            } else {
                println!(
                    "{}: {}",
                    v["id"].as_str().unwrap_or(""),
                    v["note"].as_str().or(v["was"].as_str()).unwrap_or("done")
                );
            }
        }
        InstanceCmd::Show { id } => {
            let d: InstanceDetail = cl.call(Request::InstanceShow { id })?;
            if ctx.out.json {
                ctx.out.data(&d);
                return Ok(());
            }
            let v = &d.view;
            println!(
                "{}  {}  ({})",
                v.id,
                v.state,
                v.reason.clone().unwrap_or_default()
            );
            println!(
                "  group {}  proxy group {}  place {}  run {}  mode {}  runtime {}",
                opt(&v.group),
                opt(&v.proxy_group),
                opt(&v.place_id),
                v.run,
                v.mode.as_str(),
                opt(&v.runtime)
            );
            println!(
                "  auth {:?}  since {}  uptime {}",
                v.auth,
                rfc3339(v.state_since),
                age(v.uptime_s)
            );
            let s = &d.record.signals;
            println!("  signals: engine loaded {}, signed in {}, join requested {}, connected {}, disconnected {}, disconnect code {}, screen {}", t(s.engine_loaded_at), t(s.signed_in_at), t(s.join_requested_at), t(s.connected_at), t(s.disconnected_at), opt(&s.disconnect_code), opt(&s.screen));
            if let Some(m) = &v.mem {
                println!(
                    "  memory: RSS {}  PSS {}  USS {}  swap {}  cgroup current {}",
                    mib_long(m.rss_bytes),
                    mib_long(m.pss_bytes),
                    mib_long(m.uss_bytes),
                    mib_long(m.swap_bytes),
                    mib_long(m.cgroup_current_bytes)
                );
            }
            if let Some(e) = &d.record.exit {
                println!(
                    "  exit: code {} signal {} oom-killed {} unobserved {}",
                    opt(&e.code),
                    opt(&e.signal),
                    e.oom_killed,
                    e.unobserved
                );
            }
            if !d.members.is_empty() {
                let rows: Vec<Vec<String>> = d
                    .members
                    .iter()
                    .map(|m| {
                        vec![
                            m.pid.to_string(),
                            m.class.clone(),
                            m.name.clone(),
                            mib(m.rss_bytes),
                            opt(&m.threads),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    table(
                        &["PID", "CLASS", "PROGRAM", "RSS MiB", "THREADS"],
                        &rows,
                        &[0, 3, 4]
                    )
                );
            }
            if !d.log_tail.is_empty() {
                println!("  last log lines:");
                for l in &d.log_tail {
                    println!("    {l}");
                }
            }
        }
    }
    Ok(())
}

fn t(v: Option<u64>) -> String {
    v.map(rfc3339).unwrap_or_else(|| "-".into())
}

pub fn stop_all(ctx: &Ctx, force: bool) -> Result<()> {
    let v: Value = ctx.client()?.call(Request::StopAll { force })?;
    if ctx.out.json {
        ctx.out.value(&v);
    } else {
        println!(
            "stopping {} instance(s){}",
            v["stopping"],
            if force { " (killing)" } else { "" }
        );
    }
    Ok(())
}

pub fn status(ctx: &Ctx, a: StatusArgs) -> Result<()> {
    let states = if a.live {
        vec![
            State::Queued,
            State::Starting,
            State::Joining,
            State::Connected,
            State::Unknown,
        ]
    } else {
        a.states
    };
    let v: Vec<InstanceView> = ctx.client()?.call(Request::Status {
        filter: Filter {
            states,
            group: a.group,
            proxy_group: a.proxy_group,
            label: a.label,
            accounts: a.accounts,
        },
    })?;
    if ctx.out.json {
        ctx.out.data(&v);
        return Ok(());
    }
    let mut counts: std::collections::BTreeMap<State, usize> = Default::default();
    for i in &v {
        *counts.entry(i.state).or_default() += 1;
    }
    let rows: Vec<Vec<String>> = v
        .iter()
        .map(|i| {
            vec![
                i.id.to_string(),
                i.state.to_string(),
                opt(&i.group),
                opt(&i.proxy_group),
                opt(&i.place_id),
                age(i.uptime_s),
                mib(i.mem.as_ref().and_then(|m| m.rss_bytes)),
                mib(i.mem.as_ref().and_then(|m| m.pss_bytes)),
                pct(i.cpu_percent),
                i.reason
                    .clone()
                    .unwrap_or_default()
                    .chars()
                    .take(70)
                    .collect(),
            ]
        })
        .collect();
    print!(
        "{}",
        table(
            &[
                "ID",
                "STATE",
                "GROUP",
                "PROXY GROUP",
                "PLACE",
                "UP",
                "RSS MiB",
                "PSS MiB",
                "CPU%",
                "WHY"
            ],
            &rows,
            &[5, 6, 7, 8]
        )
    );
    let summary: Vec<String> = State::ALL
        .iter()
        .filter_map(|s| counts.get(s).map(|n| format!("{n} {s}")))
        .collect();
    println!(
        "{} instance(s): {}",
        v.len(),
        if summary.is_empty() {
            "none".into()
        } else {
            summary.join(", ")
        }
    );
    Ok(())
}

fn class_row(name: &str, c: &ClassStats) -> Vec<String> {
    vec![
        name.into(),
        c.processes.to_string(),
        c.threads.to_string(),
        mib(c.rss_bytes),
        mib(c.pss_bytes),
        mib(c.uss_bytes),
        mib(c.swap_bytes),
        pct(c.cpu_percent),
    ]
}

pub fn stats(ctx: &Ctx, per_instance: bool) -> Result<()> {
    let mut cl = ctx.client()?;
    let s: StatsView = cl.call(Request::Stats {
        filter: Filter::default(),
    })?;
    let inst: Vec<InstanceView> = if per_instance {
        cl.call(Request::Status {
            filter: Filter {
                states: vec![
                    State::Starting,
                    State::Joining,
                    State::Connected,
                    State::Unknown,
                ],
                ..Default::default()
            },
        })?
    } else {
        vec![]
    };
    if ctx.out.json {
        ctx.out
            .value(&serde_json::json!({ "stats": s, "instances": inst }));
        return Ok(());
    }
    match s.sampled_at {
        Some(at) => println!(
            "sampled {} ago; CPU over {}; 100 = one core",
            human_duration(now_unix().saturating_sub(at)),
            s.cpu_window_s
                .map(|w| format!("{w:.0} s"))
                .unwrap_or_else(|| NM.into())
        ),
        None => println!("no sample yet"),
    }
    let rows = vec![
        class_row("manager", &s.manager),
        class_row("engine", &s.engines),
        class_row("compositor", &s.compositors),
        class_row("helpers", &s.helpers),
        class_row("TOTAL", &s.total),
    ];
    print!(
        "{}",
        table(
            &["CLASS", "PROCS", "THREADS", "RSS MiB", "PSS MiB", "USS MiB", "SWAP MiB", "CPU%"],
            &rows,
            &[1, 2, 3, 4, 5, 6, 7]
        )
    );
    println!("RSS counts shared pages in every process that maps them, so its total overstates; PSS divides shared pages among their users; USS is what only that process holds.");
    println!(
        "instances: {}   cgroup memory.current (sum, includes page cache): {}",
        s.instances,
        mib_long(s.cgroup_current_bytes)
    );
    println!("system: available {}   memory pressure (some, 10 s): {}   disk used by caches and runtime: {}", mib_long(s.mem_available_bytes), s.memory_pressure_some_avg10.map(|p| format!("{p:.1}%")).unwrap_or_else(|| NM.into()), mib_long(s.cache_disk_bytes));
    if let Some(k) = &s.ksm {
        println!(
            "KSM: {} pages shared by {} mappings",
            k.pages_shared, k.pages_sharing
        );
    }
    for (g, n) in &s.network {
        println!(
            "proxy group {g}: rx {}  tx {}",
            mib_long(n.rx_bytes),
            mib_long(n.tx_bytes)
        );
    }
    for n in &s.notes {
        println!("note: {n}");
    }
    if per_instance {
        let rows: Vec<Vec<String>> = inst
            .iter()
            .map(|i| {
                let m = i.mem.clone().unwrap_or_default();
                vec![
                    i.id.to_string(),
                    i.state.to_string(),
                    opt(&i.processes),
                    opt(&i.threads),
                    mib(m.rss_bytes),
                    mib(m.pss_bytes),
                    mib(m.uss_bytes),
                    mib(m.cgroup_current_bytes),
                    pct(i.cpu_percent),
                ]
            })
            .collect();
        print!(
            "{}",
            table(
                &["ID", "STATE", "PROCS", "THREADS", "RSS", "PSS", "USS", "CGROUP", "CPU%"],
                &rows,
                &[2, 3, 4, 5, 6, 7, 8]
            )
        );
        println!("PSS/USS are sampled every stats.pss_interval_s and may be older than RSS; \"-\" means {NM}.");
    }
    Ok(())
}

pub fn logs(ctx: &Ctx, id: AccountName, lines: usize, follow: bool) -> Result<()> {
    let mut cl = ctx.client()?;
    if !follow {
        let v: Vec<String> = cl.call(Request::Logs {
            id,
            lines,
            follow: false,
        })?;
        if ctx.out.json {
            ctx.out.data(&v);
        } else {
            for l in v {
                println!("{l}");
            }
        }
        return Ok(());
    }
    // The first reply carries the last lines; events follow.
    let json = ctx.out.json;
    cl.stream(
        Request::Logs {
            id,
            lines,
            follow: true,
        },
        |ev| {
            if let Some(arr) = ev.as_array() {
                for l in arr {
                    println!("{}", l.as_str().unwrap_or(""));
                }
            } else if let Ok(Event::Log { line, .. }) = serde_json::from_value::<Event>(ev.clone())
            {
                if json {
                    println!("{}", serde_json::json!({ "line": line }));
                } else {
                    println!("{line}");
                }
            }
            true
        },
    )
}

pub fn queue(ctx: &Ctx, c: QueueCmd) -> Result<()> {
    let mut cl = ctx.client()?;
    match c {
        QueueCmd::List => {
            let v: Vec<InstanceView> = cl.call(Request::QueueList)?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                let rows: Vec<Vec<String>> = v
                    .iter()
                    .map(|i| {
                        vec![
                            opt(&i.queue_position),
                            i.id.to_string(),
                            opt(&i.proxy_group),
                            opt(&i.place_id),
                            i.reason.clone().unwrap_or_default(),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    table(
                        &["#", "ID", "PROXY GROUP", "PLACE", "WHY WAITING"],
                        &rows,
                        &[0]
                    )
                );
            }
        }
        QueueCmd::Cancel { ids, all } => {
            if ids.is_empty() && !all {
                return Err(Error::invalid("name the accounts to cancel, or pass --all"));
            }
            let v: Value = cl.call(Request::QueueCancel { ids, all })?;
            ctx.out.line(format!("cancelled {}", v["cancelled"]));
            if ctx.out.json {
                ctx.out.value(&v);
            }
        }
    }
    Ok(())
}
