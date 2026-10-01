//! runtime, network, gateway.

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use serde_json::Value;

use hrd_core::ids::GroupName;
use hrd_core::model::{ExitInfo, Ipv6Policy, NetBackend, Network};
use hrd_core::proto::{ImportFile, NetworkView, Request};
use hrd_core::{fsutil, Error, Result};
use hrd_net::client::NetdClient;
use hrd_net::gateway::{self, GatewayInput, GatewayPeer, PanelForward};
use hrd_net::ipnet::IpNet;
use hrd_net::proto::{NetdRequest, NetworkSummary};

use crate::util::{age, opt, table};
use crate::{Ctx, NetworkCmd, RuntimeCmd};

fn apks_in(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        let md = std::fs::metadata(p).map_err(|e| Error::io(format!("{}", p.display()), e))?;
        if md.is_dir() {
            let mut v: Vec<PathBuf> = std::fs::read_dir(p)
                .map_err(|e| Error::io(format!("read {}", p.display()), e))?
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|x| x.eq_ignore_ascii_case("apk")) && p.is_file()
                })
                .collect();
            v.sort();
            if v.is_empty() {
                return Err(Error::invalid(format!(
                    "{} holds no .apk files",
                    p.display()
                )));
            }
            out.extend(v);
        } else {
            out.push(p.clone());
        }
    }
    Ok(out)
}

fn import_apks(
    ctx: &Ctx,
    apk: &[PathBuf],
    label: Option<String>,
    keep_current: bool,
) -> Result<()> {
    let paths = apks_in(apk)?;
    // The operator opens the files; the daemon's importer reads exactly
    // those descriptors, whatever their permissions or paths.
    let files: Vec<std::fs::File> = paths
        .iter()
        .map(|p| std::fs::File::open(p).map_err(|e| Error::io(format!("open {}", p.display()), e)))
        .collect::<Result<_>>()?;
    let meta: Vec<ImportFile> = paths
        .iter()
        .zip(&files)
        .map(|(p, f)| ImportFile {
            name: p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            size: f.metadata().map(|m| m.len()).unwrap_or(0),
        })
        .collect();
    let fds: Vec<_> = files.iter().map(|f| f.as_fd()).collect();
    ctx.out.line(format!(
        "verifying and installing {} file(s); this reads every byte and can take a few minutes",
        paths.len()
    ));
    let mut cl = hrd_core::wire::Client::connect(
        &ctx.socket,
        "cordialctl",
        Some(Duration::from_secs(3600)),
    )?;
    let v: Value = cl.call_with_fds(
        Request::RuntimeImport {
            files: meta,
            label,
            make_current: !keep_current,
        },
        &fds,
    )?;
    if ctx.out.json {
        ctx.out.value(&v);
    } else {
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    }
    Ok(())
}

/// `cordial-import fetch` as the invoking user, into a private temporary
/// directory that is removed afterwards.
fn fetch_runtime(ctx: &Ctx, version: Option<String>, list: bool, keep_current: bool) -> Result<()> {
    let importer = std::env::var("CORDIAL_IMPORTER")
        .unwrap_or_else(|_| "/usr/lib/cordial-hrd/cordial-import".to_string());
    if !Path::new(&importer).exists() {
        return Err(Error::unavailable(format!("{importer} is not installed")));
    }
    if list {
        let st = std::process::Command::new(&importer)
            .args(["fetch", "--list"])
            .status()
            .map_err(|e| Error::io("run the importer", e))?;
        return if st.success() {
            Ok(())
        } else {
            Err(Error::unavailable(
                "the mirror could not be reached or did not answer",
            ))
        };
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| Error::unavailable("no HOME to download into"))?;
    fsutil::ensure_private_dir(&base, 0o700)?;
    let dir = base.join(format!("cordial-hrd-fetch-{}", std::process::id()));
    let _ = fsutil::remove_dir_all_if_exists(&dir);
    fsutil::ensure_private_dir(&dir, 0o700)?;
    let result = (|| {
        ctx.out
            .line("downloading the Roblox build for x86-64; the file is about 150 MB");
        let mut cmd = std::process::Command::new(&importer);
        cmd.arg("fetch").arg("--into").arg(&dir);
        if let Some(v) = &version {
            cmd.arg("--version").arg(v);
        }
        let st = cmd.status().map_err(|e| Error::io("run the importer", e))?;
        if !st.success() {
            return Err(Error::unavailable(
                "the download or the signature check failed (see above); nothing was installed",
            ));
        }
        import_apks(
            ctx,
            std::slice::from_ref(&dir),
            Some("fetched".into()),
            keep_current,
        )
    })();
    let _ = fsutil::remove_dir_all_if_exists(&dir);
    result
}

pub fn runtime(ctx: &Ctx, c: RuntimeCmd) -> Result<()> {
    match c {
        RuntimeCmd::Import {
            apk,
            label,
            keep_current,
        } => import_apks(ctx, &apk, label, keep_current)?,
        RuntimeCmd::Fetch {
            version,
            list,
            keep_current,
        } => fetch_runtime(ctx, version, list, keep_current)?,
        RuntimeCmd::Update { now } => {
            let v: hrd_core::proto::UpdateView = ctx.client()?.call(if now {
                Request::RuntimeUpdateNow
            } else {
                Request::RuntimeUpdateStatus
            })?;
            if ctx.out.json {
                ctx.out.value(&serde_json::to_value(&v).unwrap_or_default());
            } else {
                let at = |t: Option<u64>| {
                    t.map(hrd_core::time::rfc3339)
                        .unwrap_or_else(|| "never".into())
                };
                println!(
                    "automatic updates: {} (every {} h)",
                    if v.enabled { "on" } else { "off" },
                    v.interval_h
                );
                println!("last check:        {}", at(v.last_check));
                println!(
                    "result:            {}",
                    v.last_result.as_deref().unwrap_or("-")
                );
                println!(
                    "newest on mirror:  {}",
                    v.newest_seen.as_deref().unwrap_or("-")
                );
                if v.running || now {
                    println!(
                        "a check is running; run `cordialctl runtime update` again in a minute"
                    );
                }
            }
        }
        RuntimeCmd::List => {
            let v: Value = ctx.client()?.call(Request::RuntimeList)?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                let arr = v
                    .as_array()
                    .cloned()
                    .or_else(|| v.get("builds").and_then(|b| b.as_array()).cloned())
                    .unwrap_or_default();
                let cur = v.get("current").and_then(|c| c.as_str()).unwrap_or("");
                let rows: Vec<Vec<String>> = arr
                    .iter()
                    .map(|b| {
                        let ver = b["version"].as_str().unwrap_or("?");
                        vec![
                            if b["current"].as_bool() == Some(true) || ver == cur {
                                "*".into()
                            } else {
                                "".into()
                            },
                            ver.to_string(),
                            b["abi"].as_str().unwrap_or("").to_string(),
                            b["label"].as_str().unwrap_or("").to_string(),
                            b["in_use_by"]
                                .as_array()
                                .map(|a| a.len().to_string())
                                .unwrap_or_default(),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    table(&["", "VERSION", "ABI", "LABEL", "RUNNING"], &rows, &[4])
                );
            }
        }
        RuntimeCmd::Use { version } => {
            let v: Value = ctx.client()?.call(Request::RuntimeUse { version })?;
            ctx.out.line(format!(
                "current build: {}  ({})",
                v["current"].as_str().unwrap_or(""),
                v["note"].as_str().unwrap_or("")
            ));
            if ctx.out.json {
                ctx.out.value(&v);
            }
        }
        RuntimeCmd::Remove { version } => {
            let v: Value = ctx.client()?.call(Request::RuntimeRemove { version })?;
            ctx.out
                .line(format!("removed {}", v["removed"].as_str().unwrap_or("")));
            if ctx.out.json {
                ctx.out.value(&v);
            }
        }
    }
    Ok(())
}

fn netd(ctx: &Ctx) -> NetdClient {
    NetdClient::new(ctx.layout.netd_socket())
}

fn to_model(s: &NetworkSummary, ipv6: Ipv6Policy) -> Network {
    Network {
        name: s.name.clone(),
        backend: NetBackend::WireguardNetns,
        secret_ref: format!("netd:{}", s.name),
        endpoint: s.endpoint.clone(),
        peer_public_key: s.peer_public_key.clone(),
        addresses: s.addresses.iter().map(|a| a.to_string()).collect(),
        dns: s.dns.clone(),
        allowed_ips: s.allowed_ips.iter().map(|a| a.to_string()).collect(),
        mtu: s.mtu,
        persistent_keepalive: s.persistent_keepalive,
        ipv6,
        exit: ExitInfo::default(),
        stun_server: None,
        max_clients: None,
        created_at: 0,
    }
}

pub fn network(ctx: &Ctx, c: NetworkCmd) -> Result<()> {
    match c {
        NetworkCmd::Add {
            name,
            wireguard_config,
            dns,
            exit_ip,
            stun_server,
            block_ipv6,
            max_clients,
        } => {
            if fsutil::euid() != 0 {
                return Err(Error::Denied("adding a network hands a private key to the root-only helper: run this as root (sudo cordialctl network add ...)".into()));
            }
            let md = std::fs::metadata(&wireguard_config)
                .map_err(|e| Error::io(format!("{}", wireguard_config.display()), e))?;
            if std::os::unix::fs::PermissionsExt::mode(&md.permissions()) & 0o077 != 0 {
                ctx.out.warn(format!("{} is readable by other users; the key in it may already have been exposed. Once imported, delete the file and consider the key compromised if the file was ever shared.", wireguard_config.display()));
            }
            let text = String::from_utf8(fsutil::read_limited(
                &wireguard_config,
                hrd_net::wg::MAX_FILE as u64,
            )?)
            .map_err(|_| Error::invalid("the WireGuard file is not UTF-8"))?;
            // Validate locally first so that a bad file never leaves this process.
            let parsed = hrd_net::wg::parse(&text)?;
            if parsed.dns.is_empty() && dns.is_empty() {
                return Err(Error::invalid("the file has no DNS line and --dns was not given: clients in this group can only reach the tunnel, so they need a resolver behind it"));
            }
            let summary: NetworkSummary = netd(ctx).call(NetdRequest::PutNetwork {
                name: name.clone(),
                config: text,
                dns,
            })?;
            let mut net = to_model(
                &summary,
                if block_ipv6 {
                    Ipv6Policy::Block
                } else {
                    Ipv6Policy::Auto
                },
            );
            net.stun_server = stun_server;
            net.max_clients = max_clients;
            net.exit.configured = match exit_ip {
                Some(s) => Some(
                    s.parse()
                        .map_err(|_| Error::invalid(format!("{s:?} is not an IP address")))?,
                ),
                None => None,
            };
            let v: NetworkView = ctx.client()?.call(Request::NetworkRegister {
                network: Box::new(net),
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!("network {} imported. Its key is in the helper's root-only store; nothing is applied yet.", v.network.name);
                println!(
                    "  client public key (give this to the gateway): {}",
                    summary.client_public_key
                );
                println!("  next: cordialctl group create NAME --network {} --capacity N; cordialctl network plan; cordialctl network apply", v.network.name);
                if summary.carries_ipv6 && !block_ipv6 {
                    println!("  the file carries IPv6: it will be routed through the tunnel. Use --block-ipv6 to block it instead.");
                }
            }
        }
        NetworkCmd::List => {
            let v: Vec<NetworkView> = ctx.client()?.call(Request::NetworkList)?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                let rows: Vec<Vec<String>> = v
                    .iter()
                    .map(|n| {
                        vec![
                            n.network.name.to_string(),
                            n.groups
                                .iter()
                                .map(|g| g.to_string())
                                .collect::<Vec<_>>()
                                .join(","),
                            format!("{:?}", n.readiness).to_lowercase(),
                            n.network.endpoint.clone(),
                            opt(&n.network.exit.configured),
                            n.network
                                .exit
                                .observed
                                .as_ref()
                                .map(|o| {
                                    format!(
                                        "{} ({}, {} ago)",
                                        o.address,
                                        if o.via == hrd_core::model::ProbeKind::Stun {
                                            "stun/UDP"
                                        } else {
                                            "http/TCP"
                                        },
                                        age(Some(hrd_core::time::now_unix().saturating_sub(o.at)))
                                    )
                                })
                                .unwrap_or_else(|| "-".into()),
                            age(n.latest_handshake_age_s),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    table(
                        &[
                            "NETWORK",
                            "GROUP",
                            "STATE",
                            "ENDPOINT",
                            "CONFIGURED EXIT",
                            "OBSERVED EXIT",
                            "HANDSHAKE AGO"
                        ],
                        &rows,
                        &[]
                    )
                );
                for n in v.iter().filter(|n| n.reason.is_some()) {
                    println!(
                        "  {}: {}",
                        n.network.name,
                        n.reason.clone().unwrap_or_default()
                    );
                }
            }
        }
        NetworkCmd::Plan => {
            let v: Value = ctx.client()?.call(Request::NetworkPlan)?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                for l in v["text"].as_array().into_iter().flatten() {
                    println!("{}", l.as_str().unwrap_or(""));
                }
                println!("\nNothing was changed. `cordialctl network apply` performs these steps for the groups listed; they touch only this project's namespaces and firewall table.");
            }
        }
        NetworkCmd::Apply { no_prune } => {
            let v: Vec<hrd_net::proto::ApplyOutcome> = ctx
                .client()?
                .call(Request::NetworkApply { prune: !no_prune })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                for o in &v {
                    println!(
                        "{}: {:?}{} {}",
                        o.group,
                        o.action,
                        if o.ok { "" } else { " FAILED" },
                        o.message
                    );
                }
            }
            if v.iter().any(|o| !o.ok) {
                return Err(Error::unavailable("some groups could not be applied"));
            }
        }
        NetworkCmd::Check { name } => {
            let v: Value = ctx.client()?.call(Request::NetworkCheck { name })?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                println!(
                    "observed exit {} (via {}, server {})",
                    v["observed"].as_str().unwrap_or("?"),
                    v["via"].as_str().unwrap_or("?"),
                    v["server"].as_str().unwrap_or("?")
                );
                match v["matches_configured"].as_bool() {
                    Some(true) => println!(
                        "matches the configured exit {}",
                        v["configured"].as_str().unwrap_or("")
                    ),
                    Some(false) => println!(
                        "DIFFERENT from the configured exit {}",
                        v["configured"].as_str().unwrap_or("")
                    ),
                    None => println!(
                        "no configured exit to compare with (network set NAME --exit-ip ADDRESS)"
                    ),
                }
                println!("{}", v["note"].as_str().unwrap_or(""));
            }
        }
        NetworkCmd::Set {
            name,
            exit_ip,
            stun_server,
            max_clients,
        } => {
            let v: NetworkView = ctx.client()?.call(Request::NetworkSet {
                name,
                configured_exit: exit_ip,
                stun_server,
                max_clients,
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!("network {} updated", v.network.name);
            }
        }
        NetworkCmd::Remove { name } => {
            let v: Value = ctx.client()?.call(Request::NetworkRemove { name })?;
            ctx.out
                .line(format!("removed {}", v["removed"].as_str().unwrap_or("")));
        }
    }
    Ok(())
}

#[derive(Args)]
pub struct GatewayArgs {
    /// Directory to write the files into (created, mode 0700)
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
    /// WireGuard interface name on the gateway
    #[arg(long, default_value = "wg-clients")]
    interface: String,
    #[arg(long, default_value_t = 51820)]
    listen_port: u16,
    /// The gateway's own address inside the tunnel network, for example 10.66.0.1/16
    #[arg(long)]
    address: String,
    /// The gateway's public network interface
    #[arg(long, default_value = "eth0")]
    uplink: String,
    /// Groups to include (default: every group with a network and a configured exit)
    #[arg(long = "group")]
    groups: Vec<GroupName>,
    /// Forward a port of the gateway to this machine's panel: its address on the management tunnel
    #[arg(long)]
    panel_target: Option<std::net::IpAddr>,
    #[arg(long, default_value_t = 0)]
    panel_port: u16,
    /// Source network allowed to reach the forwarded port (repeatable, required with --panel-target)
    #[arg(long = "panel-allow")]
    panel_allow: Vec<String>,
    #[arg(long)]
    panel_mgmt_key: Option<String>,
}

pub fn gateway_plan(ctx: &Ctx, a: GatewayArgs) -> Result<()> {
    let mut cl = ctx.client()?;
    let nets: Vec<NetworkView> = cl.call(Request::NetworkList)?;
    let summaries: Vec<NetworkSummary> = netd(ctx).call(NetdRequest::ListNetworks)?;
    let mut peers = Vec::new();
    for n in &nets {
        let Some(group) = n.groups.first() else {
            continue;
        };
        if !a.groups.is_empty() && !a.groups.contains(group) {
            continue;
        }
        let Some(exit) = n.network.exit.configured else {
            ctx.out.warn(format!("network {} has no configured exit; skipped (cordialctl network set {} --exit-ip ADDRESS)", n.network.name, n.network.name));
            continue;
        };
        let s = summaries
            .iter()
            .find(|s| s.name == n.network.name)
            .ok_or_else(|| {
                Error::not_found(format!(
                    "the helper does not know network {}",
                    n.network.name
                ))
            })?;
        peers.push(GatewayPeer {
            group: group.clone(),
            client_public_key: s.client_public_key.clone(),
            client_addresses: s.addresses.clone(),
            exit,
            has_preshared_key: s.has_preshared_key,
        });
    }
    let address: IpNet = a
        .address
        .parse()
        .map_err(|e| Error::invalid(format!("--address: {e}")))?;
    let panel = match a.panel_target {
        None => None,
        Some(target) => Some(PanelForward {
            target,
            port: a.panel_port,
            allowed_sources: a
                .panel_allow
                .iter()
                .map(|s| {
                    s.parse()
                        .map_err(|e| Error::invalid(format!("--panel-allow {s}: {e}")))
                })
                .collect::<Result<_>>()?,
            mgmt_public_key: a.panel_mgmt_key.clone().ok_or_else(|| {
                Error::invalid("--panel-mgmt-key is required with --panel-target")
            })?,
        }),
    };
    let plan = gateway::plan(&GatewayInput {
        interface: a.interface,
        listen_port: a.listen_port,
        address,
        uplink: a.uplink,
        peers,
        panel,
    })?;
    fsutil::ensure_private_dir(&a.out, 0o700)?;
    for f in &plan.files {
        let p = Path::new(&a.out).join(&f.name);
        fsutil::atomic_write(&p, f.content.as_bytes(), f.mode)?;
        ctx.out.line(format!("wrote {}", p.display()));
    }
    for w in &plan.warnings {
        ctx.out.warn(w);
    }
    ctx.out.line("Nothing was applied anywhere. Read the files (README first), copy them to the gateway and apply them there yourself.");
    Ok(())
}
