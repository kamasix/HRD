//! What applying a group's network means, as data.
//!
//! A plan is a list of [`Step`]s. The same enum is what the privileged helper
//! executes, so what `hrdctl network plan` prints and what
//! `hrd-netd` does cannot drift apart: adding an action means adding a
//! variant, and the compiler then demands both a description here and an
//! executor there.
//!
//! Every name and address in a step has already been parsed into a type that
//! cannot carry shell syntax, and the helper runs commands as argument vectors
//! without a shell. The description strings are for humans; they are never
//! executed.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use hrd_core::ids::{GroupName, NetworkName};
use hrd_core::model::Ipv6Policy;

use crate::ipnet::IpNet;

/// Name of the WireGuard interface inside every group's namespace. It is
/// inside its own namespace, so it does not need to be unique.
pub const IFACE: &str = "wg0";

/// What the operator asked for: this group leaves through this network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSpec {
    pub group: GroupName,
    pub network: NetworkName,
    pub ipv6: Ipv6Policy,
}

/// The resolved facts about a network that the steps depend on. The helper
/// builds this from its own root-only store; nothing in it comes from the
/// unprivileged side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFacts {
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub carries_ipv6: bool,
    /// SHA-256 of the key material and peer parameters, hex. Changes when the
    /// private key, the preshared key, the peer or the endpoint change, without
    /// the key itself ever appearing in a plan.
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Step {
    CreateNetns {
        group: GroupName,
    },
    LoopbackUp {
        group: GroupName,
    },
    CreateWireguard {
        group: GroupName,
        tmp: String,
    },
    MoveWireguard {
        tmp: String,
        group: GroupName,
    },
    ConfigureWireguard {
        group: GroupName,
        network: NetworkName,
    },
    FlushAddresses {
        group: GroupName,
    },
    AddAddress {
        group: GroupName,
        addr: IpNet,
    },
    SetMtu {
        group: GroupName,
        mtu: u16,
    },
    LinkUp {
        group: GroupName,
    },
    ReplaceDefaultRoute {
        group: GroupName,
        v6: bool,
    },
    DisableIpv6 {
        group: GroupName,
    },
    InstallFirewall {
        group: GroupName,
    },
    WriteResolver {
        group: GroupName,
        servers: Vec<IpAddr>,
    },
    WriteNsswitch {
        group: GroupName,
    },
    RemoveNetns {
        group: GroupName,
    },
}

impl Step {
    /// The command line this step amounts to, for the operator to read.
    /// Secrets are never part of it: key material travels on a pipe.
    pub fn describe(&self, netns_dir: &str) -> String {
        match self {
            Step::CreateNetns { group } => format!("create network namespace {netns_dir}/{group} (bind-mounted, survives a helper restart)"),
            Step::LoopbackUp { group } => format!("[{group}] ip link set lo up"),
            Step::CreateWireguard { tmp, .. } => format!("ip link add {tmp} type wireguard   (created in the host namespace: its UDP socket stays there and reaches the gateway; skipped if the namespace already has {IFACE})"),
            Step::MoveWireguard { tmp, group } => format!("ip link set {tmp} netns {netns_dir}/{group} name {IFACE}"),
            Step::ConfigureWireguard { group, network } => format!("[{group}] wg setconf {IFACE} /dev/stdin   (peer and keys of network {network}, key material on stdin)"),
            Step::FlushAddresses { group } => format!("[{group}] ip addr flush dev {IFACE}"),
            Step::AddAddress { group, addr } => format!("[{group}] ip addr add {addr} dev {IFACE}"),
            Step::SetMtu { group, mtu } => format!("[{group}] ip link set {IFACE} mtu {mtu}"),
            Step::LinkUp { group } => format!("[{group}] ip link set {IFACE} up"),
            Step::ReplaceDefaultRoute { group, v6 } => {
                format!("[{group}] ip {}route replace default dev {IFACE}", if *v6 { "-6 " } else { "" })
            }
            Step::DisableIpv6 { group } => format!("[{group}] sysctl net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1"),
            Step::InstallFirewall { group } => format!("[{group}] nft -f -   (table inet hrd: output and forward default-drop, only lo and {IFACE} allowed)"),
            Step::WriteResolver { group, servers } => {
                let s: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
                format!("write {netns_dir}/{group}.resolv.conf   (nameserver {})", s.join(", "))
            }
            Step::WriteNsswitch { group } => format!("write {netns_dir}/{group}.nsswitch.conf   (host's nsswitch.conf with hosts: files dns, so name lookups cannot go through systemd-resolved or nscd)"),
            Step::RemoveNetns { group } => format!("remove network namespace {netns_dir}/{group} and its generated files"),
        }
    }
}

/// The ruleset installed inside a group's namespace. Output is the direction
/// that matters: nothing may leave except through the tunnel (and loopback),
/// whatever the routing table says, so a missing or wrong route fails as "no
/// connection" and never as "another interface".
pub fn nft_ruleset(ipv6_blocked: bool) -> String {
    let v6 = if ipv6_blocked {
        "    meta nfproto ipv6 drop\n"
    } else {
        ""
    };
    format!(
        "flush ruleset\n\
         table inet hrd {{\n\
         \x20 chain input {{\n\
         \x20   type filter hook input priority 0; policy drop;\n\
         {v6}\
         \x20   iifname \"lo\" accept\n\
         \x20   iifname \"{IFACE}\" accept\n\
         \x20 }}\n\
         \x20 chain output {{\n\
         \x20   type filter hook output priority 0; policy drop;\n\
         {v6}\
         \x20   oifname \"lo\" accept\n\
         \x20   oifname \"{IFACE}\" accept\n\
         \x20 }}\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority 0; policy drop;\n\
         \x20 }}\n\
         }}\n"
    )
}

/// `nsswitch.conf` with only the `hosts:` line replaced.
pub fn nsswitch_with_dns_only(original: &str) -> String {
    let mut out = String::with_capacity(original.len() + 32);
    let mut replaced = false;
    for line in original.lines() {
        if line.trim_start().starts_with("hosts:") {
            if !replaced {
                out.push_str("hosts:          files dns\n");
                replaced = true;
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str("hosts:          files dns\n");
    }
    out
}

pub fn resolv_conf(servers: &[IpAddr]) -> String {
    let mut s =
        String::from("# generated by hrd-netd; reachable only through the group's tunnel\n");
    for d in servers {
        s.push_str(&format!("nameserver {d}\n"));
    }
    s.push_str("options timeout:3 attempts:2\n");
    s
}

// ---------------------------------------------------------------------------
// Manifest and diff
// ---------------------------------------------------------------------------

/// What the helper recorded after a successful apply of a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedGroup {
    pub network: NetworkName,
    pub hash: String,
    pub applied_at: u64,
    pub endpoint: String,
    pub ipv6_blocked: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub groups: BTreeMap<GroupName, AppliedGroup>,
}

/// Decide whether a group's ipv6 is blocked, from the policy and the tunnel.
pub fn ipv6_blocked(policy: Ipv6Policy, facts: &NetworkFacts) -> bool {
    match policy {
        Ipv6Policy::Block => true,
        Ipv6Policy::Auto => !facts.carries_ipv6,
    }
}

/// Hash of everything that, if it changed, means the namespace has to be
/// reconfigured.
pub fn desired_hash(spec: &GroupSpec, facts: &NetworkFacts) -> String {
    let mut h = Sha256::new();
    h.update(b"hrd-net-v1\n");
    h.update(spec.group.as_str().as_bytes());
    h.update(b"\n");
    h.update(spec.network.as_str().as_bytes());
    h.update(b"\n");
    h.update(facts.fingerprint.as_bytes());
    h.update(b"\n");
    h.update(
        serde_json::to_vec(&(
            &facts.addresses,
            &facts.dns,
            facts.mtu,
            ipv6_blocked(spec.ipv6, facts),
        ))
        .unwrap_or_default(),
    );
    hex(&h.finalize())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What a group needs, from nothing.
pub fn steps_to_create(spec: &GroupSpec, facts: &NetworkFacts, tmp_ifname: &str) -> Vec<Step> {
    let g = &spec.group;
    let mut v = vec![
        Step::CreateNetns { group: g.clone() },
        Step::LoopbackUp { group: g.clone() },
        Step::CreateWireguard {
            group: g.clone(),
            tmp: tmp_ifname.to_string(),
        },
        Step::MoveWireguard {
            tmp: tmp_ifname.to_string(),
            group: g.clone(),
        },
    ];
    v.extend(steps_to_reconfigure(spec, facts));
    v
}

/// What changes when the namespace and interface already exist.
pub fn steps_to_reconfigure(spec: &GroupSpec, facts: &NetworkFacts) -> Vec<Step> {
    let g = &spec.group;
    let blocked = ipv6_blocked(spec.ipv6, facts);
    let mut v = vec![
        // The firewall goes in first, before the interface has an address or a
        // route: from the first instant the namespace has a way out, it is one
        // that the ruleset already restricts.
        Step::InstallFirewall { group: g.clone() },
        Step::ConfigureWireguard {
            group: g.clone(),
            network: spec.network.clone(),
        },
        Step::FlushAddresses { group: g.clone() },
    ];
    for a in &facts.addresses {
        if blocked && a.is_v6() {
            continue;
        }
        v.push(Step::AddAddress {
            group: g.clone(),
            addr: *a,
        });
    }
    v.push(Step::SetMtu {
        group: g.clone(),
        mtu: facts.mtu,
    });
    v.push(Step::LinkUp { group: g.clone() });
    v.push(Step::ReplaceDefaultRoute {
        group: g.clone(),
        v6: false,
    });
    if blocked {
        v.push(Step::DisableIpv6 { group: g.clone() });
    } else {
        v.push(Step::ReplaceDefaultRoute {
            group: g.clone(),
            v6: true,
        });
    }
    v.push(Step::WriteResolver {
        group: g.clone(),
        servers: facts.dns.clone(),
    });
    v.push(Step::WriteNsswitch { group: g.clone() });
    v
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Reconfigure,
    Unchanged,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPlan {
    pub group: GroupName,
    pub action: Action,
    pub reason: String,
    /// Reconfiguring or removing a group that may have live clients interrupts
    /// them. The daemon refuses unless told to go ahead.
    pub disruptive: bool,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Plan {
    pub groups: Vec<GroupPlan>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.groups.iter().all(|g| g.action == Action::Unchanged)
    }
}

/// Compare what is wanted with what was applied.
///
/// `namespace_present` says whether the named namespace file still exists and
/// is a namespace: a manifest that claims a group the system no longer has
/// (after a reboot, `/run` is empty) is a `Create`, not `Unchanged`.
pub fn diff(
    specs: &[(GroupSpec, NetworkFacts)],
    manifest: &Manifest,
    namespace_present: &dyn Fn(&GroupName) -> bool,
    prune: bool,
    fresh_ifname: &dyn Fn() -> String,
) -> Plan {
    let mut out = Plan::default();
    for (spec, facts) in specs {
        let want = desired_hash(spec, facts);
        match manifest.groups.get(&spec.group) {
            Some(applied) if namespace_present(&spec.group) => {
                if applied.hash == want {
                    out.groups.push(GroupPlan {
                        group: spec.group.clone(),
                        action: Action::Unchanged,
                        reason: "namespace exists and matches the configuration".into(),
                        disruptive: false,
                        steps: vec![],
                    });
                } else {
                    out.groups.push(GroupPlan {
                        group: spec.group.clone(),
                        action: Action::Reconfigure,
                        reason: if applied.network != spec.network {
                            format!(
                                "network changed from {} to {}",
                                applied.network, spec.network
                            )
                        } else {
                            "the network's parameters or key changed".into()
                        },
                        disruptive: true,
                        steps: steps_to_reconfigure(spec, facts),
                    });
                }
            }
            Some(_) => out.groups.push(GroupPlan {
                group: spec.group.clone(),
                action: Action::Create,
                reason: "recorded as applied but the namespace is gone (reboot?)".into(),
                disruptive: false,
                steps: steps_to_create(spec, facts, &fresh_ifname()),
            }),
            None => out.groups.push(GroupPlan {
                group: spec.group.clone(),
                action: Action::Create,
                reason: "not applied yet".into(),
                disruptive: false,
                steps: steps_to_create(spec, facts, &fresh_ifname()),
            }),
        }
    }
    if prune {
        for g in manifest.groups.keys() {
            if !specs.iter().any(|(s, _)| &s.group == g) {
                out.groups.push(GroupPlan {
                    group: g.clone(),
                    action: Action::Remove,
                    reason: "no longer configured".into(),
                    disruptive: true,
                    steps: vec![Step::RemoveNetns { group: g.clone() }],
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(s: &str) -> GroupName {
        GroupName::new(s).unwrap()
    }
    fn n(s: &str) -> NetworkName {
        NetworkName::new(s).unwrap()
    }
    fn facts(v6: bool) -> NetworkFacts {
        NetworkFacts {
            addresses: if v6 {
                vec![
                    "10.66.1.2/32".parse().unwrap(),
                    "fd66::2/128".parse().unwrap(),
                ]
            } else {
                vec!["10.66.1.2/32".parse().unwrap()]
            },
            dns: vec!["10.66.0.1".parse().unwrap()],
            mtu: 1380,
            carries_ipv6: v6,
            fingerprint: "ab".repeat(32),
        }
    }
    fn spec() -> GroupSpec {
        GroupSpec {
            group: g("g01"),
            network: n("de-1"),
            ipv6: Ipv6Policy::Auto,
        }
    }

    #[test]
    fn the_firewall_is_installed_before_the_interface_has_a_way_out() {
        let steps = steps_to_create(&spec(), &facts(false), "hrdwtmp");
        let fw = steps
            .iter()
            .position(|s| matches!(s, Step::InstallFirewall { .. }))
            .unwrap();
        let up = steps
            .iter()
            .position(|s| matches!(s, Step::LinkUp { .. }))
            .unwrap();
        let route = steps
            .iter()
            .position(|s| matches!(s, Step::ReplaceDefaultRoute { .. }))
            .unwrap();
        assert!(fw < up && fw < route);
        // and the tunnel is configured before anything is addressed
        let conf = steps
            .iter()
            .position(|s| matches!(s, Step::ConfigureWireguard { .. }))
            .unwrap();
        let addr = steps
            .iter()
            .position(|s| matches!(s, Step::AddAddress { .. }))
            .unwrap();
        assert!(conf < addr);
    }

    #[test]
    fn ipv6_is_blocked_unless_the_tunnel_carries_it_and_policy_allows() {
        assert!(ipv6_blocked(Ipv6Policy::Auto, &facts(false)));
        assert!(!ipv6_blocked(Ipv6Policy::Auto, &facts(true)));
        assert!(ipv6_blocked(Ipv6Policy::Block, &facts(true)));

        let s = steps_to_reconfigure(
            &GroupSpec {
                ipv6: Ipv6Policy::Block,
                ..spec()
            },
            &facts(true),
        );
        assert!(s.iter().any(|x| matches!(x, Step::DisableIpv6 { .. })));
        assert!(
            !s.iter()
                .any(|x| matches!(x, Step::AddAddress { addr, .. } if addr.is_v6())),
            "a blocked v6 must not be addressed"
        );
        assert!(!s
            .iter()
            .any(|x| matches!(x, Step::ReplaceDefaultRoute { v6: true, .. })));

        let s = steps_to_reconfigure(&spec(), &facts(true));
        assert!(s
            .iter()
            .any(|x| matches!(x, Step::ReplaceDefaultRoute { v6: true, .. })));
        assert!(!s.iter().any(|x| matches!(x, Step::DisableIpv6 { .. })));
    }

    #[test]
    fn the_ruleset_allows_nothing_but_loopback_and_the_tunnel_out() {
        let r = nft_ruleset(false);
        assert!(r.contains("hook output priority 0; policy drop;"));
        assert_eq!(r.matches("accept").count(), 4, "{r}");
        for line in r.lines().filter(|l| l.contains("accept")) {
            assert!(
                line.contains("\"lo\"") || line.contains("\"wg0\""),
                "unexpected allow: {line}"
            );
        }
        assert!(nft_ruleset(true).contains("meta nfproto ipv6 drop"));
        assert!(!nft_ruleset(false).contains("nfproto"));
    }

    #[test]
    fn nsswitch_only_the_hosts_line_changes() {
        let orig = "passwd: files systemd\ngroup: files systemd\nhosts: files resolve [!UNAVAIL=return] dns\nnetworks: files\n";
        let out = nsswitch_with_dns_only(orig);
        assert!(out.contains("passwd: files systemd"));
        assert!(out.contains("hosts:          files dns"));
        assert!(!out.contains("resolve"));
        assert_eq!(out.matches("hosts:").count(), 1);
        assert!(nsswitch_with_dns_only("passwd: files\n").contains("hosts:          files dns"));
    }

    #[test]
    fn diff_distinguishes_create_unchanged_reconfigure_and_a_vanished_namespace() {
        let (s, f) = (spec(), facts(false));
        let mut m = Manifest::default();
        let fresh = || "hrdwtest".to_string();
        let present = |_: &GroupName| true;
        let absent = |_: &GroupName| false;

        let p = diff(&[(s.clone(), f.clone())], &m, &present, false, &fresh);
        assert_eq!(p.groups[0].action, Action::Create);

        m.groups.insert(
            s.group.clone(),
            AppliedGroup {
                network: s.network.clone(),
                hash: desired_hash(&s, &f),
                applied_at: 1,
                endpoint: "x".into(),
                ipv6_blocked: true,
            },
        );
        assert_eq!(
            diff(&[(s.clone(), f.clone())], &m, &present, false, &fresh).groups[0].action,
            Action::Unchanged
        );
        assert!(diff(&[(s.clone(), f.clone())], &m, &present, false, &fresh).is_empty());
        assert_eq!(
            diff(&[(s.clone(), f.clone())], &m, &absent, false, &fresh).groups[0].action,
            Action::Create,
            "after a reboot /run is empty"
        );

        let mut f2 = f.clone();
        f2.fingerprint = "cd".repeat(32);
        let p = diff(&[(s.clone(), f2)], &m, &present, false, &fresh);
        assert_eq!(p.groups[0].action, Action::Reconfigure);
        assert!(p.groups[0].disruptive);
    }

    #[test]
    fn prune_removes_only_what_is_recorded_and_no_longer_wanted() {
        let mut m = Manifest::default();
        m.groups.insert(
            g("old"),
            AppliedGroup {
                network: n("x"),
                hash: "h".into(),
                applied_at: 0,
                endpoint: "e".into(),
                ipv6_blocked: true,
            },
        );
        let fresh = || "t".to_string();
        let present = |_: &GroupName| true;
        assert!(diff(&[], &m, &present, false, &fresh).groups.is_empty());
        let p = diff(&[], &m, &present, true, &fresh);
        assert_eq!(p.groups.len(), 1);
        assert_eq!(p.groups[0].action, Action::Remove);
        assert!(p.groups[0].disruptive);
    }

    #[test]
    fn descriptions_never_contain_key_material_words() {
        for s in steps_to_create(&spec(), &facts(true), "hrdwtmp") {
            let d = s.describe("/run/cordial-hrd-netns").to_ascii_lowercase();
            assert!(
                !d.contains("privatekey") && !d.contains("presharedkey"),
                "{d}"
            );
        }
    }
}
