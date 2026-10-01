//! The other end of the tunnels: what the VPS has to be told.
//!
//! Nothing here touches a machine. [`plan`] turns the groups and their exit
//! addresses into a set of files and instructions that the operator reads,
//! copies to the gateway and applies themselves. The brief says no deployment
//! without a separate command, and a gateway that is also the only way to reach
//! the server is the last place to apply something unread.
//!
//! The mapping is explicit. Each group's tunnel address is mapped to one public
//! address of the gateway, by name, in one place; traffic from any tunnel
//! address that is *not* in the map is dropped rather than translated to a
//! default. The gateway cannot create public addresses: each must already be
//! routed to it by the provider, and the plan says so.

use std::net::IpAddr;

use hrd_core::ids::GroupName;
use hrd_core::{Error, Result};

use crate::ipnet::IpNet;

#[derive(Debug, Clone)]
pub struct GatewayPeer {
    pub group: GroupName,
    /// The client side's public key (derived from the imported private key).
    pub client_public_key: String,
    /// The tunnel address(es) the client uses; the gateway routes only these
    /// back to it.
    pub client_addresses: Vec<IpNet>,
    /// The public address of the gateway this group's traffic should leave
    /// from, as configured by the operator.
    pub exit: IpAddr,
    /// The imported file carried a preshared key; the operator must put the
    /// same key on the gateway.
    pub has_preshared_key: bool,
}

#[derive(Debug, Clone)]
pub struct GatewayInput {
    /// WireGuard interface on the gateway.
    pub interface: String,
    pub listen_port: u16,
    /// The gateway's own tunnel address, e.g. `10.66.0.1/16`.
    pub address: IpNet,
    /// The public interface.
    pub uplink: String,
    pub peers: Vec<GatewayPeer>,
    /// Optional forward of the management panel (see docs/panel.md).
    pub panel: Option<PanelForward>,
}

#[derive(Debug, Clone)]
pub struct PanelForward {
    /// The home server's address on the management tunnel.
    pub target: IpAddr,
    pub port: u16,
    /// Source addresses allowed to reach the forwarded port. Empty is refused:
    /// an admin interface should not be forwarded to the whole Internet.
    pub allowed_sources: Vec<IpNet>,
    /// The gateway's management peer, added to the same interface.
    pub mgmt_public_key: String,
}

#[derive(Debug, Clone)]
pub struct GeneratedFile {
    pub name: String,
    pub mode: u32,
    pub content: String,
}

#[derive(Debug, Clone, Default)]
pub struct GatewayPlan {
    pub files: Vec<GeneratedFile>,
    pub warnings: Vec<String>,
}

fn ifname_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !s.starts_with('-')
}

fn check(input: &GatewayInput) -> Result<()> {
    if !ifname_ok(&input.interface) {
        return Err(Error::invalid(format!(
            "interface name {:?} is not usable (1-15 characters: letters, digits, - _ .)",
            input.interface
        )));
    }
    if !ifname_ok(&input.uplink) {
        return Err(Error::invalid(format!(
            "uplink name {:?} is not usable",
            input.uplink
        )));
    }
    if input.listen_port == 0 {
        return Err(Error::invalid("listen port must not be 0"));
    }
    if input.peers.is_empty() {
        return Err(Error::invalid("no groups with a configured exit address: set one with `hrdctl network set NAME --exit-ip ADDRESS`"));
    }
    let mut seen_addr: Vec<IpNet> = Vec::new();
    for p in &input.peers {
        if p.client_addresses.is_empty() {
            return Err(Error::invalid(format!(
                "group {} has no tunnel address",
                p.group
            )));
        }
        for a in &p.client_addresses {
            if seen_addr.contains(a) {
                return Err(Error::invalid(format!(
                    "tunnel address {a} is used by two groups; each client needs its own"
                )));
            }
            seen_addr.push(*a);
        }
        if p.exit.is_loopback() || p.exit.is_unspecified() || p.exit.is_multicast() {
            return Err(Error::invalid(format!(
                "group {}: exit address {} cannot be a public address",
                p.group, p.exit
            )));
        }
    }
    if let Some(pf) = &input.panel {
        if pf.allowed_sources.is_empty() {
            return Err(Error::invalid("the panel forward needs at least one allowed source address; it will not be opened to everyone"));
        }
        if pf.port == 0 {
            return Err(Error::invalid("panel port must not be 0"));
        }
    }
    Ok(())
}

pub fn plan(input: &GatewayInput) -> Result<GatewayPlan> {
    check(input)?;
    let mut out = GatewayPlan::default();

    // ---- WireGuard ----------------------------------------------------
    let mut wg = String::new();
    wg.push_str("# Generated by hrdctl gateway plan. Review before use.\n");
    wg.push_str(
        "# Nothing in this file runs a command: there is deliberately no PostUp/PreDown.\n",
    );
    wg.push_str("# Firewall and NAT are in hrd-gateway.nft, loaded separately.\n\n");
    wg.push_str("[Interface]\n");
    wg.push_str(&format!("Address = {}\n", input.address));
    wg.push_str(&format!("ListenPort = {}\n", input.listen_port));
    wg.push_str(
        "# Generate on the gateway, never here:  umask 077; wg genkey > /etc/wireguard/hrd.key\n",
    );
    wg.push_str("PrivateKey = <PASTE THE GATEWAY PRIVATE KEY HERE>\n");
    for p in &input.peers {
        wg.push_str(&format!(
            "\n# group {}  ->  exit {}\n[Peer]\n",
            p.group, p.exit
        ));
        wg.push_str(&format!("PublicKey = {}\n", p.client_public_key));
        if p.has_preshared_key {
            wg.push_str("PresharedKey = <PASTE THE SAME PRESHARED KEY AS IN THE CLIENT FILE>\n");
        }
        let ips: Vec<String> = p.client_addresses.iter().map(|a| a.to_string()).collect();
        wg.push_str(&format!("AllowedIPs = {}\n", ips.join(", ")));
    }
    if let Some(pf) = &input.panel {
        wg.push_str("\n# management tunnel to the home server (panel access)\n[Peer]\n");
        wg.push_str(&format!("PublicKey = {}\n", pf.mgmt_public_key));
        wg.push_str(&format!(
            "AllowedIPs = {}/{}\n",
            pf.target,
            if pf.target.is_ipv4() { 32 } else { 128 }
        ));
    }
    out.files.push(GeneratedFile {
        name: format!("{}.conf", input.interface),
        mode: 0o600,
        content: wg,
    });

    // ---- nftables -----------------------------------------------------
    let mapped: Vec<String> = input
        .peers
        .iter()
        .flat_map(|p| {
            p.client_addresses
                .iter()
                .filter(|a| a.addr.is_ipv4())
                .map(|a| a.addr.to_string())
        })
        .collect();
    let mut nft = String::new();
    nft.push_str("# Generated by hrdctl gateway plan. Check with: nft -c -f hrd-gateway.nft\n");
    nft.push_str("# Only the two tables below are managed; `nft delete table` on them removes everything this file adds.\n\n");
    nft.push_str("table inet hrd_gw {\n");
    nft.push_str(&format!(
        "  set mapped {{\n    type ipv4_addr\n    elements = {{ {} }}\n  }}\n",
        mapped.join(", ")
    ));
    nft.push_str("  chain forward {\n    type filter hook forward priority 0; policy accept;\n");
    nft.push_str(
        "    # a tunnel address with no explicit exit is dropped, never translated to a default\n",
    );
    nft.push_str(&format!(
        "    iifname \"{}\" ip saddr != @mapped drop\n",
        input.interface
    ));
    nft.push_str(&format!(
        "    iifname \"{}\" ip6 saddr != {{ ::/0 }} drop  # IPv6 is not translated by this plan\n",
        input.interface
    ));
    nft.push_str("  }\n}\n\n");
    nft.push_str("table ip hrd_gw_nat {\n  chain postrouting {\n    type nat hook postrouting priority 100; policy accept;\n");
    for p in &input.peers {
        for a in p.client_addresses.iter().filter(|a| a.addr.is_ipv4()) {
            nft.push_str(&format!(
                "    ip saddr {} oifname \"{}\" snat to {} comment \"{}\"\n",
                a.addr, input.uplink, p.exit, p.group
            ));
        }
    }
    nft.push_str("  }\n");
    if let Some(pf) = &input.panel {
        let srcs: Vec<String> = pf.allowed_sources.iter().map(|s| s.to_string()).collect();
        nft.push_str(
            "  chain prerouting {\n    type nat hook prerouting priority -100; policy accept;\n",
        );
        nft.push_str(&format!(
            "    iifname \"{}\" tcp dport {} ip saddr {{ {} }} dnat to {}:{} comment \"panel\"\n",
            input.uplink,
            pf.port,
            srcs.join(", "),
            pf.target,
            pf.port
        ));
        nft.push_str("  }\n");
    }
    nft.push_str("}\n");
    out.files.push(GeneratedFile {
        name: "hrd-gateway.nft".into(),
        mode: 0o644,
        content: nft,
    });

    // ---- sysctl -------------------------------------------------------
    out.files.push(GeneratedFile {
        name: "99-hrd-gateway.conf".into(),
        mode: 0o644,
        content: "# /etc/sysctl.d/99-hrd-gateway.conf\nnet.ipv4.ip_forward = 1\n".into(),
    });

    // ---- instructions -------------------------------------------------
    let mut readme = String::new();
    readme.push_str("Gateway plan. Nothing has been applied to any machine.\n\n");
    readme.push_str("Mapping (group -> tunnel address -> public exit):\n");
    for p in &input.peers {
        let addrs: Vec<String> = p.client_addresses.iter().map(|a| a.to_string()).collect();
        readme.push_str(&format!(
            "  {:<24} {:<32} {}\n",
            p.group.as_str(),
            addrs.join(","),
            p.exit
        ));
    }
    readme.push_str("\nBefore applying:\n");
    readme.push_str("  1. Every exit address above must already be assigned to this VPS and routed to it by the provider.\n");
    readme.push_str("     This plan cannot create public addresses. If the provider does not add them to the interface\n");
    readme.push_str(&format!(
        "     for you, add each with:  ip addr add <exit>/32 dev {}\n",
        input.uplink
    ));
    readme.push_str("  2. apt install wireguard-tools nftables\n");
    readme.push_str(&format!(
        "  3. Generate the gateway key on the VPS and paste it into {}.conf (mode 600).\n",
        input.interface
    ));
    readme.push_str(&format!(
        "  4. Copy {0}.conf to /etc/wireguard/ and enable:  systemctl enable --now wg-quick@{0}\n",
        input.interface
    ));
    readme
        .push_str("  5. Install 99-hrd-gateway.conf to /etc/sysctl.d/ and run:  sysctl --system\n");
    readme.push_str("  6. Check the firewall file first:  nft -c -f hrd-gateway.nft\n");
    readme.push_str("     Load it:  nft -f hrd-gateway.nft   (persist by including it from /etc/nftables.conf)\n");
    readme.push_str(
        "  7. Do not close your SSH session until you have opened a second one and it works.\n",
    );
    readme.push_str("     Neither file touches the `inet filter` table or the SSH port.\n");
    readme.push_str("\nVerify (from the home server, after `hrdctl network apply`):\n");
    readme.push_str("  hrdctl network check <name> --stun <your STUN server>   # the address the UDP path exits from\n");
    readme.push_str("\nRemove:\n");
    readme.push_str("  nft delete table inet hrd_gw; nft delete table ip hrd_gw_nat\n");
    readme.push_str(&format!(
        "  systemctl disable --now wg-quick@{}; rm /etc/wireguard/{}.conf\n",
        input.interface, input.interface
    ));
    out.files.push(GeneratedFile {
        name: "README-gateway.txt".into(),
        mode: 0o644,
        content: readme,
    });

    // ---- warnings -----------------------------------------------------
    if input
        .peers
        .iter()
        .any(|p| p.client_addresses.iter().any(|a| a.is_v6()))
    {
        out.warnings.push("a group has an IPv6 tunnel address; this plan does not translate IPv6. Keep the group's IPv6 policy on `block` unless the gateway routes a prefix to it.".into());
    }
    if let Some(pf) = &input.panel {
        out.warnings.push(format!(
            "the panel forward exposes TCP port {} of the VPS to {} and nothing else; the panel itself requires a token and TLS",
            pf.port,
            pf.allowed_sources.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(group: &str, addr: &str, exit: &str) -> GatewayPeer {
        GatewayPeer {
            group: GroupName::new(group).unwrap(),
            client_public_key: "kEjWL7wdlWmHMsqX5vofEwV4wV+tKPY4BY1rz+qFNjw=".into(),
            client_addresses: vec![addr.parse().unwrap()],
            exit: exit.parse().unwrap(),
            has_preshared_key: false,
        }
    }

    fn input() -> GatewayInput {
        GatewayInput {
            interface: "wg-hrd".into(),
            listen_port: 51820,
            address: "10.66.0.1/16".parse().unwrap(),
            uplink: "eth0".into(),
            peers: vec![
                peer("g01", "10.66.1.2/32", "203.0.113.11"),
                peer("g02", "10.66.2.2/32", "203.0.113.12"),
            ],
            panel: None,
        }
    }

    #[test]
    fn every_group_is_mapped_to_its_own_exit_by_name() {
        let p = plan(&input()).unwrap();
        let nft = &p
            .files
            .iter()
            .find(|f| f.name.ends_with(".nft"))
            .unwrap()
            .content;
        assert!(
            nft.contains(
                "ip saddr 10.66.1.2 oifname \"eth0\" snat to 203.0.113.11 comment \"g01\""
            ),
            "{nft}"
        );
        assert!(
            nft.contains(
                "ip saddr 10.66.2.2 oifname \"eth0\" snat to 203.0.113.12 comment \"g02\""
            ),
            "{nft}"
        );
        assert!(
            nft.contains("ip saddr != @mapped drop"),
            "unmapped tunnel addresses must be dropped"
        );
        assert!(!nft.contains("masquerade"), "no default translation");
    }

    #[test]
    fn the_wireguard_file_has_no_hooks_and_no_key() {
        let p = plan(&input()).unwrap();
        let wg = &p.files.iter().find(|f| f.name == "wg-hrd.conf").unwrap();
        for bad in ["PostUp", "PreUp", "PostDown", "PreDown"] {
            assert!(
                !wg.content.lines().any(|l| l.trim_start().starts_with(bad)),
                "{bad}"
            );
        }
        assert!(wg.content.contains("<PASTE THE GATEWAY PRIVATE KEY HERE>"));
        assert_eq!(wg.mode, 0o600);
        assert_eq!(wg.content.matches("[Peer]").count(), 2);
        assert!(wg.content.contains("AllowedIPs = 10.66.1.2/32"));
    }

    #[test]
    fn duplicate_tunnel_addresses_are_refused() {
        let mut i = input();
        i.peers[1] = peer("g02", "10.66.1.2/32", "203.0.113.12");
        assert!(plan(&i).unwrap_err().to_string().contains("two groups"));
    }

    #[test]
    fn names_that_reach_nftables_syntax_are_checked() {
        for bad in ["eth0; flush ruleset", "a b", "", "-x", "0123456789abcdef"] {
            let mut i = input();
            i.uplink = bad.into();
            assert!(plan(&i).is_err(), "{bad:?}");
            let mut i = input();
            i.interface = bad.into();
            assert!(plan(&i).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_panel_forward_is_limited_to_named_sources() {
        let mut i = input();
        i.panel = Some(PanelForward {
            target: "10.77.0.2".parse().unwrap(),
            port: 41873,
            allowed_sources: vec![],
            mgmt_public_key: "x".into(),
        });
        assert!(plan(&i).is_err());
        i.panel = Some(PanelForward {
            target: "10.77.0.2".parse().unwrap(),
            port: 41873,
            allowed_sources: vec!["198.51.100.7/32".parse().unwrap()],
            mgmt_public_key: "kEjWL7wdlWmHMsqX5vofEwV4wV+tKPY4BY1rz+qFNjw=".into(),
        });
        let p = plan(&i).unwrap();
        let nft = &p
            .files
            .iter()
            .find(|f| f.name.ends_with(".nft"))
            .unwrap()
            .content;
        assert!(
            nft.contains("tcp dport 41873 ip saddr { 198.51.100.7/32 } dnat to 10.77.0.2:41873"),
            "{nft}"
        );
        assert!(p.warnings.iter().any(|w| w.contains("token and TLS")));
    }

    #[test]
    fn the_instructions_say_nothing_was_applied_and_how_to_remove_it() {
        let p = plan(&input()).unwrap();
        let r = &p
            .files
            .iter()
            .find(|f| f.name.starts_with("README"))
            .unwrap()
            .content;
        assert!(r.contains("Nothing has been applied"));
        assert!(r.contains("nft delete table inet hrd_gw"));
        assert!(r.contains("routed to it by the provider"));
    }
}
