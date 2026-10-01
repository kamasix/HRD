//! Asking a proxy group's namespace how it is.

use std::time::Duration;

use hrd_core::ids::ProxyGroupName;
use hrd_net::plan::IFACE;
use hrd_net::proto::GroupStatus;

use crate::apply::Env;
use crate::exec;
use crate::nsops;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PeerDump {
    pub latest_handshake: u64,
    pub rx: u64,
    pub tx: u64,
}

/// Parse `wg show <if> dump`: a header line describing the interface (which
/// carries the private key and is never kept) then one tab-separated line per
/// peer. Fields of a peer line: public key, preshared key, endpoint, allowed
/// ips, latest handshake, rx, tx, keepalive.
pub fn parse_dump(text: &str) -> Vec<PeerDump> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Some(PeerDump {
                latest_handshake: f.get(4)?.parse().ok()?,
                rx: f.get(5)?.parse().ok()?,
                tx: f.get(6)?.parse().ok()?,
            })
        })
        .collect()
}

pub fn group_status(env: &Env, group: &ProxyGroupName) -> GroupStatus {
    let mut s = GroupStatus {
        group: Some(group.clone()),
        ..Default::default()
    };
    let manifest = env.store.manifest();
    if let Some(a) = manifest.groups.get(group) {
        s.network = Some(a.network.clone());
        s.applied_hash = Some(a.hash.clone());
        s.ipv6_blocked = Some(a.ipv6_blocked);
        s.endpoint = Some(a.endpoint.clone());
        if a.hash.is_empty() {
            s.problems
                .push("the last reconfiguration failed part-way; apply again".into());
        }
    }
    let path = env.ns_path(group);
    s.namespace_present = nsops::is_nsfs(&path);
    if !s.namespace_present {
        if manifest.groups.contains_key(group) {
            s.problems.push("recorded as applied but the namespace is gone (a reboot empties /run); apply again".into());
        }
        return s;
    }
    let Ok(ns) = nsops::open(&path) else {
        s.problems
            .push("the namespace file cannot be opened".into());
        return s;
    };
    let t = Duration::from_secs(10);
    match exec::run(
        &env.tools.ip,
        &["-o", "link", "show", "dev", IFACE],
        None,
        Some(&ns),
        t,
    ) {
        Ok(o) if o.ok() => {
            s.interface_present = true;
            // `<...,UP,LOWER_UP>` in the flags.
            let flags = o
                .stdout
                .split('<')
                .nth(1)
                .and_then(|r| r.split('>').next())
                .unwrap_or("");
            s.link_up = flags.split(',').any(|f| f == "UP");
            if !s.link_up {
                s.problems.push(format!("{IFACE} is down"));
            }
        }
        _ => s.problems.push(format!("the namespace has no {IFACE}")),
    }
    if s.interface_present {
        if let Ok(o) = exec::run(&env.tools.wg, &["show", IFACE, "dump"], None, Some(&ns), t) {
            if o.ok() {
                if let Some(p) = parse_dump(&o.stdout).into_iter().next() {
                    s.latest_handshake = (p.latest_handshake > 0).then_some(p.latest_handshake);
                    s.rx_bytes = Some(p.rx);
                    s.tx_bytes = Some(p.tx);
                }
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dump_is_parsed_and_the_interface_line_is_ignored() {
        let d = "PRIVATEKEYxxx\tPUBLIC\t51820\toff\nPEERKEY\t(none)\t203.0.113.1:51820\t0.0.0.0/0\t1700000123\t4096\t2048\t25\n";
        assert_eq!(
            parse_dump(d),
            vec![PeerDump {
                latest_handshake: 1700000123,
                rx: 4096,
                tx: 2048
            }]
        );
        assert_eq!(parse_dump("only\tthe\tinterface\tline\n"), vec![]);
        assert_eq!(parse_dump(""), vec![]);
    }
}
