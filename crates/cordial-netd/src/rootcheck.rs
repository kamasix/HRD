//! Checks that need root and a kernel that allows namespaces. They are
//! `#[ignore]`d so `cargo test` stays hermetic; run them on purpose with
//!
//! ```text
//! HRD_ROOT_TESTS=1 cargo test -p cordial-netd -- --ignored --nocapture
//! ```
//!
//! They use a `veth` pair where the real thing uses a WireGuard interface,
//! because a kernel is not guaranteed to have WireGuard and this checks what
//! this helper does around the interface, not WireGuard. What they therefore do
//! **not** cover is `wg setconf` and the handshake; `docs/status.md` says so.

use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use hrd_core::ids::{GroupName, NetworkName};
use hrd_core::layout::Layout;
use hrd_core::model::Ipv6Policy;
use hrd_net::base64;
use hrd_net::plan::{self, GroupSpec, IFACE};

use crate::apply::{self, Env};
use crate::exec::{self, Tools};
use crate::nsops;
use crate::status;
use crate::store::NetStore;

fn enabled() -> bool {
    std::env::var_os("HRD_ROOT_TESTS").is_some() && rustix::process::geteuid().is_root()
}

fn sh(prog: &str, args: &[&str]) -> (bool, String) {
    let o = Command::new(prog).args(args).output().unwrap();
    (
        o.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}

fn in_ns(ns: &Path, prog: &str, args: &[&str]) -> (bool, String) {
    let mut a = vec![
        format!("--net={}", ns.display()),
        "--".to_string(),
        prog.to_string(),
    ];
    a.extend(args.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    sh("nsenter", &refs)
}

fn conf() -> String {
    let k = |n: u8| base64::encode(&[n; 32]);
    format!("[Interface]\nPrivateKey = {}\nAddress = 10.99.0.2/24\nDNS = 10.99.0.1\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.1:51820\n", k(1), k(2))
}

#[test]
#[ignore]
fn a_namespace_has_one_way_out_and_it_is_the_tunnel_interface() {
    if !enabled() {
        eprintln!("skipped: set HRD_ROOT_TESTS=1 and run as root");
        return;
    }
    let root = std::env::temp_dir().join(format!("hrd-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let layout = Layout::under(&root);
    let env = Env {
        layout: layout.clone(),
        tools: Tools::locate().expect("ip, wg and nft installed"),
        store: NetStore::new(layout.netd_state_dir.clone()),
    };
    env.store.ensure().unwrap();
    let net_name = NetworkName::new("t1").unwrap();
    env.store.put(&net_name, &conf(), &[]).unwrap();
    let net = env.store.get(&net_name).unwrap();
    let group = GroupName::new("gt1").unwrap();
    let spec = GroupSpec {
        group: group.clone(),
        network: net_name.clone(),
        ipv6: Ipv6Policy::Auto,
    };
    let endpoint = "203.0.113.1:51820".parse().unwrap();
    let ns = env.ns_path(&group);

    // 1. create, twice
    apply::exec_step(
        &env,
        &plan::Step::CreateNetns {
            group: group.clone(),
        },
        &spec,
        &net,
        endpoint,
    )
    .unwrap();
    apply::exec_step(
        &env,
        &plan::Step::CreateNetns {
            group: group.clone(),
        },
        &spec,
        &net,
        endpoint,
    )
    .expect("idempotent");
    assert!(
        nsops::is_nsfs(&ns),
        "the namespace is a bind-mounted handle"
    );
    apply::exec_step(
        &env,
        &plan::Step::LoopbackUp {
            group: group.clone(),
        },
        &spec,
        &net,
        endpoint,
    )
    .unwrap();

    // 2. a veth pair stands in for the tunnel: one end is moved in as wg0
    let (ok, out) = sh(
        "ip",
        &[
            "link", "add", "hrdwtest", "type", "veth", "peer", "name", "hrdwpeer",
        ],
    );
    assert!(ok, "{out}");
    apply::exec_step(
        &env,
        &plan::Step::MoveWireguard {
            tmp: "hrdwtest".into(),
            group: group.clone(),
        },
        &spec,
        &net,
        endpoint,
    )
    .unwrap();
    assert!(env.iface_exists(&group), "moved and renamed to {IFACE}");
    assert!(
        !sh("ip", &["link", "show", "hrdwtest"]).0,
        "no longer in the host namespace"
    );

    // 3. everything the plan does after the interface exists, except `wg setconf`
    let plan_steps = plan::steps_to_reconfigure(&spec, &net.facts());
    for s in &plan_steps {
        if matches!(s, plan::Step::ConfigureWireguard { .. }) {
            continue;
        }
        apply::exec_step(&env, s, &spec, &net, endpoint)
            .unwrap_or_else(|e| panic!("{}: {e}", s.describe("")));
    }
    let (_, addrs) = in_ns(&ns, "ip", &["-o", "addr", "show", "dev", IFACE]);
    assert!(addrs.contains("10.99.0.2/24"), "{addrs}");
    let (_, routes) = in_ns(&ns, "ip", &["route", "show"]);
    assert!(routes.contains("default dev wg0"), "{routes}");
    let (_, rules) = in_ns(&ns, "nft", &["list", "ruleset"]);
    assert!(
        rules.contains("policy drop") && rules.contains("oifname \"wg0\" accept"),
        "{rules}"
    );
    assert!(layout.netns_resolv(&group).exists() && layout.netns_nsswitch(&group).exists());
    let resolv = std::fs::read_to_string(layout.netns_resolv(&group)).unwrap();
    assert!(resolv.contains("nameserver 10.99.0.1"), "{resolv}");
    let nss = std::fs::read_to_string(layout.netns_nsswitch(&group)).unwrap();
    assert!(nss.contains("hosts:          files dns"), "{nss}");

    // 4. status sees it
    let (ok, _) = sh("ip", &["addr", "add", "10.99.0.1/24", "dev", "hrdwpeer"]);
    assert!(ok);
    sh("ip", &["link", "set", "hrdwpeer", "up"]);
    let st = status::group_status(&env, &group);
    assert!(
        st.namespace_present && st.interface_present && st.link_up,
        "{st:?}"
    );

    // 5. the tunnel stand-in carries traffic out of the namespace...
    let py = |host: &str| {
        format!("import socket,sys\ns=socket.socket();s.settimeout(1.5)\ntry:\n s.connect(('{host}',9));print('connected')\nexcept ConnectionRefusedError:\n print('refused-but-reachable')\nexcept Exception as e:\n print('unreachable', type(e).__name__)\n")
    };
    let (_, via_wg) = in_ns(&ns, "python3", &["-c", &py("10.99.0.1")]);
    assert!(
        via_wg.contains("refused-but-reachable") || via_wg.contains("connected"),
        "through wg0: {via_wg}"
    );

    // 6. ...and a second interface the plan did not make is a dead end even though
    // its network is directly attached and its peer answers
    let (ok, out) = sh(
        "ip",
        &[
            "link", "add", "evil0", "type", "veth", "peer", "name", "evilp",
        ],
    );
    assert!(ok, "{out}");
    sh(
        "ip",
        &["link", "set", "evil0", "netns", ns.to_str().unwrap()],
    );
    sh("ip", &["addr", "add", "10.98.0.1/24", "dev", "evilp"]);
    sh("ip", &["link", "set", "evilp", "up"]);
    in_ns(&ns, "ip", &["addr", "add", "10.98.0.2/24", "dev", "evil0"]);
    in_ns(&ns, "ip", &["link", "set", "evil0", "up"]);
    let (_, via_evil) = in_ns(&ns, "python3", &["-c", &py("10.98.0.1")]);
    assert!(
        via_evil.contains("unreachable"),
        "the firewall must drop output on any interface but lo and wg0: {via_evil}"
    );

    // 6b. the control: the same path is reachable once the rules are gone, so it
    // was the ruleset, and not a missing route, that stopped it
    in_ns(&ns, "nft", &["flush", "ruleset"]);
    let (_, control) = in_ns(&ns, "python3", &["-c", &py("10.98.0.1")]);
    assert!(
        control.contains("refused-but-reachable") || control.contains("connected"),
        "control (no firewall) must reach the peer: {control}"
    );

    // 7. teardown is complete and idempotent
    apply::remove_group(&env, &group).unwrap();
    apply::remove_group(&env, &group).expect("idempotent");
    assert!(!nsops::is_nsfs(&ns) && !ns.exists() && !layout.netns_resolv(&group).exists());
    sh("ip", &["link", "del", "hrdwpeer"]);
    sh("ip", &["link", "del", "evilp"]);
    let _ = std::fs::remove_dir_all(&root);
    let _ = (IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), exec::run); // keep imports honest in both cfgs
}
