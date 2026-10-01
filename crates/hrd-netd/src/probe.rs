//! The STUN probe, run from inside a group's namespace.

use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use hrd_core::ids::ProxyGroupName;
use hrd_core::{Error, Result};
use hrd_net::proto::StunResult;
use hrd_net::stun;

use crate::apply::Env;
use crate::nsops;

fn txid() -> [u8; 12] {
    let mut b = [0u8; 12];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b
}

pub fn stun_probe(env: &Env, group: &ProxyGroupName, server: &str) -> Result<StunResult> {
    if server.is_empty()
        || server.len() > 253
        || !server
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return Err(Error::invalid(format!(
            "{server:?} is not a STUN server (host or host:port)"
        )));
    }
    let with_port = if server
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
    {
        server.to_string()
    } else {
        format!("{server}:3478")
    };
    // Resolved here, in the host's namespace: the namespace's own resolver is
    // the group's, and the question is about the path, not about the name.
    let addrs: Vec<_> = with_port
        .to_socket_addrs()
        .map_err(|e| Error::unavailable(format!("cannot resolve {server}: {e}")))?
        .collect();
    let dest = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| Error::unavailable(format!("{server} has no address")))?;
    let ns = nsops::open(&env.ns_path(group))?;
    let id = txid();
    let result = nsops::in_netns(&ns, move || -> Result<(IpAddr, u16)> {
        let bind = if dest.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind)
            .map_err(|e| Error::io("bind a UDP socket in the namespace", e))?;
        sock.set_read_timeout(Some(Duration::from_millis(1500)))
            .map_err(|e| Error::io("set a timeout", e))?;
        sock.connect(dest)
            .map_err(|e| Error::io("connect the UDP socket", e))?;
        let req = stun::binding_request(&id);
        let mut buf = [0u8; 512];
        for _ in 0..3 {
            sock.send(&req)
                .map_err(|e| Error::io("send the STUN request", e))?;
            if let Ok(n) = sock.recv(&mut buf) {
                if let Some(found) = stun::parse_response(&buf[..n], &id) {
                    return Ok(found);
                }
            }
        }
        Err(Error::unavailable(format!("no STUN reply from {dest} in 3 attempts: UDP does not get out through this group's tunnel, or the server is unreachable")))
    })??;
    Ok(StunResult {
        address: result.0,
        port: result.1,
        server: dest.to_string(),
    })
}
