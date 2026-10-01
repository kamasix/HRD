//! What the helper keeps on disk. Root-owned, mode 0600/0700: the WireGuard
//! private keys live here and nowhere else.

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

use hrd_core::fsutil;
use hrd_core::ids::NetworkName;
use hrd_core::{Error, Result};
use hrd_net::plan::{Manifest, NetworkFacts};
use hrd_net::proto::NetworkSummary;
use hrd_net::wg::{self, WgConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub struct NetStore {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct OnDisk {
    config: String,
    dns: Vec<IpAddr>,
}

pub struct StoredNetwork {
    pub summary: NetworkSummary,
    pub wg: WgConfig,
    pub dns: Vec<IpAddr>,
}

const DEFAULT_MTU: u16 = 1420;

impl StoredNetwork {
    pub fn facts(&self) -> NetworkFacts {
        let mut h = Sha256::new();
        h.update(self.wg.private_key.expose().as_bytes());
        h.update(b"\n");
        if let Some(p) = &self.wg.peer.preshared_key {
            h.update(p.expose().as_bytes());
        }
        h.update(b"\n");
        h.update(self.wg.peer.public_key.as_bytes());
        h.update(b"\n");
        h.update(self.wg.peer.endpoint.to_string().as_bytes());
        h.update(b"\n");
        for a in &self.wg.peer.allowed_ips {
            h.update(a.to_string().as_bytes());
            h.update(b",");
        }
        h.update(
            format!(
                "\n{:?}\n{:?}",
                self.wg.peer.persistent_keepalive, self.wg.listen_port
            )
            .as_bytes(),
        );
        NetworkFacts {
            addresses: self.wg.addresses.clone(),
            dns: self.dns.clone(),
            mtu: self.wg.mtu.unwrap_or(DEFAULT_MTU),
            carries_ipv6: self.wg.carries_ipv6(),
            fingerprint: h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        }
    }
}

fn summarise(name: &NetworkName, cfg: &WgConfig, dns: &[IpAddr]) -> Result<NetworkSummary> {
    Ok(NetworkSummary {
        name: name.clone(),
        addresses: cfg.addresses.clone(),
        dns: dns.to_vec(),
        allowed_ips: cfg.peer.allowed_ips.clone(),
        endpoint: cfg.peer.endpoint.to_string(),
        peer_public_key: cfg.peer.public_key.clone(),
        client_public_key: cfg.public_key()?,
        mtu: cfg.mtu,
        persistent_keepalive: cfg.peer.persistent_keepalive,
        carries_ipv6: cfg.carries_ipv6(),
        has_preshared_key: cfg.peer.preshared_key.is_some(),
    })
}

impl NetStore {
    pub fn new(dir: impl Into<PathBuf>) -> NetStore {
        NetStore { dir: dir.into() }
    }

    pub fn ensure(&self) -> Result<()> {
        fsutil::ensure_private_dir(&self.dir, 0o700)?;
        fsutil::ensure_private_dir(&self.networks_dir(), 0o700)
    }

    fn networks_dir(&self) -> PathBuf {
        self.dir.join("networks")
    }

    fn file(&self, name: &NetworkName) -> PathBuf {
        self.networks_dir().join(format!("{name}.json"))
    }

    /// Validate `config` and keep it. `dns` replaces the file's DNS when
    /// non-empty. A network with no resolver is refused: a namespace whose only
    /// route is the tunnel needs a resolver reachable through it, and inheriting
    /// the host's would send name lookups around the tunnel.
    pub fn put(&self, name: &NetworkName, config: &str, dns: &[IpAddr]) -> Result<NetworkSummary> {
        let parsed = wg::parse(config)?;
        let dns: Vec<IpAddr> = if dns.is_empty() {
            parsed.dns.clone()
        } else {
            dns.to_vec()
        };
        if dns.is_empty() {
            return Err(Error::invalid(
                "the network has no DNS server. Its clients can only reach the tunnel, so they need a resolver that the tunnel reaches: add `DNS = ...` to the file's [Interface] or pass --dns",
            ));
        }
        let summary = summarise(name, &parsed, &dns)?;
        self.ensure()?;
        fsutil::write_json_atomic(
            &self.file(name),
            &OnDisk {
                config: config.to_string(),
                dns,
            },
            0o600,
        )?;
        Ok(summary)
    }

    pub fn get(&self, name: &NetworkName) -> Result<StoredNetwork> {
        let bytes = fsutil::read_limited_opt(&self.file(name), wg::MAX_FILE as u64 + 4096)?
            .ok_or_else(|| {
                Error::not_found(format!("no network {name} is stored in the helper"))
            })?;
        let disk: OnDisk = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Internal(format!("stored network {name}: {e}")))?;
        let wg = wg::parse(&disk.config)?;
        let summary = summarise(name, &wg, &disk.dns)?;
        Ok(StoredNetwork {
            summary,
            wg,
            dns: disk.dns,
        })
    }

    pub fn list(&self) -> Vec<NetworkSummary> {
        let mut out: Vec<NetworkSummary> = fs::read_dir(self.networks_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                e.file_name()
                    .to_str()?
                    .strip_suffix(".json")
                    .map(String::from)
            })
            .filter_map(|n| NetworkName::new(n).ok())
            .filter_map(|n| self.get(&n).ok().map(|s| s.summary))
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn delete(&self, name: &NetworkName) -> Result<()> {
        match fs::remove_file(self.file(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::not_found(format!("no network {name} is stored")))
            }
            Err(e) => Err(Error::io("delete the stored network", e)),
        }
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join("applied.json")
    }

    pub fn manifest(&self) -> Manifest {
        fsutil::read_limited_opt(&self.manifest_path(), 4 * 1024 * 1024)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save_manifest(&self, m: &Manifest) -> Result<()> {
        self.ensure()?;
        fsutil::write_json_atomic(&self.manifest_path(), m, 0o600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hrd_net::base64;

    fn conf(dns: bool, key: u8) -> String {
        let k = |n: u8| base64::encode(&[n; 32]);
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.66.1.2/32\n{}\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.1:51820\n",
            k(key),
            if dns { "DNS = 10.66.0.1" } else { "" },
            k(2)
        )
    }

    fn scratch(tag: &str) -> NetStore {
        let d = std::env::temp_dir().join(format!("hrd-netstore-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        NetStore::new(d)
    }

    #[test]
    fn a_stored_network_round_trips_and_the_file_is_private() {
        let s = scratch("rt");
        let n = NetworkName::new("de-1").unwrap();
        let sum = s.put(&n, &conf(true, 1), &[]).unwrap();
        assert_eq!(sum.dns, vec!["10.66.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(sum.client_public_key.len(), 44);
        let got = s.get(&n).unwrap();
        assert_eq!(got.summary, sum);
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(s.file(&n)).unwrap().mode() & 0o777, 0o600);
        assert_eq!(s.list().len(), 1);
        s.delete(&n).unwrap();
        assert!(s.get(&n).is_err());
        fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn no_dns_is_refused_unless_given() {
        let s = scratch("dns");
        let n = NetworkName::new("x").unwrap();
        assert!(s
            .put(&n, &conf(false, 1), &[])
            .unwrap_err()
            .to_string()
            .contains("no DNS"));
        let sum = s
            .put(&n, &conf(false, 1), &["9.9.9.9".parse().unwrap()])
            .unwrap();
        assert_eq!(sum.dns.len(), 1);
        fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn the_fingerprint_changes_with_the_key_and_not_with_the_address() {
        let s = scratch("fp");
        let n = NetworkName::new("x").unwrap();
        s.put(&n, &conf(true, 1), &[]).unwrap();
        let a = s.get(&n).unwrap().facts().fingerprint;
        s.put(&n, &conf(true, 1), &[]).unwrap();
        assert_eq!(s.get(&n).unwrap().facts().fingerprint, a);
        s.put(&n, &conf(true, 9), &[]).unwrap();
        assert_ne!(s.get(&n).unwrap().facts().fingerprint, a);
        fs::remove_dir_all(&s.dir).ok();
    }

    #[test]
    fn a_hook_in_the_file_never_reaches_the_store() {
        let s = scratch("hook");
        let n = NetworkName::new("x").unwrap();
        let bad = conf(true, 1).replace("[Peer]", "PostUp = rm -rf /\n[Peer]");
        assert!(s.put(&n, &bad, &[]).is_err());
        assert!(s.list().is_empty());
        fs::remove_dir_all(&s.dir).ok();
    }
}
