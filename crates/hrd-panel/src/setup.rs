//! The panel's own state: where it listens, its certificate and its token hash.
//! Everything is under `<state>/panel` (owner-only) and is created by
//! `hrd-panel init`, which is the only place a token is ever shown.

use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use hrd_core::layout::Layout;
use hrd_core::time::now_unix;
use hrd_core::{fsutil, Error, Result};

use crate::auth;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelConf {
    pub listen: IpAddr,
    pub port: u16,
    /// Names and addresses the certificate is valid for, and that `show` prints.
    pub sans: Vec<String>,
    pub created_at: u64,
}

pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn new(l: &Layout) -> Paths {
        Paths {
            dir: l.state_dir.join("panel"),
        }
    }
    pub fn conf(&self) -> PathBuf {
        self.dir.join("panel.json")
    }
    pub fn cert(&self) -> PathBuf {
        self.dir.join("tls.crt")
    }
    pub fn key(&self) -> PathBuf {
        self.dir.join("tls.key")
    }
    pub fn token_hash(&self) -> PathBuf {
        self.dir.join("token.sha256")
    }
    pub fn uploads(&self) -> PathBuf {
        self.dir.join("uploads")
    }
}

pub fn load_conf(p: &Paths) -> Result<PanelConf> {
    let b = fsutil::read_limited_opt(&p.conf(), 64 * 1024)?.ok_or_else(|| {
        Error::not_found(
            "the panel is not set up: run `hrd-panel init --listen ADDRESS` as the service user",
        )
    })?;
    serde_json::from_slice(&b).map_err(|e| Error::invalid(format!("{}: {e}", p.conf().display())))
}

pub fn load_token_hash(p: &Paths) -> Result<[u8; 32]> {
    fsutil::require_private_file(&p.token_hash())?;
    let b = fsutil::read_limited(&p.token_hash(), 256)?;
    let s = String::from_utf8_lossy(&b);
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::invalid(
            "token.sha256 is damaged: `hrd-panel reset-token`",
        ));
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| Error::invalid("token.sha256"))?;
    }
    Ok(out)
}

/// A random port in the range unlikely to collide with anything, that can be
/// bound on `listen` right now.
pub fn pick_port(listen: IpAddr) -> Result<u16> {
    for _ in 0..200 {
        let b = auth::random_bytes::<2>();
        let port = 20000 + (u16::from_le_bytes(b) % 40000);
        if TcpListener::bind(SocketAddr::new(listen, port)).is_ok() {
            return Ok(port);
        }
    }
    Err(Error::unavailable("could not find a free port"))
}

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn year_now() -> i32 {
    1970 + (now_unix() / 31_556_952) as i32
}

pub fn make_certificate(sans: &[String]) -> Result<(String, String, Vec<u8>)> {
    let mut params = rcgen::CertificateParams::new(sans.to_vec())
        .map_err(|e| Error::invalid(format!("certificate names: {e}")))?;
    let y = year_now();
    params.not_before = rcgen::date_time_ymd(y - 1, 1, 1);
    params.not_after = rcgen::date_time_ymd(y + 2, 1, 1);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "hrd panel");
    let key =
        rcgen::KeyPair::generate().map_err(|e| Error::Internal(format!("key generation: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| Error::Internal(format!("certificate: {e}")))?;
    Ok((cert.pem(), key.serialize_pem(), cert.der().to_vec()))
}

pub struct InitOpts {
    pub listen: IpAddr,
    pub port: Option<u16>,
    pub sans: Vec<String>,
    pub force: bool,
}

pub struct Initialised {
    pub conf: PanelConf,
    pub token: String,
    pub fingerprint: String,
}

pub fn init(p: &Paths, o: InitOpts) -> Result<Initialised> {
    fsutil::ensure_private_dir(&p.dir, 0o700)?;
    if p.conf().exists() && !o.force {
        return Err(Error::conflict("the panel is already set up (`hrd-panel show`); --force replaces the port, certificate and token"));
    }
    let port = match o.port {
        Some(p) => p,
        None => pick_port(o.listen)?,
    };
    let mut sans = o.sans;
    if !o.listen.is_unspecified() {
        sans.push(o.listen.to_string());
    }
    sans.push("localhost".into());
    sans.sort();
    sans.dedup();
    let (cert_pem, key_pem, der) = make_certificate(&sans)?;
    fsutil::atomic_write(&p.cert(), cert_pem.as_bytes(), 0o644)?;
    fsutil::atomic_write(&p.key(), key_pem.as_bytes(), 0o600)?;
    let token = auth::new_token();
    fsutil::atomic_write(
        &p.token_hash(),
        auth::hex(&auth::hash_token(&token)).as_bytes(),
        0o600,
    )?;
    let conf = PanelConf {
        listen: o.listen,
        port,
        sans,
        created_at: now_unix(),
    };
    fsutil::write_json_atomic(&p.conf(), &conf, 0o600)?;
    Ok(Initialised {
        conf,
        token,
        fingerprint: fingerprint(&der),
    })
}

pub fn reset_token(p: &Paths) -> Result<String> {
    load_conf(p)?;
    let token = auth::new_token();
    fsutil::atomic_write(
        &p.token_hash(),
        auth::hex(&auth::hash_token(&token)).as_bytes(),
        0o600,
    )?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_private_material_and_shows_the_token_only_once() {
        let d = std::env::temp_dir().join(format!("hrd-panel-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = Paths::new(&Layout::under(&d));
        let r = init(
            &p,
            InitOpts {
                listen: "127.0.0.1".parse().unwrap(),
                port: None,
                sans: vec!["203.0.113.5".into()],
                force: false,
            },
        )
        .unwrap();
        assert!((20000..60000).contains(&r.conf.port));
        assert!(
            r.conf.sans.contains(&"203.0.113.5".to_string())
                && r.conf.sans.contains(&"localhost".to_string())
        );
        assert_eq!(r.fingerprint.split(':').count(), 32);
        use std::os::unix::fs::PermissionsExt;
        for f in [p.key(), p.token_hash(), p.conf()] {
            assert_eq!(
                std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o600,
                "{}",
                f.display()
            );
        }
        assert_eq!(
            std::fs::metadata(&p.dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // Only the hash is on disk.
        let disk = std::fs::read_to_string(p.token_hash()).unwrap();
        assert!(!disk.contains(&r.token));
        assert_eq!(load_token_hash(&p).unwrap(), auth::hash_token(&r.token));
        assert!(init(
            &p,
            InitOpts {
                listen: "127.0.0.1".parse().unwrap(),
                port: None,
                sans: vec![],
                force: false
            }
        )
        .is_err());
        let t2 = reset_token(&p).unwrap();
        assert_ne!(t2, r.token);
        assert_eq!(load_token_hash(&p).unwrap(), auth::hash_token(&t2));
        std::fs::remove_dir_all(d).ok();
    }
}
