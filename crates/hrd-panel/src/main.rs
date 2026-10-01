//! `hrd-panel`: an optional web panel for the fleet manager.
//!
//! Off unless you set it up. `init` picks a random port, makes a self-signed
//! certificate and a login token (shown once); `run` serves HTTPS and forwards
//! what the page asks to the daemon over its control socket, as the service user.
//! It has no authority of its own: whatever it does, `hrdctl` could do.

mod api;
mod auth;
mod http;
mod setup;

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use hrd_core::layout::Layout;
use hrd_core::proto::{ImportFile, NetworkView, Request};
use hrd_core::wire::Client;
use hrd_core::{fsutil, Error, Result};
use hrd_net::client::NetdClient;
use hrd_net::proto::{NetdRequest, NetworkSummary};

use crate::api::{Backend, Ctx, NetworkSpec};
use crate::setup::Paths;

const USAGE: &str = "\
usage: hrd-panel [--root DIR] COMMAND

  init --listen ADDRESS [--port N] [--san NAME]... [--force]
        Set the panel up: random port (unless --port), a self-signed certificate
        for the names given and ADDRESS, and a login token. The token is printed
        once; only its hash is kept. Run it as the service user:
        sudo -u cordial hrd-panel init --listen 127.0.0.1
  run   Serve the panel (this is what the systemd unit runs).
  show  Print the URL and the certificate fingerprint (never the token).
  reset-token
        Make a new token and print it once.

Serving HTTPS on an address reachable from the Internet exposes a login page: use
an address on your management tunnel and a firewall allow-list (docs/panel.md).
";

struct Real {
    socket: PathBuf,
    netd: NetdClient,
}

impl Real {
    fn client(&self, t: Duration) -> Result<Client> {
        Client::connect(&self.socket, "hrd-panel", Some(t))
    }
}

impl Backend for Real {
    fn call(&self, req: Request) -> Result<Value> {
        self.client(Duration::from_secs(120))?.call_value(req)
    }

    fn import_runtime(
        &self,
        files: &[PathBuf],
        label: Option<String>,
        make_current: bool,
    ) -> Result<Value> {
        let opened: Vec<std::fs::File> = files
            .iter()
            .map(|p| std::fs::File::open(p).map_err(|e| Error::io("open an upload", e)))
            .collect::<Result<_>>()?;
        let meta: Vec<ImportFile> = files
            .iter()
            .zip(&opened)
            .map(|(p, f)| {
                let n = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                // Strip the "NN-" ordering prefix the upload route added.
                ImportFile {
                    name: n.split_once('-').map(|x| x.1.to_string()).unwrap_or(n),
                    size: f.metadata().map(|m| m.len()).unwrap_or(0),
                }
            })
            .collect();
        let fds: Vec<_> = opened.iter().map(|f| f.as_fd()).collect();
        let mut c = self.client(Duration::from_secs(3600))?;
        c.call_with_fds(
            Request::RuntimeImport {
                files: meta,
                label,
                make_current,
            },
            &fds,
        )
    }

    fn helper_status(&self) -> Value {
        match self.netd.call_value(NetdRequest::Ping) {
            Ok(v) => serde_json::json!({
                "helper": true,
                "can_define": v.get("service_define").and_then(|b| b.as_bool()).unwrap_or(false),
            }),
            Err(e) => serde_json::json!({
                "helper": false,
                "can_define": false,
                "error": e.to_string(),
            }),
        }
    }

    fn add_network(&self, s: NetworkSpec) -> Result<Value> {
        // Everything that can be wrong is checked before the helper stores the key:
        // a refusal after that would leave a stored proxy the registry knows nothing of.
        let exit = match s.exit_ip {
            Some(e) if !e.is_empty() => Some(
                e.parse::<IpAddr>()
                    .map_err(|_| Error::invalid(format!("{e:?} is not an IP address")))?,
            ),
            _ => None,
        };
        let parsed = hrd_net::wg::parse(&s.config)?;
        if parsed.dns.is_empty() && s.dns.is_empty() {
            return Err(Error::invalid("the file has no DNS line and none was given: clients behind this proxy can only reach the tunnel, so they need a resolver behind it"));
        }
        // The helper and the registry would both take a second file under an existing
        // name as a replacement and keep only the new key and endpoint. From a form
        // that is a typo with a cost, so here a name that is taken is refused.
        let known: Vec<NetworkView> = self
            .client(Duration::from_secs(60))?
            .call(Request::NetworkList)?;
        if known.iter().any(|n| n.network.name == s.name) {
            return Err(Error::conflict(format!(
                "a proxy named {} already exists: pick another name (adding over it would replace its key and endpoint)",
                s.name
            )));
        }
        let summary: NetworkSummary = self.netd.call(NetdRequest::PutNetwork {
            name: s.name.clone(),
            config: s.config,
            dns: s.dns,
        })?;
        let net = hrd_core::model::Network {
            name: summary.name.clone(),
            backend: hrd_core::model::NetBackend::WireguardNetns,
            secret_ref: format!("netd:{}", summary.name),
            endpoint: summary.endpoint.clone(),
            peer_public_key: summary.peer_public_key.clone(),
            addresses: summary.addresses.iter().map(|a| a.to_string()).collect(),
            dns: summary.dns.clone(),
            allowed_ips: summary.allowed_ips.iter().map(|a| a.to_string()).collect(),
            mtu: summary.mtu,
            persistent_keepalive: summary.persistent_keepalive,
            ipv6: if s.block_ipv6 {
                hrd_core::model::Ipv6Policy::Block
            } else {
                hrd_core::model::Ipv6Policy::Auto
            },
            exit: hrd_core::model::ExitInfo {
                configured: exit,
                observed: None,
            },
            stun_server: s.stun_server.filter(|x| !x.is_empty()),
            max_clients: s.max_clients,
            created_at: 0,
        };
        let v: NetworkView =
            self.client(Duration::from_secs(60))?
                .call(Request::NetworkRegister {
                    network: Box::new(net),
                })?;
        Ok(
            serde_json::json!({ "network": v.network.name, "client_public_key": summary.client_public_key }),
        )
    }
}

fn tls_config(p: &Paths) -> Result<Arc<rustls::ServerConfig>> {
    let cert_pem = fsutil::read_limited(&p.cert(), 64 * 1024)?;
    let key_pem = fsutil::read_limited(&p.key(), 64 * 1024)?;
    fsutil::require_private_file(&p.key())?;
    let certs = rustls_pemfile_certs(&cert_pem)?;
    let key = rustls_pemfile_key(&key_pem)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Internal(format!("TLS versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::invalid(format!("the panel certificate and key do not match: {e}")))?;
    Ok(Arc::new(cfg))
}

/// Minimal PEM reading: the two object kinds rcgen writes, base64 between the
/// markers. Avoids a parsing crate for a file this program wrote itself.
fn pem_blocks(pem: &[u8], label: &str) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let (begin, end) = (
        format!("-----BEGIN {label}-----"),
        format!("-----END {label}-----"),
    );
    let mut out = Vec::new();
    let mut rest: &str = &text;
    while let Some(i) = rest.find(&begin) {
        let after = &rest[i + begin.len()..];
        let Some(j) = after.find(&end) else { break };
        let b64: String = after[..j].chars().filter(|c| !c.is_whitespace()).collect();
        let std_b64 = b64.replace('-', "+").replace('_', "/");
        if let Some(d) = hrd_net::base64::decode(&std_b64) {
            out.push(d);
        }
        rest = &after[j + end.len()..];
    }
    out
}

fn rustls_pemfile_certs(pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let v: Vec<_> = pem_blocks(pem, "CERTIFICATE")
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    if v.is_empty() {
        Err(Error::invalid("tls.crt holds no certificate"))
    } else {
        Ok(v)
    }
}

fn rustls_pemfile_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let der = pem_blocks(pem, "PRIVATE KEY")
        .into_iter()
        .next()
        .ok_or_else(|| Error::invalid("tls.key holds no PKCS#8 private key"))?;
    Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(der),
    ))
}

static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Connections one address may hold at once, and how long it has to finish
/// sending the request head. The per-read timeout alone lets a client that
/// sends a byte every few seconds hold a slot for ever.
const PER_IP: usize = 6;
const HEAD_DEADLINE: Duration = Duration::from_secs(20);

fn per_ip() -> &'static std::sync::Mutex<std::collections::HashMap<IpAddr, usize>> {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>> =
        std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

fn serve_one(ctx: &Ctx, tls: Arc<rustls::ServerConfig>, tcp: TcpStream) {
    let remote = tcp
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(60)));
    let Ok(conn) = rustls::ServerConnection::new(tls) else {
        return;
    };
    let watchdog = tcp.try_clone().ok();
    let head_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Some(w) = watchdog {
        let done = head_done.clone();
        std::thread::Builder::new()
            .name("panel-deadline".into())
            .spawn(move || {
                std::thread::sleep(HEAD_DEADLINE);
                if !done.load(Ordering::Relaxed) {
                    let _ = w.shutdown(std::net::Shutdown::Both);
                }
            })
            .ok();
    }
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    let head = http::read_request(&mut stream);
    head_done.store(true, Ordering::Relaxed);
    let req = match head {
        Ok(r) => r,
        Err(b) => {
            let status = match b {
                http::Bad::TooLarge => 431,
                http::Bad::Unsupported => 501,
                _ => 400,
            };
            let _ = http::write_response(&mut stream, &http::Response::text(status, "bad request"));
            return;
        }
    };
    let resp = api::handle(ctx, &req, &mut stream, &remote);
    // Path only: never the query, never a body, never a cookie.
    eprintln!(
        "<6>panel: {remote} {} {} -> {}",
        req.method, req.path, resp.status
    );
    let _ = http::write_response(&mut stream, &resp);
    let _ = stream.flush();
    stream.conn.send_close_notify();
    let _ = stream.flush();
}

fn run(layout: &Layout) -> Result<()> {
    let p = Paths::new(layout);
    let conf = setup::load_conf(&p)?;
    let hash = setup::load_token_hash(&p)?;
    let tls = tls_config(&p)?;
    let backend: Arc<dyn Backend> = Arc::new(Real {
        socket: layout.control_socket(),
        netd: NetdClient::new(layout.netd_socket()),
    });
    // Uploads left by an interrupted import are removed at start.
    let _ = fsutil::remove_dir_all_if_exists(&p.uploads());
    let ctx = Arc::new(Ctx {
        auth: {
            let p2 = Paths::new(layout);
            auth::Auth::new(hash).with_reload(move || setup::load_token_hash(&p2).ok())
        },
        backend,
        uploads: p.uploads(),
        login_delay: Duration::from_millis(1000),
    });
    let addr = SocketAddr::new(conf.listen, conf.port);
    let listener = TcpListener::bind(addr).map_err(|e| Error::io(format!("bind {addr}"), e))?;
    eprintln!("<6>panel: listening on https://{addr}/ (login token required)");
    if conf.listen.is_unspecified() {
        eprintln!("<4>panel: listening on every address; prefer an address on your management tunnel (docs/panel.md)");
    }
    for conn in listener.incoming() {
        let Ok(tcp) = conn else { continue };
        if ACTIVE.fetch_add(1, Ordering::Relaxed) >= 32 {
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
            continue;
        }
        let ip = tcp.peer_addr().map(|a| a.ip()).ok();
        if let Some(ip) = ip {
            let mut m = per_ip().lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(ip).or_insert(0);
            if *n >= PER_IP {
                ACTIVE.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            *n += 1;
        }
        let (ctx, tls) = (ctx.clone(), tls.clone());
        let spawned = std::thread::Builder::new()
            .name("panel-conn".into())
            .spawn(move || {
                serve_one(&ctx, tls, tcp);
                ACTIVE.fetch_sub(1, Ordering::Relaxed);
                if let Some(ip) = ip {
                    let mut m = per_ip().lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(n) = m.get_mut(&ip) {
                        *n -= 1;
                        if *n == 0 {
                            m.remove(&ip);
                        }
                    }
                }
            });
        if spawned.is_err() {
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
            if let Some(ip) = ip {
                let mut m = per_ip().lock().unwrap_or_else(|e| e.into_inner());
                if let Some(n) = m.get_mut(&ip) {
                    *n = n.saturating_sub(1);
                }
            }
        }
    }
    Ok(())
}

fn url(conf: &setup::PanelConf) -> String {
    let host = conf
        .sans
        .iter()
        .find(|s| s.parse::<IpAddr>().is_ok() && *s != "127.0.0.1")
        .cloned()
        .unwrap_or_else(|| conf.listen.to_string());
    format!("https://{host}:{}/", conf.port)
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = None;
    if args.first().map(String::as_str) == Some("--root") && args.len() >= 2 {
        root = Some(PathBuf::from(args.remove(1)));
        args.remove(0);
    }
    let layout = root
        .map(|r| Layout::under(&r))
        .unwrap_or_else(Layout::from_env);
    let p = Paths::new(&layout);
    let r: Result<()> = match args.first().map(String::as_str) {
        Some("init") => (|| {
            let (mut listen, mut port, mut sans, mut force) = (None, None, Vec::new(), false);
            let mut it = args.iter().skip(1);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--listen" => listen = Some(it.next().ok_or_else(|| Error::invalid("--listen needs an address"))?.parse::<IpAddr>().map_err(|_| Error::invalid("--listen wants an IP address"))?),
                    "--port" => port = Some(it.next().ok_or_else(|| Error::invalid("--port needs a number"))?.parse::<u16>().map_err(|_| Error::invalid("--port wants 1-65535"))?),
                    "--san" => sans.push(it.next().ok_or_else(|| Error::invalid("--san needs a name or address"))?.clone()),
                    "--force" => force = true,
                    o => return Err(Error::invalid(format!("unknown argument {o}"))),
                }
            }
            let listen = listen.ok_or_else(|| Error::invalid("--listen ADDRESS is required: say where the panel should be reachable (127.0.0.1 for this machine only)"))?;
            let i = setup::init(&p, setup::InitOpts { listen, port, sans, force })?;
            println!("Panel set up.\n  URL:                 {}\n  Login token:         {}\n  Certificate SHA-256: {}\n", url(&i.conf), i.token, i.fingerprint);
            println!("The token is shown only now; only its hash is stored. `hrd-panel reset-token` makes a new one.");
            println!("The certificate is self-signed: compare the fingerprint above with the one your browser shows before accepting it.");
            println!("Start it with: systemctl enable --now hrd-panel");
            Ok(())
        })(),
        Some("run") => run(&layout),
        Some("show") => setup::load_conf(&p).map(|c| {
            println!("URL: {}", url(&c));
            if let Ok(pem) = fsutil::read_limited(&p.cert(), 65536) {
                if let Some(d) = pem_blocks(&pem, "CERTIFICATE").first() {
                    println!("Certificate SHA-256: {}", setup::fingerprint(d));
                }
            }
        }),
        Some("reset-token") => setup::reset_token(&p).map(|t| println!("New login token (shown once): {t}\nThe running panel adopts it at the next login attempt and ends every session opened with the old one.")),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hrd-panel: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
