//! Routes. Every `/api` route needs a live session; every state-changing one also
//! needs the CSRF header and a same-origin `Origin`.
//!
//! `/api/call` forwards one control-protocol request to the daemon and returns its
//! answer: the panel adds no operation of its own beyond the three that need
//! something the socket protocol cannot carry (importing a WireGuard file,
//! uploading and importing an APK, fetching a screenshot as an image).

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use hrd_core::proto::Request;
use hrd_core::{Error, Result};

use crate::auth::{Auth, Login};
use crate::http::{self, Bad, Response};

pub trait Backend: Send + Sync {
    fn call(&self, req: Request) -> Result<Value>;
    fn import_runtime(
        &self,
        files: &[PathBuf],
        label: Option<String>,
        make_current: bool,
    ) -> Result<Value>;
    fn add_network(&self, spec: NetworkSpec) -> Result<Value>;
}

#[derive(serde::Deserialize)]
pub struct NetworkSpec {
    pub name: hrd_core::ids::NetworkName,
    pub config: String,
    #[serde(default)]
    pub dns: Vec<std::net::IpAddr>,
    pub exit_ip: Option<String>,
    pub stun_server: Option<String>,
    #[serde(default)]
    pub block_ipv6: bool,
    pub max_clients: Option<u32>,
}

pub struct Ctx {
    pub auth: Auth,
    pub backend: Arc<dyn Backend>,
    pub uploads: PathBuf,
    pub login_delay: Duration,
}

const INDEX: &str = include_str!("../assets/index.html");
const JS: &str = include_str!("../assets/app.js");
const CSS: &str = include_str!("../assets/app.css");
const MAX_JSON: u64 = 2 * 1024 * 1024;
const MAX_UPLOAD: u64 = 1 << 30;
const MAX_UPLOAD_FILES: usize = 4;

fn err(status: u16, code: &str, msg: &str) -> Response {
    Response::json(
        status,
        &json!({ "ok": false, "error": { "code": code, "message": msg } }),
    )
}

fn from_error(e: &Error) -> Response {
    let status = match e {
        Error::Invalid(_) | Error::Protocol(_) => 400,
        Error::NotFound(_) => 404,
        Error::Denied(_) => 403,
        _ => 200,
    };
    // Domain errors are answers, not transport failures: the page shows them.
    Response::json(
        if status == 200 { 200 } else { status },
        &json!({ "ok": false, "error": { "code": e.code(), "message": e.to_string() } }),
    )
}

fn same_origin(req: &http::Request) -> bool {
    let Some(host) = req.header("host") else {
        return false;
    };
    match req.header("origin") {
        Some(o) => o == format!("https://{host}"),
        None => false,
    }
}

fn session_cookie(cookie: &str) -> String {
    format!("hrd_session={cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200")
}

pub fn handle(ctx: &Ctx, req: &http::Request, stream: &mut dyn Read, remote: &str) -> Response {
    let (m, p) = (req.method.as_str(), req.path.as_str());
    match (m, p) {
        ("GET", "/") | ("GET", "/index.html") => {
            return Response {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: INDEX.as_bytes().to_vec(),
                extra: vec![],
            }
        }
        ("GET", "/app.js") => {
            return Response {
                status: 200,
                content_type: "text/javascript; charset=utf-8",
                body: JS.as_bytes().to_vec(),
                extra: vec![],
            }
        }
        ("GET", "/app.css") => {
            return Response {
                status: 200,
                content_type: "text/css; charset=utf-8",
                body: CSS.as_bytes().to_vec(),
                extra: vec![],
            }
        }
        ("GET", "/favicon.ico") => {
            return Response {
                status: 204,
                content_type: "image/x-icon",
                body: vec![],
                extra: vec![],
            }
        }
        ("POST", "/api/login") => return login(ctx, req, stream, remote),
        _ => {}
    }
    if !p.starts_with("/api/") {
        return err(404, "not_found", "no such page");
    }
    // Everything below needs a session.
    let Some(cookie) = req.cookie("hrd_session") else {
        return err(401, "auth_required", "sign in");
    };
    let Some(csrf) = ctx.auth.check(cookie) else {
        return err(401, "auth_required", "the session ended; sign in again");
    };
    if m != "GET" {
        if !same_origin(req) {
            return err(403, "denied", "cross-origin request refused");
        }
        if req
            .header("x-csrf")
            .map(|v| crate::auth::ct_eq(v.as_bytes(), csrf.as_bytes()))
            != Some(true)
        {
            return err(403, "denied", "missing or wrong CSRF header");
        }
    }
    match (m, p) {
        ("GET", "/api/session") => {
            Response::json(200, &json!({ "ok": true, "data": { "csrf": csrf } }))
        }
        ("POST", "/api/logout") => {
            ctx.auth.logout(cookie);
            Response::json(200, &json!({ "ok": true })).with(
                "Set-Cookie",
                "hrd_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
            )
        }
        ("POST", "/api/call") => call(ctx, req, stream),
        ("POST", "/api/network/add") => network_add(ctx, req, stream),
        ("POST", "/api/runtime/import") => runtime_import(ctx, req, stream),
        ("PUT", "/api/upload/runtime") => upload(ctx, req, stream),
        ("GET", _) if p.starts_with("/api/shot/") => shot(ctx, &p["/api/shot/".len()..]),
        _ => err(404, "not_found", "no such API route"),
    }
}

fn body_json(req: &http::Request, stream: &mut dyn Read) -> std::result::Result<Value, Response> {
    if !req
        .header("content-type")
        .is_some_and(|c| c.starts_with("application/json"))
    {
        return Err(err(400, "invalid", "Content-Type must be application/json"));
    }
    let mut s = stream;
    let body = http::read_body(req, &mut s, MAX_JSON).map_err(|b| match b {
        Bad::TooLarge => err(413, "invalid", "body too large"),
        _ => err(400, "invalid", "unreadable body"),
    })?;
    serde_json::from_slice(&body).map_err(|e| err(400, "invalid", &format!("not JSON: {e}")))
}

fn login(ctx: &Ctx, req: &http::Request, stream: &mut dyn Read, remote: &str) -> Response {
    if !same_origin(req) {
        return err(403, "denied", "cross-origin request refused");
    }
    let v = match body_json(req, stream) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let token = v.get("token").and_then(|t| t.as_str()).unwrap_or("");
    if token.len() > 256 {
        return err(400, "invalid", "that is not a token");
    }
    match ctx.auth.login(remote, token) {
        Login::Ok { cookie, csrf } => {
            Response::json(200, &json!({ "ok": true, "data": { "csrf": csrf } }))
                .with("Set-Cookie", &session_cookie(&cookie))
        }
        Login::Wrong => {
            std::thread::sleep(ctx.login_delay);
            err(401, "auth_required", "wrong token")
        }
        Login::Locked(s) => err(
            429,
            "denied",
            &format!("too many wrong tokens from this address; try again in {s} s"),
        ),
    }
}

/// Requests the panel will not forward: ones that stream, ones that need
/// descriptors (they have their own route), and ending the daemon (done over SSH).
fn forbidden(r: &Request) -> Option<&'static str> {
    match r {
        Request::Hello { .. } => Some("not needed"),
        Request::Subscribe | Request::Logs { follow: true, .. } => {
            Some("streams are not available in the panel; it polls")
        }
        Request::RuntimeImport { .. } => Some("use the upload route"),
        Request::Shutdown { .. } => Some("stopping the daemon is done from SSH"),
        _ => None,
    }
}

fn call(ctx: &Ctx, req: &http::Request, stream: &mut dyn Read) -> Response {
    let v = match body_json(req, stream) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cmd = v
        .get("cmd")
        .and_then(|c| c.as_str())
        .unwrap_or("?")
        .to_string();
    let request: Request = match serde_json::from_value(v) {
        Ok(r) => r,
        Err(e) => return err(400, "invalid", &format!("not a request: {e}")),
    };
    if let Some(why) = forbidden(&request) {
        return err(403, "denied", why);
    }
    eprintln!("<6>panel: call {cmd}");
    match ctx.backend.call(request) {
        Ok(data) => Response::json(200, &json!({ "ok": true, "data": data })),
        Err(e) => from_error(&e),
    }
}

fn network_add(ctx: &Ctx, req: &http::Request, stream: &mut dyn Read) -> Response {
    let v = match body_json(req, stream) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let spec: NetworkSpec = match serde_json::from_value(v) {
        Ok(s) => s,
        Err(e) => return err(400, "invalid", &format!("not a network: {e}")),
    };
    eprintln!("<6>panel: network add {}", spec.name);
    match ctx.backend.add_network(spec) {
        Ok(d) => Response::json(200, &json!({ "ok": true, "data": d })),
        Err(e) => from_error(&e),
    }
}

fn shot(ctx: &Ctx, name: &str) -> Response {
    let Ok(acct) = name.parse::<hrd_core::ids::AccountName>() else {
        return err(400, "invalid", "not an account name");
    };
    match ctx.backend.call(Request::LoginShot { name: acct }) {
        Ok(v) => match v
            .get("png_base64")
            .and_then(|p| p.as_str())
            .and_then(hrd_net::base64::decode)
        {
            Some(png) => Response {
                status: 200,
                content_type: "image/png",
                body: png,
                extra: vec![],
            },
            None => err(500, "internal", "bad screenshot"),
        },
        Err(e) => from_error(&e),
    }
}

fn valid_set(s: &str) -> bool {
    (8..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn clean_name(n: &str) -> String {
    let base = n.rsplit(['/', '\\']).next().unwrap_or("");
    let s: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(80)
        .collect();
    if s.is_empty() || s.starts_with('.') {
        "upload.apk".into()
    } else {
        s
    }
}

fn upload(ctx: &Ctx, req: &http::Request, stream: &mut dyn Read) -> Response {
    let (Some(set), Some(name)) = (req.query_param("set"), req.query_param("name")) else {
        return err(400, "invalid", "set and name are required");
    };
    if !valid_set(set) {
        return err(400, "invalid", "set must be 8-32 hex digits");
    }
    if req.content_length == 0 || req.content_length > MAX_UPLOAD {
        return err(413, "invalid", "a file is 1 byte to 1 GiB");
    }
    let dir = ctx.uploads.join(set);
    if hrd_core::fsutil::ensure_private_dir(&ctx.uploads, 0o700)
        .and_then(|_| hrd_core::fsutil::ensure_private_dir(&dir, 0o700))
        .is_err()
    {
        return err(500, "internal", "cannot prepare the upload directory");
    }
    let existing = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
    if existing >= MAX_UPLOAD_FILES {
        return err(400, "invalid", "at most 4 files per import");
    }
    let file = dir.join(format!(
        "{existing:02}-{}",
        clean_name(&percent_decode(name))
    ));
    let mut f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode_0600()
        .open(&file)
    {
        Ok(f) => f,
        Err(_) => return err(500, "internal", "cannot create the file"),
    };
    let mut left = req.content_length;
    let write = |b: &[u8], f: &mut std::fs::File| std::io::Write::write_all(f, b);
    let pre = req.body_prefix.len().min(left as usize);
    if write(&req.body_prefix[..pre], &mut f).is_err() {
        let _ = std::fs::remove_file(&file);
        return err(500, "internal", "write failed");
    }
    left -= pre as u64;
    let mut buf = vec![0u8; 256 * 1024];
    while left > 0 {
        let want = (left as usize).min(buf.len());
        match stream.read(&mut buf[..want]) {
            Ok(0) | Err(_) => {
                let _ = std::fs::remove_file(&file);
                return err(400, "invalid", "the upload was cut short");
            }
            Ok(n) => {
                if write(&buf[..n], &mut f).is_err() {
                    let _ = std::fs::remove_file(&file);
                    return err(500, "internal", "write failed");
                }
                left -= n as u64;
            }
        }
    }
    eprintln!("<6>panel: upload {} bytes", req.content_length);
    Response::json(
        200,
        &json!({ "ok": true, "data": { "set": set, "size": req.content_length } }),
    )
}

trait Mode0600 {
    fn mode_0600(&mut self) -> &mut Self;
}
impl Mode0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, 0o600)
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn runtime_import(ctx: &Ctx, req: &http::Request, stream: &mut dyn Read) -> Response {
    let v = match body_json(req, stream) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let set = v.get("set").and_then(|s| s.as_str()).unwrap_or("");
    if !valid_set(set) {
        return err(400, "invalid", "set must be 8-32 hex digits");
    }
    let dir = ctx.uploads.join(set);
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(d) => d.flatten().map(|e| e.path()).collect(),
        Err(_) => return err(404, "not_found", "no such upload"),
    };
    files.sort();
    if files.is_empty() {
        return err(400, "invalid", "nothing was uploaded");
    }
    let label = v.get("label").and_then(|l| l.as_str()).map(str::to_string);
    let keep = v
        .get("keep_current")
        .and_then(|k| k.as_bool())
        .unwrap_or(false);
    eprintln!("<6>panel: runtime import of {} file(s)", files.len());
    let r = ctx.backend.import_runtime(&files, label, !keep);
    let _ = std::fs::remove_dir_all(&dir);
    match r {
        Ok(d) => Response::json(200, &json!({ "ok": true, "data": d })),
        Err(e) => from_error(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{hash_token, new_token};
    use std::sync::Mutex;

    struct Mock {
        seen: Mutex<Vec<String>>,
    }
    impl Backend for Mock {
        fn call(&self, req: Request) -> Result<Value> {
            self.seen.lock().unwrap().push(format!("{req:?}"));
            Ok(json!(["ok"]))
        }
        fn import_runtime(&self, files: &[PathBuf], _l: Option<String>, _m: bool) -> Result<Value> {
            Ok(json!({ "files": files.len() }))
        }
        fn add_network(&self, s: NetworkSpec) -> Result<Value> {
            Ok(json!({ "name": s.name }))
        }
    }

    fn ctx(token: &str) -> (Ctx, Arc<Mock>) {
        let m = Arc::new(Mock {
            seen: Mutex::new(vec![]),
        });
        let up = std::env::temp_dir().join(format!(
            "hrd-panel-up-{}-{}",
            std::process::id(),
            new_token().len() + token.len()
        ));
        (
            Ctx {
                auth: Auth::new(hash_token(token)),
                backend: m.clone(),
                uploads: up,
                login_delay: Duration::from_millis(1),
            },
            m,
        )
    }

    fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> http::Request {
        let mut raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: panel:1\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (k, v) in headers {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str("\r\n");
        raw.push_str(body);
        http::read_request(&mut raw.as_bytes()).unwrap()
    }

    fn run(c: &Ctx, r: &http::Request) -> Response {
        handle(c, r, &mut std::io::empty(), "1.1.1.1")
    }

    fn login_ok(c: &Ctx, token: &str) -> (String, String) {
        let r = request(
            "POST",
            "/api/login",
            &[
                ("Origin", "https://panel:1"),
                ("Content-Type", "application/json"),
            ],
            &format!("{{\"token\":\"{token}\"}}"),
        );
        let resp = run(c, &r);
        assert_eq!(resp.status, 200);
        let cookie = resp
            .extra
            .iter()
            .find(|(k, _)| k == "Set-Cookie")
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let csrf = serde_json::from_slice::<Value>(&resp.body).unwrap()["data"]["csrf"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(resp.extra.iter().any(|(_, v)| v.contains("HttpOnly")
            && v.contains("Secure")
            && v.contains("SameSite=Strict")));
        (cookie, csrf)
    }

    #[test]
    fn the_page_is_public_and_the_api_is_not() {
        let t = new_token();
        let (c, _) = ctx(&t);
        assert_eq!(run(&c, &request("GET", "/", &[], "")).status, 200);
        assert_eq!(
            run(&c, &request("GET", "/api/session", &[], "")).status,
            401
        );
        assert_eq!(
            run(
                &c,
                &request(
                    "POST",
                    "/api/call",
                    &[("Content-Type", "application/json")],
                    "{}"
                )
            )
            .status,
            401
        );
        assert_eq!(run(&c, &request("GET", "/other", &[], "")).status, 404);
    }

    #[test]
    fn a_wrong_token_is_401_and_repeated_ones_lock_out() {
        let t = new_token();
        let (c, _) = ctx(&t);
        let bad = request(
            "POST",
            "/api/login",
            &[
                ("Origin", "https://panel:1"),
                ("Content-Type", "application/json"),
            ],
            "{\"token\":\"nope\"}",
        );
        for _ in 0..5 {
            assert_eq!(run(&c, &bad).status, 401);
        }
        assert_eq!(run(&c, &bad).status, 429);
    }

    #[test]
    fn a_state_changing_call_needs_the_session_the_csrf_header_and_a_same_origin_origin() {
        let t = new_token();
        let (c, m) = ctx(&t);
        let (cookie, csrf) = login_ok(&c, &t);
        let body = "{\"cmd\":\"account_list\"}";
        let h = |csrf: &str, origin: &str| {
            vec![
                ("Cookie", cookie.clone()),
                ("X-CSRF", csrf.to_string()),
                ("Origin", origin.to_string()),
                ("Content-Type", "application/json".to_string()),
            ]
        };
        let send = |hs: Vec<(&str, String)>| {
            let hs2: Vec<(&str, &str)> = hs.iter().map(|(k, v)| (*k, v.as_str())).collect();
            run(&c, &request("POST", "/api/call", &hs2, body)).status
        };
        assert_eq!(send(h("wrong", "https://panel:1")), 403, "wrong CSRF");
        assert_eq!(send(h(&csrf, "https://evil.example")), 403, "cross-origin");
        assert_eq!(
            send(vec![
                ("Cookie", cookie.clone()),
                ("X-CSRF", csrf.clone()),
                ("Content-Type", "application/json".into())
            ]),
            403,
            "no Origin"
        );
        assert!(
            m.seen.lock().unwrap().is_empty(),
            "nothing reached the daemon"
        );
        assert_eq!(send(h(&csrf, "https://panel:1")), 200);
        assert_eq!(m.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn requests_the_panel_will_not_forward_are_refused() {
        let t = new_token();
        let (c, m) = ctx(&t);
        let (cookie, csrf) = login_ok(&c, &t);
        for body in [
            "{\"cmd\":\"shutdown\",\"args\":{\"stop_instances\":null}}",
            "{\"cmd\":\"subscribe\"}",
            "{\"cmd\":\"logs\",\"args\":{\"id\":\"a\",\"lines\":1,\"follow\":true}}",
            "{\"cmd\":\"runtime_import\",\"args\":{\"files\":[],\"label\":null,\"make_current\":true}}",
        ] {
            let r = request("POST", "/api/call", &[("Cookie", &cookie), ("X-CSRF", &csrf), ("Origin", "https://panel:1"), ("Content-Type", "application/json")], body);
            assert_eq!(run(&c, &r).status, 403, "{body}");
        }
        let junk = request(
            "POST",
            "/api/call",
            &[
                ("Cookie", &cookie),
                ("X-CSRF", &csrf),
                ("Origin", "https://panel:1"),
                ("Content-Type", "application/json"),
            ],
            "{\"cmd\":\"rm_rf\"}",
        );
        assert_eq!(run(&c, &junk).status, 400);
        assert!(m.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn upload_names_are_cleaned_and_bounded() {
        assert_eq!(clean_name("../../etc/passwd"), "passwd");
        assert_eq!(clean_name("base apk.apk"), "baseapk.apk");
        assert_eq!(clean_name(""), "upload.apk");
        assert_eq!(clean_name(".hidden"), "upload.apk");
        assert_eq!(percent_decode("a%2Fb%20c%zz"), "a/b c%zz");
        assert!(valid_set("deadbeef01") && !valid_set("../x") && !valid_set("short"));
    }
}
