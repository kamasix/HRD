//! A deliberately small HTTP/1.1 server core: one request per connection,
//! bounded everything, no keep-alive, no chunked bodies, no upgrades.
//!
//! It exists because the panel needs a handful of routes with exact limits, and
//! a framework would bring an async runtime into a program whose whole job is to
//! stay small. What it refuses is listed in [`read_request`].

use std::io::{self, Read, Write};

pub const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    /// Bytes of the body already read together with the head.
    pub body_prefix: Vec<u8>,
    pub content_length: u64,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
    }

    pub fn query_param(&self, key: &str) -> Option<&str> {
        self.query
            .split('&')
            .filter_map(|p| p.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Bad {
    Io,
    TooLarge,
    Malformed,
    Unsupported,
}

/// Read the request line and headers. Refuses: heads over [`MAX_HEAD`], request
/// targets that are not an absolute path, `Transfer-Encoding` (chunked bodies
/// are not parsed, so a body is only accepted with `Content-Length`), duplicated
/// `Content-Length`, methods other than GET, POST and PUT, and any control
/// character in a header value.
pub fn read_request(r: &mut impl Read) -> Result<Request, Bad> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD {
            return Err(Bad::TooLarge);
        }
        let n = r.read(&mut chunk).map_err(|_| Bad::Io)?;
        if n == 0 {
            return Err(Bad::Io);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if end > MAX_HEAD {
        return Err(Bad::TooLarge);
    }
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| Bad::Malformed)?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or(Bad::Malformed)?;
    let mut parts = first.split(' ');
    let (method, target, version) = (
        parts.next().ok_or(Bad::Malformed)?,
        parts.next().ok_or(Bad::Malformed)?,
        parts.next().ok_or(Bad::Malformed)?,
    );
    if parts.next().is_some() || !(version == "HTTP/1.1" || version == "HTTP/1.0") {
        return Err(Bad::Malformed);
    }
    if !matches!(method, "GET" | "POST" | "PUT") {
        return Err(Bad::Unsupported);
    }
    if !target.starts_with('/')
        || target.starts_with("//")
        || target.bytes().any(|b| b <= b' ' || b == 0x7f)
    {
        return Err(Bad::Malformed);
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = Vec::new();
    let mut content_length: Option<u64> = None;
    for l in lines {
        let (k, v) = l.split_once(':').ok_or(Bad::Malformed)?;
        let v = v.trim();
        if k.is_empty()
            || k.bytes().any(|b| b <= b' ' || b == b':')
            || v.bytes().any(|b| b < b' ' && b != b'\t')
        {
            return Err(Bad::Malformed);
        }
        if k.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Bad::Unsupported);
        }
        if k.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(Bad::Malformed);
            }
            content_length = Some(v.parse().map_err(|_| Bad::Malformed)?);
        }
        headers.push((k.to_string(), v.to_string()));
    }
    let body_prefix = buf[end + 4..].to_vec();
    Ok(Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        content_length: content_length.unwrap_or(0),
        body_prefix,
    })
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Read exactly the declared body into memory, up to `max`.
pub fn read_body(req: &Request, r: &mut impl Read, max: u64) -> Result<Vec<u8>, Bad> {
    if req.content_length > max {
        return Err(Bad::TooLarge);
    }
    let mut body = req.body_prefix.clone();
    if body.len() as u64 > req.content_length {
        body.truncate(req.content_length as usize);
    }
    let mut chunk = [0u8; 8192];
    while (body.len() as u64) < req.content_length {
        let want = ((req.content_length - body.len() as u64) as usize).min(chunk.len());
        let n = r.read(&mut chunk[..want]).map_err(|_| Bad::Io)?;
        if n == 0 {
            return Err(Bad::Io);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(body)
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub extra: Vec<(String, String)>,
}

impl Response {
    pub fn json(status: u16, v: &serde_json::Value) -> Response {
        Response {
            status,
            content_type: "application/json",
            body: v.to_string().into_bytes(),
            extra: vec![],
        }
    }
    pub fn text(status: u16, t: &str) -> Response {
        Response {
            status,
            content_type: "text/plain; charset=utf-8",
            body: t.as_bytes().to_vec(),
            extra: vec![],
        }
    }
    pub fn with(mut self, k: &str, v: &str) -> Response {
        self.extra.push((k.to_string(), v.to_string()));
        self
    }
}

fn reason(s: u16) -> &'static str {
    match s {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Status",
    }
}

/// Headers every response carries. The page is self-contained (scripts and
/// styles only from this origin, nothing inline) and cannot be framed.
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Strict-Transport-Security", "max-age=31536000"),
];

pub fn write_response(w: &mut impl Write, r: &Response) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    for (k, v) in SECURITY_HEADERS {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    for (k, v) in &r.extra {
        // Header values are built by this program, never from request data, but
        // a line break in one would be response splitting: refuse outright.
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            return Err(io::Error::other("line break in a response header"));
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(&r.body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Request, Bad> {
        read_request(&mut s.as_bytes())
    }

    #[test]
    fn a_normal_request_is_read_with_its_query_and_cookie() {
        let r = parse("GET /api/shot/alt-1?x=1&y=2 HTTP/1.1\r\nHost: h\r\nCookie: a=b; hrd_session=tok\r\n\r\n").unwrap();
        assert_eq!(
            (r.method.as_str(), r.path.as_str(), r.query_param("y")),
            ("GET", "/api/shot/alt-1", Some("2"))
        );
        assert_eq!(r.cookie("hrd_session"), Some("tok"));
        assert_eq!(r.cookie("nope"), None);
    }

    #[test]
    fn dangerous_or_unsupported_requests_are_refused() {
        for (req, want) in [
            ("DELETE / HTTP/1.1\r\n\r\n", Bad::Unsupported),
            (
                "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                Bad::Unsupported,
            ),
            ("GET //evil HTTP/1.1\r\n\r\n", Bad::Malformed),
            ("GET http://x/ HTTP/1.1\r\n\r\n", Bad::Malformed),
            ("GET /a b HTTP/1.1\r\n\r\n", Bad::Malformed),
            ("GET / HTTP/2\r\n\r\n", Bad::Malformed),
            (
                "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
                Bad::Malformed,
            ),
            (
                "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
                Bad::Malformed,
            ),
            ("GET / HTTP/1.1\r\nX: a\x01b\r\n\r\n", Bad::Malformed),
            ("GET / HTTP/1.1\r\nNoColon\r\n\r\n", Bad::Malformed),
        ] {
            assert_eq!(parse(req).err(), Some(want), "{req:?}");
        }
        let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD + 10));
        assert_eq!(parse(&huge).err(), Some(Bad::TooLarge));
    }

    #[test]
    fn bodies_are_bounded_by_the_declared_length_and_the_cap() {
        let raw = "POST /api/call HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let mut s = raw.as_bytes();
        let r = read_request(&mut s).unwrap();
        assert_eq!(read_body(&r, &mut s, 100).unwrap(), b"hello");
        assert_eq!(read_body(&r, &mut s, 3).err(), Some(Bad::TooLarge));
        let short = "POST / HTTP/1.1\r\nContent-Length: 50\r\n\r\nabc";
        let mut s = short.as_bytes();
        let r = read_request(&mut s).unwrap();
        assert_eq!(
            read_body(&r, &mut s, 100).err(),
            Some(Bad::Io),
            "a truncated body is an error"
        );
    }

    #[test]
    fn responses_carry_the_security_headers_and_refuse_header_injection() {
        let mut out = Vec::new();
        write_response(&mut out, &Response::text(200, "hi")).unwrap();
        let t = String::from_utf8(out).unwrap();
        assert!(t.contains("Content-Security-Policy: default-src 'none'"));
        assert!(t.contains("frame-ancestors 'none'") && t.contains("nosniff"));
        let mut out = Vec::new();
        assert!(write_response(
            &mut out,
            &Response::text(200, "x").with("Set-Cookie", "a=b\r\nX: y")
        )
        .is_err());
    }
}
