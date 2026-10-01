//! Who may use the panel: one secret token, sessions, and a limit on guessing.
//!
//! The token is 32 random bytes shown once by `hrd-panel init`; only its
//! SHA-256 is stored. Logging in trades it for a session cookie (HttpOnly,
//! Secure, SameSite=Strict) and a CSRF value the page keeps in memory and sends as
//! a header; both are random and live on the server. Failures are counted per
//! remote address and, past a few, locked out for a while, and the answer to a
//! wrong token is delayed, so guessing costs time and cannot be parallelised for
//! free.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    let mut filled = 0;
    while filled < N {
        // getrandom(2) may return fewer bytes than asked for.
        match rustix::rand::getrandom(&mut b[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => panic!("the system has no random source: {e}"),
        }
    }
    b
}

pub fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(A[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            out.push(A[n as usize & 63] as char);
        }
    }
    out
}

pub fn new_token() -> String {
    b64url(&random_bytes::<32>())
}

pub fn hash_token(t: &str) -> [u8; 32] {
    Sha256::digest(t.as_bytes()).into()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

const FAILS_BEFORE_LOCK: u32 = 5;
const LOCK: Duration = Duration::from_secs(600);
const WINDOW: Duration = Duration::from_secs(600);
const SESSION_MAX: Duration = Duration::from_secs(12 * 3600);
const SESSION_IDLE: Duration = Duration::from_secs(2 * 3600);
const MAX_SESSIONS: usize = 16;

struct Session {
    csrf: String,
    created: Instant,
    last: Instant,
}

#[derive(Default)]
struct Fails {
    count: u32,
    first: Option<Instant>,
    locked_until: Option<Instant>,
}

type Reload = Box<dyn Fn() -> Option<[u8; 32]> + Send + Sync>;

pub struct Auth {
    token_hash: Mutex<[u8; 32]>,
    /// Reads the stored hash again at each login, so that `reset-token` takes
    /// effect without restarting the panel.
    reload: Option<Reload>,
    sessions: Mutex<HashMap<String, Session>>,
    fails: Mutex<HashMap<String, Fails>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Login {
    Ok { cookie: String, csrf: String },
    Wrong,
    Locked(u64),
}

impl Auth {
    pub fn new(token_hash: [u8; 32]) -> Auth {
        Auth {
            token_hash: Mutex::new(token_hash),
            reload: None,
            sessions: Mutex::new(HashMap::new()),
            fails: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_reload(mut self, f: impl Fn() -> Option<[u8; 32]> + Send + Sync + 'static) -> Auth {
        self.reload = Some(Box::new(f));
        self
    }

    /// Adopt a replaced token: the old one stops working and every session
    /// opened with it ends.
    fn refresh_token(&self) {
        let Some(new) = self.reload.as_ref().and_then(|f| f()) else {
            return;
        };
        let mut cur = self.token_hash.lock().unwrap_or_else(|e| e.into_inner());
        if *cur != new {
            *cur = new;
            self.sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }
    }

    pub fn login(&self, who: &str, token: &str) -> Login {
        let now = Instant::now();
        {
            let mut f = self.fails.lock().unwrap_or_else(|e| e.into_inner());
            let e = f.entry(who.to_string()).or_default();
            if let Some(until) = e.locked_until {
                if now < until {
                    return Login::Locked((until - now).as_secs() + 1);
                }
                *e = Fails::default();
            }
        }
        self.refresh_token();
        let current = *self.token_hash.lock().unwrap_or_else(|e| e.into_inner());
        if ct_eq(&hash_token(token), &current) {
            self.fails
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(who);
            let cookie = new_token();
            let csrf = new_token();
            let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            s.retain(|_, v| {
                now.duration_since(v.created) < SESSION_MAX
                    && now.duration_since(v.last) < SESSION_IDLE
            });
            if s.len() >= MAX_SESSIONS {
                if let Some(oldest) = s.iter().min_by_key(|(_, v)| v.last).map(|(k, _)| k.clone()) {
                    s.remove(&oldest);
                }
            }
            s.insert(
                cookie.clone(),
                Session {
                    csrf: csrf.clone(),
                    created: now,
                    last: now,
                },
            );
            return Login::Ok { cookie, csrf };
        }
        let mut f = self.fails.lock().unwrap_or_else(|e| e.into_inner());
        if f.len() > 4096 {
            f.retain(|_, v| v.locked_until.is_some_and(|u| u > now));
        }
        let e = f.entry(who.to_string()).or_default();
        if e.first.is_none_or(|t| now.duration_since(t) > WINDOW) {
            *e = Fails {
                count: 0,
                first: Some(now),
                locked_until: None,
            };
        }
        e.count += 1;
        if e.count >= FAILS_BEFORE_LOCK {
            e.locked_until = Some(now + LOCK);
        }
        Login::Wrong
    }

    /// The CSRF value of a live session, refreshing its idle timer.
    pub fn check(&self, cookie: &str) -> Option<String> {
        let now = Instant::now();
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let ok = s.get(cookie).is_some_and(|v| {
            now.duration_since(v.created) < SESSION_MAX && now.duration_since(v.last) < SESSION_IDLE
        });
        if !ok {
            s.remove(cookie);
            return None;
        }
        let v = s.get_mut(cookie)?;
        v.last = now;
        Some(v.csrf.clone())
    }

    pub fn logout(&self, cookie: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(cookie);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_random_and_url_safe() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        assert_eq!(b64url(b"\xff\xfe\xfd"), "__79");
        assert_eq!(b64url(b"f"), "Zg");
    }

    #[test]
    fn the_right_token_gives_a_session_and_the_wrong_one_does_not() {
        let t = new_token();
        let a = Auth::new(hash_token(&t));
        assert_eq!(a.login("1.2.3.4", "wrong"), Login::Wrong);
        let Login::Ok { cookie, csrf } = a.login("1.2.3.4", &t) else {
            panic!("should log in")
        };
        assert_eq!(a.check(&cookie).as_deref(), Some(csrf.as_str()));
        assert_eq!(a.check("not-a-cookie"), None);
        a.logout(&cookie);
        assert_eq!(a.check(&cookie), None);
    }

    #[test]
    fn guessing_is_locked_out_per_address_even_for_the_right_token_afterwards() {
        let t = new_token();
        let a = Auth::new(hash_token(&t));
        for _ in 0..FAILS_BEFORE_LOCK {
            assert_eq!(a.login("9.9.9.9", "nope"), Login::Wrong);
        }
        assert!(
            matches!(a.login("9.9.9.9", &t), Login::Locked(_)),
            "the lock holds against the right token too"
        );
        assert!(
            matches!(a.login("8.8.8.8", &t), Login::Ok { .. }),
            "another address is unaffected"
        );
    }

    #[test]
    fn the_session_table_is_bounded() {
        let t = new_token();
        let a = Auth::new(hash_token(&t));
        let cookies: Vec<String> = (0..MAX_SESSIONS + 4)
            .map(|_| match a.login("x", &t) {
                Login::Ok { cookie, .. } => cookie,
                _ => panic!(),
            })
            .collect();
        assert!(
            a.check(&cookies[0]).is_none(),
            "the oldest session was dropped"
        );
        assert!(a.check(cookies.last().unwrap()).is_some());
    }

    #[test]
    fn comparison_is_exact() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
    }
}
