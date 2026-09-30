//! Keeping secrets out of places that get copied.
//!
//! Two tools. [`Secret`] is for a value the program holds on purpose: it is
//! overwritten when dropped and prints as a length, never as content, so that
//! a stray `{:?}` in a log line cannot leak it. [`scrub`] is for text that
//! came from somewhere else, such as a child's log, and removes the shapes of
//! credential this project knows about before the text is shown.

use std::borrow::Cow;
use std::fmt;

use zeroize::Zeroizing;

/// A secret string. No `Display`, no `Clone`, no serialisation: anything that
/// needs the content has to call [`Secret::expose`] and therefore be visible
/// in review.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(s: String) -> Self {
        Secret(Zeroizing::new(s))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<{} bytes>)", self.0.len())
    }
}

/// A secret that travels in a protocol message: it serialises as the plain
/// string (the message is the transport) but never prints, and is overwritten
/// when dropped.
#[derive(Clone, Default)]
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn new(s: String) -> Self {
        Passphrase(Zeroizing::new(s))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Passphrase(<{} bytes>)", self.0.len())
    }
}

impl serde::Serialize for Passphrase {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Passphrase {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Passphrase::new)
    }
}

const MASK: &str = "[REDACTED]";

/// Markers after which the rest of a token is a credential. The Roblox session
/// cookie starts with a fixed warning banner, which makes it findable without
/// knowing the cookie name it travelled under.
const COOKIE_BANNER: &str = "_|WARNING:-DO-NOT-SHARE-THIS";

/// Key names whose value, up to the end of the word, is masked.
const KEYS: &[&str] = &[
    ".ROBLOSECURITY",
    "ROBLOSECURITY",
    "PrivateKey",
    "PresharedKey",
    "password",
    "passphrase",
    "Authorization: Bearer",
    "x-csrf-token",
];

/// Remove credential-shaped text from one line.
pub fn scrub(line: &str) -> Cow<'_, str> {
    let mut out: Cow<'_, str> = Cow::Borrowed(line);

    // Every occurrence of the cookie banner, not only the first.
    let mut from = 0;
    while let Some(rel) = out[from..].find(COOKIE_BANNER) {
        let pos = from + rel;
        let end = out[pos..]
            .find(|c: char| c.is_whitespace() || c == ';' || c == '"' || c == '\'')
            .map(|n| pos + n)
            .unwrap_or(out.len());
        out = Cow::Owned(format!("{}{MASK}{}", &out[..pos], &out[end..]));
        from = pos + MASK.len();
    }

    for key in KEYS {
        let needle = key.to_ascii_lowercase();
        let mut search_from = 0;
        loop {
            // ASCII lowercasing keeps byte offsets, so `lower` indexes `out`.
            let lower = out.to_ascii_lowercase();
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let key_end = search_from + rel + needle.len();
            let rest = &lower[key_end..];
            let sep_len = rest
                .find(|c: char| !matches!(c, '=' | ':' | ' ' | '"' | '\''))
                .unwrap_or(rest.len());
            if sep_len == 0 {
                search_from = key_end;
                continue;
            }
            let value_start = key_end + sep_len;
            let value_end = out[value_start..]
                .find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\'')
                .map(|n| value_start + n)
                .unwrap_or(out.len());
            if value_end == value_start || out[value_start..value_end] == *MASK {
                search_from = key_end;
                continue;
            }
            out = Cow::Owned(format!(
                "{}{MASK}{}",
                &out[..value_start],
                &out[value_end..]
            ));
            search_from = value_start + MASK.len();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_never_prints_its_content() {
        let s = Secret::new("hunter2".into());
        assert_eq!(format!("{s:?}"), "Secret(<7 bytes>)");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn scrub_masks_the_cookie_banner_wherever_it_appears() {
        let line = "set-cookie: .ROBLOSECURITY=_|WARNING:-DO-NOT-SHARE-THIS.--abc123; Path=/";
        let out = scrub(line);
        assert!(!out.contains("abc123"), "{out}");
        assert!(out.contains(MASK));
    }

    #[test]
    fn scrub_masks_key_value_pairs() {
        assert!(
            !scrub("PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").contains("AAAA")
        );
        assert!(!scrub("password=hunter2 user=x").contains("hunter2"));
        assert!(scrub("password=hunter2 user=x").contains("user=x"));
        assert!(!scrub("Authorization: Bearer abcdef").contains("abcdef"));
    }

    #[test]
    fn scrub_masks_every_occurrence() {
        let out = scrub("password=aaa1 x password=bbb2 _|WARNING:-DO-NOT-SHARE-THIS.c1 _|WARNING:-DO-NOT-SHARE-THIS.c2");
        for leak in ["aaa1", "bbb2", "c1", "c2"] {
            assert!(!out.contains(leak), "{out}");
        }
    }

    #[test]
    fn scrub_leaves_ordinary_lines_alone() {
        let line = "[FLog::Output] setAssetFolder /data/app_assets/content";
        assert!(matches!(scrub(line), Cow::Borrowed(_)));
    }
}

#[cfg(test)]
mod passphrase_tests {
    use super::*;

    #[test]
    fn a_passphrase_round_trips_but_never_prints() {
        let p = Passphrase::new("hunter2".into());
        assert!(!format!("{p:?}").contains("hunter2"));
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "\"hunter2\"");
        let back: Passphrase = serde_json::from_str(&j).unwrap();
        assert_eq!(back.expose(), "hunter2");
        let req = crate::proto::Request::SecretsUnlock {
            passphrase: p,
            create: false,
        };
        assert!(!format!("{req:?}").contains("hunter2"));
    }
}
