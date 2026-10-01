//! Validated names.
//!
//! Every operator-chosen name ends up somewhere it could do harm if it were
//! not checked: a path component, a cgroup directory, a network namespace
//! file, a keyring attribute, a process argument. So the rule is not "escape
//! it where it is used" but "refuse anything that would need escaping", once,
//! at the edge, and carry the proof in the type.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

fn check(
    kind: &str,
    s: &str,
    max: usize,
    first: impl Fn(char) -> bool,
    rest: impl Fn(char) -> bool,
) -> Result<()> {
    if s.is_empty() {
        return Err(Error::invalid(format!("{kind} name is empty")));
    }
    if s.len() > max {
        return Err(Error::invalid(format!(
            "{kind} name {s:?} is longer than {max} characters"
        )));
    }
    let mut chars = s.chars();
    let c0 = chars.next().unwrap_or('\0');
    if !first(c0) || !chars.all(&rest) {
        return Err(Error::invalid(format!(
            "{kind} name {s:?} is not allowed: use lowercase letters, digits and '-' (and '_' for accounts), starting with a {}",
            if kind == "account" { "letter or digit" } else { "letter" }
        )));
    }
    if s.ends_with('-') || s.ends_with('_') {
        return Err(Error::invalid(format!(
            "{kind} name {s:?} must not end with a separator"
        )));
    }
    Ok(())
}

macro_rules! name_type {
    ($(#[$m:meta])* $ty:ident, $kind:literal, $max:expr, $first:expr, $rest:expr) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $ty(String);

        impl $ty {
            pub const MAX_LEN: usize = $max;

            pub fn new(s: impl Into<String>) -> Result<Self> {
                let s = s.into();
                check($kind, &s, $max, $first, $rest)?;
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($ty), self.0)
            }
        }

        impl std::str::FromStr for $ty {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                Self::new(s)
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

name_type!(
    /// An account, which is also the name of its profile and of its one
    /// instance slot. Used as a path component and inside cgroup names.
    ///
    /// At most 32 characters, and the number is not arbitrary: the client binds
    /// a Unix socket at `<state>/acct/<name>/data/cordial/profiles/default/live/settings.sock`,
    /// and `sun_path` holds 107 bytes. With the packaged state directory that
    /// leaves room for exactly 33.
    AccountName,
    "account",
    32,
    |c: char| c.is_ascii_lowercase() || c.is_ascii_digit(),
    |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'
);

name_type!(
    /// A named set of proxy groups that join the same place. Purely
    /// organisational: it is never a path, a namespace or a cgroup.
    GroupName,
    "group",
    24,
    |c: char| c.is_ascii_lowercase(),
    |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
);

name_type!(
    /// Accounts that leave through one proxy: one tunnel, one network
    /// namespace. It names the namespace file, so it has the same shape as a
    /// network name and, unlike a group name, is unique across every group.
    ProxyGroupName,
    "proxy group",
    24,
    |c: char| c.is_ascii_lowercase(),
    |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
);

name_type!(
    /// A network definition (one tunnel). Also names the namespace file, so it
    /// has the same shape as a group name.
    NetworkName,
    "network",
    24,
    |c: char| c.is_ascii_lowercase(),
    |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
);

/// A Roblox place id as typed by the operator.
///
/// Stored as a number: it is interpolated into a launch URL later, and a
/// number cannot carry a `&` or a `/` with it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlaceId(u64);

impl PlaceId {
    pub fn new(n: u64) -> Result<Self> {
        // Roblox ids are positive and comfortably inside 2^53, the largest
        // integer a JSON consumer (including Roblox's own web APIs) holds
        // exactly.
        if n == 0 || n > 9_007_199_254_740_991 {
            return Err(Error::invalid(format!("place id {n} is out of range")));
        }
        Ok(Self(n))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::str::FromStr for PlaceId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() || s.len() > 16 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::invalid(format!(
                "place id {s:?} must be a positive integer"
            )));
        }
        Self::new(
            s.parse::<u64>()
                .map_err(|_| Error::invalid(format!("place id {s:?} is not a number")))?,
        )
    }
}

impl fmt::Display for PlaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A free-form operator label such as `batch-2` or `region:de`.
pub fn check_label(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 32 {
        return Err(Error::invalid(format!(
            "label {s:?} must be 1-32 characters"
        )));
    }
    let ok = s.chars().enumerate().all(|(i, c)| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || (i > 0 && matches!(c, '-' | '_' | '.' | ':'))
    });
    if !ok {
        return Err(Error::invalid(format!(
            "label {s:?} must be lowercase letters and digits, with '-', '_', '.' or ':' after the first character"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for s in ["alt-001", "a", "main_acct", "0", "x".repeat(32).as_str()] {
            AccountName::new(s).unwrap_or_else(|e| panic!("{s}: {e}"));
        }
        for s in ["g01", "de-1", "exit-germany-a"] {
            GroupName::new(s).unwrap();
            ProxyGroupName::new(s).unwrap();
            NetworkName::new(s).unwrap();
        }
    }

    #[test]
    fn refuses_anything_that_could_escape_a_path_or_an_argument() {
        for s in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a b",
            "A",
            "a\n",
            "a\0",
            "-a",
            "_a",
            "a-",
            "a.",
            "a;b",
            "a$b",
            "a`b",
            "é",
            "a\\b",
            "--profile",
        ] {
            assert!(
                AccountName::new(s).is_err(),
                "account {s:?} must be refused"
            );
        }
        for s in [
            "",
            "1g",
            "-g",
            "g_1",
            "G",
            "g.1",
            "g/1",
            "g-",
            "a".repeat(25).as_str(),
        ] {
            assert!(GroupName::new(s).is_err(), "group {s:?} must be refused");
            assert!(
                ProxyGroupName::new(s).is_err(),
                "proxy group {s:?} must be refused"
            );
            assert!(
                NetworkName::new(s).is_err(),
                "network {s:?} must be refused"
            );
        }
    }

    #[test]
    fn serde_enforces_the_same_rules() {
        assert!(serde_json::from_str::<AccountName>("\"ok-1\"").is_ok());
        assert!(serde_json::from_str::<AccountName>("\"../etc\"").is_err());
        let json = serde_json::to_string(&AccountName::new("a1").unwrap()).unwrap();
        assert_eq!(json, "\"a1\"");
    }

    #[test]
    fn place_ids_are_numbers_only() {
        assert_eq!("920587237".parse::<PlaceId>().unwrap().get(), 920587237);
        for s in [
            "",
            "0",
            "-1",
            "12a",
            "1 2",
            "1;2",
            "99999999999999999",
            "0x10",
            "+5",
        ] {
            assert!(s.parse::<PlaceId>().is_err(), "{s:?}");
        }
    }

    #[test]
    fn labels() {
        for s in ["batch-2", "region:de", "a", "x.y_z"] {
            check_label(s).unwrap();
        }
        for s in ["", "-a", "A", "a b", "a/b", &"x".repeat(33)] {
            assert!(check_label(s).is_err(), "{s:?}");
        }
    }
}
