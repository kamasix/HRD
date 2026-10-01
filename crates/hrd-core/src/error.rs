//! One error type for the whole fleet manager.
//!
//! The variants are chosen so that the CLI can turn them into an exit code and
//! the control protocol into a stable `code` string without either of them
//! matching on rendered text, which is how such mappings rot.

use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// The request itself is wrong: a bad name, an unsupported field, a value
    /// out of range. Retrying it unchanged will fail again.
    Invalid(String),
    /// Something the request names does not exist.
    NotFound(String),
    /// The request is fine but collides with current state: a name in use, a
    /// profile held by another instance, a group that is full.
    Conflict(String),
    /// A dependency is missing or not reachable: the daemon is not running, no
    /// runtime is installed, the secret store is locked, a tunnel is down.
    Unavailable(String),
    /// The caller is not allowed to do this.
    Denied(String),
    /// The account has no usable session and the operator has to provide one.
    AuthRequired(String),
    /// An I/O failure, with what was being attempted.
    Io { context: String, source: io::Error },
    /// The peer spoke something that is not the protocol.
    Protocol(String),
    /// A bug or an impossible state. Never the operator's fault.
    Internal(String),
}

impl Error {
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::Invalid(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Error::NotFound(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Error::Conflict(msg.into())
    }

    pub fn unavailable(msg: impl Into<String>) -> Self {
        Error::Unavailable(msg.into())
    }

    /// Stable machine-readable name, used on the wire and in JSON output.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Invalid(_) => "invalid",
            Error::NotFound(_) => "not_found",
            Error::Conflict(_) => "conflict",
            Error::Unavailable(_) => "unavailable",
            Error::Denied(_) => "denied",
            Error::AuthRequired(_) => "auth_required",
            Error::Io { .. } => "io",
            Error::Protocol(_) => "protocol",
            Error::Internal(_) => "internal",
        }
    }

    /// Process exit status for `hrdctl`. Documented in `--help` and in
    /// docs/operations.md; scripts are entitled to rely on these.
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Internal(_) | Error::Io { .. } | Error::Protocol(_) => 1,
            Error::Invalid(_) => 2,
            Error::NotFound(_) => 3,
            Error::Conflict(_) => 4,
            Error::Unavailable(_) => 5,
            Error::AuthRequired(_) => 6,
            Error::Denied(_) => 7,
        }
    }

    /// Rebuild an error from the `code` and message of a protocol response, so
    /// that a failure survives the trip from the daemon to the CLI with its
    /// exit status intact.
    pub fn from_wire(code: &str, message: String) -> Self {
        match code {
            "invalid" => Error::Invalid(message),
            "not_found" => Error::NotFound(message),
            "conflict" => Error::Conflict(message),
            "unavailable" => Error::Unavailable(message),
            "denied" => Error::Denied(message),
            "auth_required" => Error::AuthRequired(message),
            "protocol" => Error::Protocol(message),
            _ => Error::Internal(message),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(m)
            | Error::NotFound(m)
            | Error::Conflict(m)
            | Error::Unavailable(m)
            | Error::Denied(m)
            | Error::AuthRequired(m)
            | Error::Protocol(m)
            | Error::Internal(m) => f.write_str(m),
            Error::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io {
            context: "I/O error".into(),
            source: e,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Protocol(format!("malformed JSON: {e}"))
    }
}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Error::Io {
            context: "system call".into(),
            source: io::Error::from_raw_os_error(e.raw_os_error()),
        }
    }
}

/// Attach context to an `io::Result` on its way into [`Error`].
pub trait IoContext<T> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::io(what(), e))
    }
}

impl<T> IoContext<T> for std::result::Result<T, rustix::io::Errno> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::io(what(), io::Error::from_raw_os_error(e.raw_os_error())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_round_trips_through_the_wire_form() {
        let samples = [
            Error::invalid("a"),
            Error::not_found("b"),
            Error::conflict("c"),
            Error::unavailable("d"),
            Error::Denied("e".into()),
            Error::AuthRequired("f".into()),
            Error::Protocol("g".into()),
        ];
        for e in samples {
            let back = Error::from_wire(e.code(), e.to_string());
            assert_eq!(back.code(), e.code());
            assert_eq!(back.exit_code(), e.exit_code());
        }
    }

    #[test]
    fn exit_codes_match_the_documented_table() {
        assert_eq!(Error::AuthRequired("x".into()).exit_code(), 6);
        assert_eq!(Error::Denied("x".into()).exit_code(), 7);
        assert_eq!(Error::Unavailable("x".into()).exit_code(), 5);
    }

    #[test]
    fn exit_codes_are_distinct_where_a_script_would_branch_on_them() {
        let codes: Vec<u8> = [
            Error::invalid(""),
            Error::not_found(""),
            Error::conflict(""),
            Error::unavailable(""),
            Error::Denied(String::new()),
            Error::AuthRequired(String::new()),
        ]
        .iter()
        .map(|e| e.exit_code())
        .collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
        assert!(!codes.contains(&0));
    }
}
