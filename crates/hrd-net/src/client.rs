//! Talking to `hrd-netd` from the unprivileged side.
//!
//! One connection per call. The helper is restarted independently of the
//! manager (an upgrade, a crash), and a connection that outlives it would fail
//! at the worst moment; connecting costs a few microseconds against a local
//! socket.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::de::DeserializeOwned;

use hrd_core::proto::{ResponseBody, ResponseEnvelope};
use hrd_core::wire::Conn;
use hrd_core::{Error, Result};

use crate::proto::{NetdEnvelope, NetdRequest};

#[derive(Debug, Clone)]
pub struct NetdClient {
    path: PathBuf,
    timeout: Duration,
}

impl NetdClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        NetdClient {
            path: path.into(),
            // Applying a proxy group runs several commands and resolves an endpoint;
            // a minute covers a slow resolver without hiding a hung helper.
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn call_value(&self, req: NetdRequest) -> Result<serde_json::Value> {
        let stream = UnixStream::connect(&self.path).map_err(|e| {
            let hint = match e.kind() {
                std::io::ErrorKind::NotFound => {
                    " (is hrd-netd running? `systemctl status hrd-netd`)"
                }
                std::io::ErrorKind::PermissionDenied => {
                    " (your user needs to be in the service group)"
                }
                _ => "",
            };
            Error::unavailable(format!(
                "cannot reach the network helper at {}: {e}{hint}",
                self.path.display()
            ))
        })?;
        // The helper runs as root. A socket served by anyone else is not it,
        // and what this client sends (WireGuard configurations) must not go there.
        let peer = rustix::net::sockopt::socket_peercred(&stream)
            .map_err(|e| Error::io("read the helper's credentials", std::io::Error::from(e)))?;
        let (peer, me) = (peer.uid.as_raw(), rustix::process::geteuid().as_raw());
        if peer != 0 && peer != me {
            return Err(Error::Denied(format!(
                "the socket at {} is served by uid {peer}, not by root: refusing to talk to it",
                self.path.display()
            )));
        }
        let mut conn = Conn::new(stream);
        conn.set_timeouts(Some(self.timeout), Some(Duration::from_secs(10)))?;
        conn.send_json(&NetdEnvelope { id: 1, req })?;
        let line = conn.read_line()?.ok_or_else(|| {
            Error::unavailable("the network helper closed the connection without answering")
        })?;
        let reply: ResponseEnvelope = serde_json::from_slice(&line).map_err(|e| {
            Error::Protocol(format!("unreadable reply from the network helper: {e}"))
        })?;
        match reply.body {
            ResponseBody::Ok { data, .. } => Ok(data),
            ResponseBody::Err { error, .. } => Err(Error::from_wire(&error.code, error.message)),
            _ => Err(Error::Protocol(
                "the network helper sent a stream reply".into(),
            )),
        }
    }

    pub fn call<T: DeserializeOwned>(&self, req: NetdRequest) -> Result<T> {
        let v = self.call_value(req)?;
        serde_json::from_value(v).map_err(|e| {
            Error::Protocol(format!(
                "the network helper's answer has an unexpected shape: {e}"
            ))
        })
    }

    pub fn ping(&self) -> Result<()> {
        self.call_value(NetdRequest::Ping).map(|_| ())
    }
}
