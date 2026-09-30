//! Both ends of the control socket: a line reader that also collects passed
//! file descriptors, and the client built on it.
//!
//! A request that carries files (`runtime_import`) is sent as one `sendmsg`
//! whose ancillary data holds the descriptors. The receiver must therefore read
//! with `recvmsg` *every* time, or a descriptor attached to a message it read
//! with a plain `read` is silently closed by the kernel. [`Conn`] does, keeps
//! the descriptors in a queue, and hands them out when a request says how many
//! it expects. Descriptors arrive close-on-exec.

use std::collections::VecDeque;
use std::io::{self, IoSlice, IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::proto::{
    encode_line, Request, RequestEnvelope, ResponseBody, ResponseEnvelope, MAX_LINE,
    PROTOCOL_VERSION,
};

/// Most descriptors one message may carry. A request names how many it expects;
/// anything beyond the limit is closed rather than queued.
pub const MAX_FDS: usize = 16;

pub struct Conn {
    stream: UnixStream,
    buf: Vec<u8>,
    fds: VecDeque<OwnedFd>,
    eof: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl Conn {
    pub fn new(stream: UnixStream) -> Conn {
        Conn {
            stream,
            buf: Vec::new(),
            fds: VecDeque::new(),
            eof: false,
        }
    }

    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

    pub fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> Result<()> {
        self.stream
            .set_read_timeout(read)
            .and_then(|_| self.stream.set_write_timeout(write))
            .map_err(|e| Error::io("set socket timeout", e))
    }

    pub fn peer_cred(&self) -> Result<PeerCred> {
        let c = rustix::net::sockopt::socket_peercred(&self.stream)
            .map_err(|e| Error::io("SO_PEERCRED", io::Error::from(e)))?;
        Ok(PeerCred {
            uid: c.uid.as_raw(),
            gid: c.gid.as_raw(),
            pid: c.pid.as_raw_nonzero().get() as u32,
        })
    }

    fn fill(&mut self) -> Result<()> {
        let mut data = [0u8; 16 * 1024];
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
        let mut anc = RecvAncillaryBuffer::new(&mut space);
        let n = {
            let mut iov = [IoSliceMut::new(&mut data)];
            match recvmsg(&self.stream, &mut iov, &mut anc, RecvFlags::CMSG_CLOEXEC) {
                Ok(r) => r.bytes,
                Err(e) => {
                    let e = io::Error::from(e);
                    return match e.kind() {
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Err(Error::io(
                            "read from the control socket timed out",
                            io::Error::from(io::ErrorKind::TimedOut),
                        )),
                        _ => Err(Error::io("read from the control socket", e)),
                    };
                }
            }
        };
        for msg in anc.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = msg {
                for fd in fds {
                    if self.fds.len() < MAX_FDS {
                        self.fds.push_back(fd);
                    }
                    // else: dropped, which closes it.
                }
            }
        }
        if n == 0 {
            self.eof = true;
        }
        self.buf.extend_from_slice(&data[..n]);
        Ok(())
    }

    /// The next line without its newline, or `None` at a clean end of stream.
    /// A line longer than [`MAX_LINE`] is a protocol error, not something to
    /// buffer without bound.
    pub fn read_line(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            if self.buf.len() >= MAX_LINE {
                return Err(Error::Protocol(format!(
                    "a line longer than {MAX_LINE} bytes"
                )));
            }
            if self.eof {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(Error::Protocol(
                        "the stream ended in the middle of a line".into(),
                    ))
                };
            }
            self.fill()?;
        }
    }

    /// Descriptors received so far that have not been claimed.
    pub fn pending_fds(&self) -> usize {
        self.fds.len()
    }

    /// Claim exactly `n` descriptors. The request said it would send them with
    /// the same message, so they have all arrived by the time its line has.
    pub fn take_fds(&mut self, n: usize) -> Result<Vec<OwnedFd>> {
        if n > MAX_FDS {
            return Err(Error::invalid(format!(
                "a request may carry at most {MAX_FDS} files"
            )));
        }
        if self.fds.len() < n {
            return Err(Error::Protocol(format!(
                "the request names {n} files and {} arrived",
                self.fds.len()
            )));
        }
        Ok(self.fds.drain(..n).collect())
    }

    /// Discard descriptors a request did not ask for.
    pub fn drop_unclaimed_fds(&mut self) {
        self.fds.clear();
    }

    pub fn write_line(&mut self, line: &[u8]) -> Result<()> {
        self.stream
            .write_all(line)
            .and_then(|_| self.stream.flush())
            .map_err(|e| Error::io("write to the control socket", e))
    }

    pub fn send_json<T: serde::Serialize>(&mut self, v: &T) -> Result<()> {
        let line = encode_line(v)?;
        self.write_line(&line)
    }

    /// Send one line with `fds` attached to it.
    pub fn send_with_fds(&mut self, line: &[u8], fds: &[BorrowedFd<'_>]) -> Result<()> {
        if fds.len() > MAX_FDS {
            return Err(Error::invalid(format!(
                "at most {MAX_FDS} files per request"
            )));
        }
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
        let mut anc = SendAncillaryBuffer::new(&mut space);
        let msg = SendAncillaryMessage::ScmRights(fds);
        if !anc.push(msg) {
            return Err(Error::Internal("ancillary buffer too small".into()));
        }
        let iov = [IoSlice::new(line)];
        let sent = sendmsg(&self.stream, &iov, &mut anc, SendFlags::empty())
            .map_err(|e| Error::io("send to the control socket", io::Error::from(e)))?;
        // The descriptors went with the first byte; the rest is ordinary data.
        if sent < line.len() {
            self.write_line(&line[sent..])?;
        }
        Ok(())
    }
}

/// A connected client session.
pub struct Client {
    conn: Conn,
    next_id: u64,
    pub server_version: String,
}

impl Client {
    /// Connect and say hello. `timeout` bounds every later read.
    pub fn connect(path: &Path, who: &str, timeout: Option<Duration>) -> Result<Client> {
        let stream = UnixStream::connect(path).map_err(|e| {
            let hint = match e.kind() {
                io::ErrorKind::NotFound => " (is cordiald running? `systemctl status cordiald`)",
                io::ErrorKind::PermissionDenied => {
                    " (your user needs to be in the service group: see docs/install.md)"
                }
                io::ErrorKind::ConnectionRefused => " (the socket exists but nothing listens)",
                _ => "",
            };
            Error::unavailable(format!("cannot connect to {}: {e}{hint}", path.display()))
        })?;
        let conn = Conn::new(stream);
        conn.set_timeouts(timeout, Some(Duration::from_secs(30)))?;
        let mut c = Client {
            conn,
            next_id: 1,
            server_version: String::new(),
        };
        let hello: serde_json::Value = c.call(Request::Hello {
            client: who.to_string(),
            protocol: PROTOCOL_VERSION,
        })?;
        c.server_version = hello
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let theirs = hello.get("protocol").and_then(|v| v.as_u64()).unwrap_or(0);
        if theirs != PROTOCOL_VERSION as u64 {
            return Err(Error::unavailable(format!(
                "the daemon speaks protocol {theirs}, this client speaks {PROTOCOL_VERSION}; \
                 install matching versions"
            )));
        }
        Ok(c)
    }

    fn envelope(&mut self, request: Request) -> RequestEnvelope {
        let id = self.next_id;
        self.next_id += 1;
        RequestEnvelope { id, request }
    }

    /// The answer to request `id`. Answers to earlier requests (one that timed
    /// out and was answered late) are skipped, so a single timeout cannot leave
    /// every later call reading the previous call's reply.
    fn read_response_for(&mut self, id: u64) -> Result<ResponseEnvelope> {
        loop {
            let r = self.read_response()?;
            if r.id == id || r.id == 0 {
                return Ok(r);
            }
            if r.id > id {
                return Err(Error::Protocol(format!(
                    "the daemon answered request {} while {id} was outstanding",
                    r.id
                )));
            }
        }
    }

    fn read_response(&mut self) -> Result<ResponseEnvelope> {
        match self.conn.read_line()? {
            None => Err(Error::unavailable(
                "the daemon closed the connection without answering",
            )),
            Some(line) => serde_json::from_slice(&line)
                .map_err(|e| Error::Protocol(format!("unreadable response: {e}"))),
        }
    }

    fn finish(&mut self, r: ResponseEnvelope) -> Result<serde_json::Value> {
        match r.body {
            ResponseBody::Ok { data, .. } => Ok(data),
            ResponseBody::Err { error, .. } => Err(Error::from_wire(&error.code, error.message)),
            ResponseBody::Event { .. } | ResponseBody::End { .. } => Err(Error::Protocol(
                "a stream reply to a request that is not a stream".into(),
            )),
        }
    }

    pub fn call_value(&mut self, request: Request) -> Result<serde_json::Value> {
        let env = self.envelope(request);
        self.conn.send_json(&env)?;
        let r = self.read_response_for(env.id)?;
        self.finish(r)
    }

    pub fn call<T: DeserializeOwned>(&mut self, request: Request) -> Result<T> {
        let v = self.call_value(request)?;
        serde_json::from_value(v).map_err(|e| {
            Error::Protocol(format!("the daemon's answer has an unexpected shape: {e}"))
        })
    }

    /// A request that carries files.
    pub fn call_with_fds<T: DeserializeOwned>(
        &mut self,
        request: Request,
        fds: &[BorrowedFd<'_>],
    ) -> Result<T> {
        let env = self.envelope(request);
        let line = encode_line(&env)?;
        self.conn.send_with_fds(&line, fds)?;
        let r = self.read_response_for(env.id)?;
        let v = self.finish(r)?;
        serde_json::from_value(v).map_err(|e| {
            Error::Protocol(format!("the daemon's answer has an unexpected shape: {e}"))
        })
    }

    /// Start a stream and hand each event to `on_event` until it returns
    /// `false`, the daemon ends the stream or the connection drops.
    pub fn stream(
        &mut self,
        request: Request,
        mut on_event: impl FnMut(serde_json::Value) -> bool,
    ) -> Result<()> {
        let env = self.envelope(request);
        self.conn.send_json(&env)?;
        loop {
            let r = match self.read_response() {
                Ok(r) => r,
                Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::TimedOut => {
                    // A quiet stream is not an error; keep waiting.
                    continue;
                }
                Err(e) => return Err(e),
            };
            match r.body {
                ResponseBody::Event { event } => {
                    if !on_event(event) {
                        return Ok(());
                    }
                }
                ResponseBody::End { .. } => return Ok(()),
                ResponseBody::Err { error, .. } => {
                    return Err(Error::from_wire(&error.code, error.message))
                }
                ResponseBody::Ok { data, .. } => {
                    // The acknowledgement that precedes a stream; it may carry
                    // the first batch (the last log lines).
                    if !on_event(data) {
                        return Ok(());
                    }
                }
            }
        }
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.conn.stream().as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsFd;

    fn pair() -> (Conn, Conn) {
        let (a, b) = UnixStream::pair().unwrap();
        (Conn::new(a), Conn::new(b))
    }

    #[test]
    fn lines_split_across_reads_and_crlf_is_tolerated() {
        let (mut a, mut b) = pair();
        a.write_line(b"one\r\ntw").unwrap();
        a.write_line(b"o\n\nthree\n").unwrap();
        assert_eq!(b.read_line().unwrap().unwrap(), b"one");
        assert_eq!(b.read_line().unwrap().unwrap(), b"two");
        assert_eq!(b.read_line().unwrap().unwrap(), b"");
        assert_eq!(b.read_line().unwrap().unwrap(), b"three");
        drop(a);
        assert_eq!(b.read_line().unwrap(), None);
    }

    #[test]
    fn a_line_that_never_ends_is_refused() {
        let (mut a, mut b) = pair();
        let chunk = vec![b'x'; 64 * 1024];
        let t = std::thread::spawn(move || {
            for _ in 0..(MAX_LINE / chunk.len() + 2) {
                if a.write_line(&chunk).is_err() {
                    break;
                }
            }
        });
        let e = b.read_line().unwrap_err();
        assert!(matches!(e, Error::Protocol(_)), "{e:?}");
        drop(b);
        t.join().unwrap();
    }

    #[test]
    fn a_half_line_at_eof_is_an_error_not_a_request() {
        let (mut a, mut b) = pair();
        a.write_line(b"{\"half\":").unwrap();
        drop(a);
        assert!(b.read_line().is_err());
    }

    #[test]
    fn descriptors_travel_with_the_line_and_arrive_close_on_exec() {
        let (mut a, mut b) = pair();
        let dir = std::env::temp_dir().join(format!("hrd-wire-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, b"payload").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        a.send_with_fds(b"{\"n\":1}\n", &[f.as_fd()]).unwrap();
        assert_eq!(b.read_line().unwrap().unwrap(), b"{\"n\":1}");
        assert_eq!(b.pending_fds(), 1);
        let got = b.take_fds(1).unwrap();
        let flags = rustix::io::fcntl_getfd(&got[0]).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        let mut file = std::fs::File::from(got.into_iter().next().unwrap());
        let mut s = String::new();
        file.read_to_string(&mut s).unwrap();
        assert_eq!(s, "payload");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn claiming_more_descriptors_than_arrived_is_a_protocol_error() {
        let (mut a, mut b) = pair();
        a.write_line(b"x\n").unwrap();
        b.read_line().unwrap();
        assert!(matches!(b.take_fds(1), Err(Error::Protocol(_))));
        assert!(b.take_fds(MAX_FDS + 1).is_err());
    }

    #[test]
    fn extra_descriptors_are_not_queued_beyond_the_limit() {
        let (mut a, mut b) = pair();
        let f = std::fs::File::open("/dev/null").unwrap();
        let many: Vec<_> = (0..MAX_FDS).map(|_| f.as_fd()).collect();
        a.send_with_fds(b"x\n", &many).unwrap();
        a.send_with_fds(b"y\n", &many).unwrap();
        b.read_line().unwrap();
        b.read_line().unwrap();
        assert!(b.pending_fds() <= MAX_FDS);
    }

    #[test]
    fn the_peer_is_identified_by_the_kernel() {
        let (a, _b) = pair();
        let c = a.peer_cred().unwrap();
        assert_eq!(c.uid, rustix::process::getuid().as_raw());
        assert_eq!(c.pid, std::process::id());
    }
}
