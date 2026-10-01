//! Running the three system tools the helper uses, and nothing else.
//!
//! `ip`, `wg` and `nft` are located once, in a fixed list of system
//! directories, and refused if they are not owned by root or are writable by
//! anyone else: the helper runs them as root, so a binary an unprivileged user
//! can replace would be a way to become root. Commands are argument vectors
//! with a cleared environment; there is no shell anywhere, so there is nothing
//! to inject into, and every value interpolated into an argument has already
//! been parsed into a type that cannot carry more than it says.

#![allow(unsafe_code)] // `pre_exec`, used only to enter a namespace; see `Runner::run`

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hrd_core::{Error, Result};

const DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];
const MAX_OUTPUT: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Tools {
    pub ip: PathBuf,
    pub wg: PathBuf,
    pub nft: PathBuf,
}

fn locate(name: &str) -> Result<PathBuf> {
    for d in DIRS {
        let p = Path::new(d).join(name);
        let Ok(md) = std::fs::metadata(&p) else {
            continue;
        };
        if !md.is_file() {
            continue;
        }
        if md.uid() != 0 || md.mode() & 0o022 != 0 {
            return Err(Error::Denied(format!(
                "{} is not owned by root or is writable by others; refusing to run it as root",
                p.display()
            )));
        }
        return Ok(p);
    }
    Err(Error::unavailable(format!(
        "{name} not found in {}: install iproute2, wireguard-tools and nftables",
        DIRS.join(", ")
    )))
}

impl Tools {
    pub fn locate() -> Result<Tools> {
        Ok(Tools {
            ip: locate("ip")?,
            wg: locate("wg")?,
            nft: locate("nft")?,
        })
    }
}

#[derive(Debug)]
pub struct Output {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

/// Run `tool args`, optionally feeding `stdin`, optionally inside the network
/// namespace referred to by `netns`.
///
/// `timeout` bounds the whole run; on expiry the child is killed. A non-zero
/// exit is returned, not raised: callers differ on whether it is an error
/// (`ip addr add` of an existing address) or an answer (`wg show` of a missing
/// interface).
pub fn run(
    tool: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    netns: Option<&File>,
    timeout: Duration,
) -> Result<Output> {
    let mut cmd = Command::new(tool);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(ns) = netns {
        let ns = ns
            .try_clone()
            .map_err(|e| Error::io("duplicate the namespace descriptor", e))?;
        // SAFETY: the closure runs between fork and exec in a possibly
        // multi-threaded parent, so it must be async-signal-safe. It calls one
        // system call (`setns`) on a descriptor that was opened before the fork
        // and owns no memory it allocates. It runs in the child only, so the
        // namespace of this process's threads is never changed.
        unsafe {
            cmd.pre_exec(move || {
                rustix::thread::move_into_link_name_space(
                    ns.as_fd(),
                    Some(rustix::thread::LinkNameSpaceType::Network),
                )
                .map_err(std::io::Error::from)
            });
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::io(format!("start {}", tool.display()), e))?;
    if let Some(data) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            // A tool that exits early closes the pipe; that is its answer, not
            // a failure of ours.
            let _ = pipe.write_all(data);
        }
    }
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let t_out = std::thread::spawn(move || read_capped(&mut out));
    let t_err = std::thread::spawn(move || read_capped(&mut err));

    let start = Instant::now();
    let status = loop {
        match child.try_wait().map_err(|e| Error::io("wait", e))? {
            Some(s) => break s.code(),
            None if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::unavailable(format!(
                    "{} did not finish within {} s",
                    tool.display(),
                    timeout.as_secs()
                )));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    Ok(Output {
        status,
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
    })
}

fn read_capped(r: &mut impl Read) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match r.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < MAX_OUTPUT {
                    buf.extend_from_slice(&chunk[..n.min(MAX_OUTPUT - buf.len())]);
                }
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Run and require success; the error carries what the tool said.
pub fn run_ok(
    tool: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    netns: Option<&File>,
) -> Result<Output> {
    let out = run(tool, args, stdin, netns, Duration::from_secs(30))?;
    if out.ok() {
        Ok(out)
    } else {
        let name = tool
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Err(Error::unavailable(format!(
            "{name} {} failed ({}): {}",
            args.join(" "),
            out.status
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into()),
            out.stderr.trim()
        )))
    }
}
