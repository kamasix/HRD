//! Where sessions are kept: a Secret Service on a private bus, no desktop.
//!
//! Upstream's client stores the cookie jar and identity of a profile in the
//! Secret Service (`CORDIAL_SECRET_STORE=keyring`), keyed by the profile's
//! absolute path, and has no encrypted alternative: its other store is a plain
//! 0600 file. So this manager runs a private session bus and a headless
//! `gnome-keyring-daemon` on it, and points every client at that bus.
//!
//! * The keyring file is encrypted with a passphrase the operator types at
//!   `cordialctl secrets unlock`. The passphrase is passed to the keyring on its
//!   standard input, is never written anywhere, and is not in any argument.
//!   After a reboot the keyring is locked until the operator unlocks it; that is
//!   the price of the key not lying next to the store.
//! * The bus is a filesystem socket (an abstract one belongs to a network
//!   namespace and would be unreachable from inside a group's).
//! * The manager never reads a secret. It asks the service whether an item
//!   exists and asks it to delete one, through `busctl`, which prints object
//!   paths and never values.
//!
//! **What this does not do:** every client runs as the same Unix user and so can
//! talk to this bus; per-profile keying separates honest clients, not a
//! compromised one. Stated in docs/security.md.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hrd_core::config::{Config, SecretBackend};
use hrd_core::layout::Layout;
use hrd_core::redact::Passphrase;
use hrd_core::{fsutil, Error, Result};

const SERVICE: &str = "org.freedesktop.secrets";
const DEFAULT_COLLECTION: &str = "/org/freedesktop/secrets/aliases/default";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretsState {
    /// `secrets.backend = none`.
    Disabled,
    /// No keyring exists yet: `secrets unlock --create`.
    NotCreated,
    /// The bus or the keyring daemon is not running.
    Stopped,
    Locked,
    Ready,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SecretsStatus {
    pub state: SecretsState,
    pub detail: String,
    pub bus: String,
}

pub struct Secrets {
    layout: Layout,
    cfg: Mutex<(SecretBackend, String, String)>,
    children: Mutex<Vec<Child>>,
}

impl Secrets {
    pub fn new(layout: Layout, cfg: &Config) -> Secrets {
        Secrets {
            layout,
            cfg: Mutex::new((
                cfg.secrets.backend,
                cfg.secrets.dbus_daemon.clone(),
                cfg.secrets.keyring_daemon.clone(),
            )),
            children: Mutex::new(Vec::new()),
        }
    }

    fn bus_path(&self) -> PathBuf {
        self.layout.secrets_bus()
    }

    fn address(&self) -> String {
        format!("unix:path={}", self.bus_path().display())
    }

    /// The bus address to give clients, only when the keyring is usable.
    pub fn bus_address(&self) -> Option<String> {
        (self.status().state == SecretsState::Ready).then(|| self.address())
    }

    fn backend(&self) -> SecretBackend {
        self.cfg.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    fn bus_up(&self) -> bool {
        UnixStream::connect(self.bus_path()).is_ok()
    }

    fn keyring_files_exist(&self) -> bool {
        std::fs::read_dir(self.layout.secrets_data().join("keyrings"))
            .map(|d| {
                d.flatten()
                    .any(|e| e.file_name().to_string_lossy().ends_with(".keyring"))
            })
            .unwrap_or(false)
    }

    fn busctl(&self, args: &[&str]) -> Result<String> {
        let out = Command::new("busctl")
            .arg(format!("--address={}", self.address()))
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Error::unavailable(format!("cannot run busctl (package systemd): {e}")))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(Error::unavailable(format!(
                "busctl: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    pub fn status(&self) -> SecretsStatus {
        let bus = self.address();
        let mk = |state, detail: &str| SecretsStatus {
            state,
            detail: detail.into(),
            bus: bus.clone(),
        };
        if self.backend() == SecretBackend::None {
            return mk(SecretsState::Disabled, "secrets.backend = none: no session is kept, every start needs a sign-in (not supported by this build's client store; see docs/security.md)");
        }
        if !self.bus_up() {
            return if self.keyring_files_exist() {
                mk(
                    SecretsState::Stopped,
                    "the keyring exists but is not running: `cordialctl secrets unlock`",
                )
            } else {
                mk(
                    SecretsState::NotCreated,
                    "no keyring yet: `cordialctl secrets unlock --create`",
                )
            };
        }
        match self.busctl(&[
            "get-property",
            SERVICE,
            DEFAULT_COLLECTION,
            "org.freedesktop.Secret.Collection",
            "Locked",
        ]) {
            Ok(o) if parse_bool_property(&o) == Some(false) => mk(SecretsState::Ready, "unlocked"),
            Ok(o) if parse_bool_property(&o) == Some(true) => mk(
                SecretsState::Locked,
                "the keyring is locked: `cordialctl secrets unlock`",
            ),
            Ok(o) => mk(
                SecretsState::Stopped,
                &format!("unexpected answer from the secret service: {}", o.trim()),
            ),
            Err(_) => mk(
                SecretsState::Stopped,
                "the bus is up but the secret service does not answer: `cordialctl secrets unlock`",
            ),
        }
    }

    fn spawn_quiet(&self, mut cmd: Command) -> Result<Child> {
        cmd.spawn()
            .map_err(|e| Error::unavailable(format!("cannot start {:?}: {e}", cmd.get_program())))
    }

    fn start_bus(&self) -> Result<()> {
        if self.bus_up() {
            return Ok(());
        }
        let run = self.layout.secrets_run();
        fsutil::ensure_private_dir(&run, 0o700)?;
        let _ = std::fs::remove_file(self.bus_path());
        let conf = run.join("session.conf");
        let xml = format!(
            "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" \
             \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n<busconfig>\n  <type>session</type>\n  \
             <listen>{}</listen>\n  <auth>EXTERNAL</auth>\n  <policy context=\"default\">\n    <allow send_destination=\"*\"/>\n    \
             <allow receive_sender=\"*\"/>\n    <allow own=\"*\"/>\n  </policy>\n</busconfig>\n",
            self.address()
        );
        fsutil::atomic_write(&conf, xml.as_bytes(), 0o600)?;
        let dbus = self.cfg.lock().unwrap_or_else(|e| e.into_inner()).1.clone();
        let mut cmd = Command::new(dbus);
        cmd.arg(format!("--config-file={}", conf.display()))
            .arg("--nofork")
            .arg("--nopidfile")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = self.spawn_quiet(cmd)?;
        self.children
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(child);
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) {
            if self.bus_up() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(Error::unavailable(
            "the private session bus did not come up in 5 s",
        ))
    }

    /// Start (or unlock) the keyring with `passphrase`. With `create`, a keyring
    /// that does not exist is made with this passphrase; without it, a missing
    /// keyring is an error rather than a surprise new one.
    pub fn unlock(&self, passphrase: &Passphrase, create: bool) -> Result<SecretsStatus> {
        if self.backend() == SecretBackend::None {
            return Err(Error::invalid("secrets.backend = none"));
        }
        if passphrase.is_empty() {
            return Err(Error::invalid("the passphrase is empty"));
        }
        if create && passphrase.expose().chars().count() < 12 {
            return Err(Error::invalid(
                "a new keyring needs a passphrase of at least 12 characters: it is the only thing protecting every stored session",
            ));
        }
        let exists = self.keyring_files_exist();
        if !exists && !create {
            return Err(Error::not_found(
                "no keyring exists yet; use `cordialctl secrets unlock --create` to make one",
            ));
        }
        if exists && create {
            return Err(Error::conflict(
                "a keyring already exists; unlock it without --create",
            ));
        }
        let st = self.status();
        if st.state == SecretsState::Ready {
            return Ok(st);
        }
        fsutil::ensure_private_dir(&self.layout.secrets_data(), 0o700)?;
        self.start_bus()?;
        self.reap_dead();
        let keyring = self.cfg.lock().unwrap_or_else(|e| e.into_inner()).2.clone();
        let mut cmd = Command::new(keyring);
        cmd.args(["--foreground", "--components=secrets", "--unlock"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("DBUS_SESSION_BUS_ADDRESS", self.address())
            .env("XDG_RUNTIME_DIR", self.layout.secrets_run())
            .env("XDG_DATA_HOME", self.layout.secrets_data())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = self.spawn_quiet(cmd)?;
        self.remember(child.id());
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::Internal("no stdin pipe".into()))?;
            // No newline: the keyring reads to end of input and a trailing one
            // would become part of the passphrase.
            let _ = stdin.write_all(passphrase.expose().as_bytes());
        }
        let t = Instant::now();
        let mut last = self.status();
        while t.elapsed() < Duration::from_secs(10) {
            last = self.status();
            if last.state == SecretsState::Ready {
                self.children
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(child);
                return Ok(last);
            }
            if matches!(child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.forget(child.id());
        let _ = child.kill();
        let _ = child.wait();
        Err(Error::Denied(format!(
            "the keyring did not unlock ({}): the passphrase is probably wrong",
            last.detail
        )))
    }

    fn reap_dead(&self) {
        self.children
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain_mut(|c| matches!(c.try_wait(), Ok(None)));
    }

    fn procs_file(&self) -> PathBuf {
        self.layout.secrets_run().join("procs.json")
    }

    fn read_idents(&self) -> Vec<(u32, u64)> {
        fsutil::read_limited_opt(&self.procs_file(), 64 * 1024)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Record a process of ours by pid *and* start time, so that a later daemon
    /// (which did not start it) can still end it without risking a reused pid.
    fn remember(&self, pid: u32) {
        let Some(t) = hrd_proc::procfs::start_ticks(pid) else {
            return;
        };
        let mut v = self.read_idents();
        v.retain(|(p, _)| *p != pid);
        v.push((pid, t));
        let _ = fsutil::write_json_atomic(&self.procs_file(), &v, 0o600);
    }

    fn forget(&self, pid: u32) {
        let mut v = self.read_idents();
        v.retain(|(p, _)| *p != pid);
        let _ = fsutil::write_json_atomic(&self.procs_file(), &v, 0o600);
    }

    /// Stop the keyring and the bus, including ones an earlier daemon started.
    /// The keyring is locked again afterwards: unlocking needs the passphrase.
    pub fn stop(&self) {
        {
            let mut ch = self.children.lock().unwrap_or_else(|e| e.into_inner());
            for c in ch.iter_mut() {
                let _ = c.kill();
                let _ = c.wait();
            }
            ch.clear();
        }
        for (pid, ticks) in self.read_idents() {
            if hrd_proc::procfs::is_same_process(pid, ticks) {
                if let Some(p) = rustix::process::Pid::from_raw(pid as i32) {
                    let _ = rustix::process::kill_process(p, rustix::process::Signal::TERM);
                }
            }
        }
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(3) && self.bus_up() {
            std::thread::sleep(Duration::from_millis(50));
        }
        for (pid, ticks) in self.read_idents() {
            if hrd_proc::procfs::is_same_process(pid, ticks) {
                if let Some(p) = rustix::process::Pid::from_raw(pid as i32) {
                    let _ = rustix::process::kill_process(p, rustix::process::Signal::KILL);
                }
            }
        }
        let _ = std::fs::remove_file(self.procs_file());
        let _ = std::fs::remove_file(self.bus_path());
    }

    fn item_paths(&self, profile: &Path) -> Result<Vec<String>> {
        let p = profile.display().to_string();
        let out = self.busctl(&[
            "call",
            SERVICE,
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
            "SearchItems",
            "a{ss}",
            "2",
            "application",
            "cordial",
            "profile",
            &p,
        ])?;
        Ok(parse_object_paths(&out))
    }

    /// Is a session stored for this profile? Existence only.
    pub fn session_present(&self, profile: &Path) -> Result<bool> {
        self.require_ready()?;
        Ok(!self.item_paths(profile)?.is_empty())
    }

    /// Delete the profile's stored items. Returns how many.
    pub fn erase(&self, profile: &Path) -> Result<usize> {
        self.require_ready()?;
        let items = self.item_paths(profile)?;
        for i in &items {
            self.busctl(&["call", SERVICE, i, "org.freedesktop.Secret.Item", "Delete"])?;
        }
        Ok(items.len())
    }

    pub fn require_ready(&self) -> Result<()> {
        let st = self.status();
        if st.state == SecretsState::Ready {
            Ok(())
        } else {
            Err(Error::unavailable(format!(
                "the secret store is not ready ({}): {}",
                format!("{:?}", st.state).to_lowercase(),
                st.detail
            )))
        }
    }
}

fn parse_bool_property(out: &str) -> Option<bool> {
    let t = out.trim();
    t.strip_prefix("b ").and_then(|v| match v.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

/// Object paths from `busctl` output such as `aoao 1 "/a/b" 0`.
fn parse_object_paths(out: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut rest = out;
    while let Some(i) = rest.find('"') {
        let after = &rest[i + 1..];
        let Some(j) = after.find('"') else { break };
        let s = &after[..j];
        if s.starts_with('/') {
            v.push(s.to_string());
        }
        rest = &after[j + 1..];
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busctl_output_is_parsed_without_reading_values() {
        assert_eq!(parse_bool_property("b false\n"), Some(false));
        assert_eq!(parse_bool_property("b true"), Some(true));
        assert_eq!(parse_bool_property("s \"x\""), None);
        assert_eq!(parse_object_paths("aoao 2 \"/org/freedesktop/secrets/collection/login/1\" \"/org/freedesktop/secrets/collection/login/2\" 0\n").len(), 2);
        assert!(parse_object_paths("aoao 0 0").is_empty());
        assert!(parse_object_paths("s \"not a path\"").is_empty());
    }

    #[test]
    fn a_disabled_backend_says_so_and_never_hands_out_a_bus() {
        let mut cfg = Config::default();
        cfg.secrets.backend = SecretBackend::None;
        let s = Secrets::new(Layout::under(Path::new("/nonexistent-hrd")), &cfg);
        assert_eq!(s.status().state, SecretsState::Disabled);
        assert!(s.bus_address().is_none());
        assert!(s.unlock(&Passphrase::new("x".into()), true).is_err());
    }

    #[test]
    fn nothing_is_created_without_asking() {
        let s = Secrets::new(
            Layout::under(Path::new("/nonexistent-hrd")),
            &Config::default(),
        );
        assert_eq!(s.status().state, SecretsState::NotCreated);
        assert!(s.unlock(&Passphrase::new("pw".into()), false).is_err());
        assert!(s.session_present(Path::new("/x")).is_err());
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Needs dbus-daemon, gnome-keyring-daemon and busctl. Creates a keyring in
    /// a scratch directory, locks it by stopping the daemons, and checks that a
    /// wrong passphrase gets no access and the right one does.
    #[test]
    #[ignore = "starts dbus-daemon and gnome-keyring-daemon"]
    fn a_keyring_is_created_locked_and_unlocked_without_a_desktop() {
        let d = std::env::temp_dir().join(format!("hrd-kr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let s = Secrets::new(Layout::under(&d), &Config::default());
        assert_eq!(s.status().state, SecretsState::NotCreated);
        let st = s
            .unlock(&Passphrase::new("correct horse".into()), true)
            .unwrap();
        assert_eq!(st.state, SecretsState::Ready, "{st:?}");
        assert!(!s.session_present(Path::new("/some/profile")).unwrap());
        assert_eq!(s.erase(Path::new("/some/profile")).unwrap(), 0);
        // The passphrase is nowhere on disk.
        let out = Command::new("grep")
            .args(["-rl", "correct horse"])
            .arg(&d)
            .output()
            .unwrap();
        assert!(out.stdout.is_empty(), "passphrase found on disk");
        s.stop();
        // Stopping the daemons leaves the keyring locked on disk.
        assert!(s.bus_address().is_none());
        let wrong = s.unlock(&Passphrase::new("wrong".into()), false);
        assert!(matches!(wrong, Err(Error::Denied(_))), "{wrong:?}");
        assert!(s.bus_address().is_none());
        s.stop();
        let again = s
            .unlock(&Passphrase::new("correct horse".into()), false)
            .unwrap();
        assert_eq!(again.state, SecretsState::Ready);
        s.stop();
        std::fs::remove_dir_all(d).ok();
    }
}
