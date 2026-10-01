//! Keeping the Roblox build current, if the operator asked for it.
//!
//! One thread. With `runtime.auto_update` on, every `check_interval_h` hours
//! (or when a check is requested) it asks `cordial-import fetch --check` whether
//! the mirror's newest x86-64 build is newer than the newest installed one. If it
//! is, it downloads it into a private directory, then installs it with
//! `cordial-import import`, which checks Roblox's signing certificate and the
//! build's consistency before anything is published, and (`runtime.make_current`)
//! selects it for clients started afterwards.
//!
//! What it does not do: touch a running client, start or restart any client, or
//! make any network request while `auto_update` is off (a requested check
//! overrides that for that one check, because the operator asked for it).
//! A failure is recorded and retried at the next interval; there is no retry loop.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use hrd_core::fsutil;
use hrd_core::proto::UpdateView;
use hrd_core::time::now_unix;

use crate::state::Daemon;

pub fn view(d: &Daemon) -> UpdateView {
    let cfg = d.cfg();
    let mut v = d.update.lock().unwrap_or_else(|e| e.into_inner()).clone();
    v.enabled = cfg.runtime.auto_update;
    v.interval_h = cfg.runtime.check_interval_h;
    v.next_check = (cfg.runtime.auto_update)
        .then(|| v.last_check.unwrap_or_else(now_unix) + cfg.runtime.check_interval_h * 3600);
    v
}

fn record(d: &Daemon, ok: bool, result: String, newest: Option<String>) {
    let mut v = d.update.lock().unwrap_or_else(|e| e.into_inner());
    v.running = false;
    v.last_check = Some(now_unix());
    v.last_ok = Some(ok);
    if newest.is_some() {
        v.newest_seen = newest;
    }
    if !ok {
        eprintln!("<4>cordiald: runtime update: {result}");
    } else {
        eprintln!("<6>cordiald: runtime update: {result}");
    }
    v.last_result = Some(result);
}

fn command(d: &Daemon) -> std::process::Command {
    let mut c = std::process::Command::new(&d.cfg().engine.importer);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null());
    c
}

fn last_line(out: &std::process::Output) -> String {
    let e = String::from_utf8_lossy(&out.stderr);
    let o = String::from_utf8_lossy(&out.stdout);
    e.lines()
        .rev()
        .chain(o.lines().rev())
        .find(|l| !l.trim().is_empty() && !l.starts_with("progress:"))
        .unwrap_or("no output")
        .trim_start_matches("cordial-import: ")
        .chars()
        .take(300)
        .collect()
}

/// One check, and the install if the mirror has something newer.
pub fn run_once(d: &Daemon) {
    {
        let mut v = d.update.lock().unwrap_or_else(|e| e.into_inner());
        if v.running {
            return;
        }
        v.running = true;
    }
    let store = d.layout.runtime_store();

    let mut c = command(d);
    c.args(["fetch", "--check", "--store"]).arg(&store);
    let out = match c.output() {
        Ok(o) => o,
        Err(e) => return record(d, false, format!("cannot run the importer: {e}"), None),
    };
    if !out.status.success() {
        return record(
            d,
            false,
            format!("could not ask the mirror: {}", last_line(&out)),
            None,
        );
    }
    let v: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => {
            return record(
                d,
                false,
                "the importer's answer was unreadable".into(),
                None,
            )
        }
    };
    let newest = v["newest"].as_str().unwrap_or("?").to_string();
    if v["newer"] != serde_json::Value::Bool(true) {
        return record(
            d,
            true,
            format!("up to date (newest on the mirror: {newest})"),
            Some(newest),
        );
    }

    // Download into a private directory of our own, removed afterwards.
    let tmp: PathBuf = d.layout.state_dir.join("update-fetch");
    let _ = fsutil::remove_dir_all_if_exists(&tmp);
    if let Err(e) = fsutil::ensure_private_dir(&tmp, 0o700) {
        return record(
            d,
            false,
            format!("cannot prepare {}: {e}", tmp.display()),
            Some(newest),
        );
    }
    let result = (|| -> Result<String, String> {
        let mut c = command(d);
        c.args(["fetch", "--into"]).arg(&tmp);
        let out = c
            .output()
            .map_err(|e| format!("cannot run the importer: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "download or signature check failed: {}",
                last_line(&out)
            ));
        }
        let mut c = command(d);
        c.args(["import", "--store"])
            .arg(&store)
            .arg("--path")
            .arg(&tmp)
            .args(["--label", "auto-update", "--json"]);
        if d.cfg().runtime.make_current {
            c.arg("--make-current");
        }
        let out = c
            .output()
            .map_err(|e| format!("cannot run the importer: {e}"))?;
        if !out.status.success() {
            return Err(format!("install refused: {}", last_line(&out)));
        }
        let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        Ok(format!(
            "installed {}{}",
            r["version"].as_str().unwrap_or(&newest),
            if r["made_current"] == serde_json::Value::Bool(true) {
                " and selected it for new clients"
            } else {
                " (not selected: `runtime use` it)"
            }
        ))
    })();
    let _ = fsutil::remove_dir_all_if_exists(&tmp);
    match result {
        Ok(m) => record(d, true, m, Some(newest)),
        Err(e) => record(d, false, e, Some(newest)),
    }
}

pub fn spawn_thread(d: Arc<Daemon>) {
    std::thread::Builder::new()
        .name("updater".into())
        .spawn(move || {
            // The first automatic check comes a few minutes after start, not
            // at once: a restart loop must not turn into a request loop.
            let mut next_auto = now_unix() + 300;
            while !d.shutdown.load(Ordering::Relaxed) {
                let cfg = d.cfg();
                let asked = d.update_now.swap(false, Ordering::Relaxed);
                let due = cfg.runtime.auto_update && now_unix() >= next_auto;
                if asked || due {
                    run_once(&d);
                    next_auto = now_unix() + cfg.runtime.check_interval_h * 3600;
                }
                for _ in 0..8 {
                    if d.shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        })
        .ok();
}
