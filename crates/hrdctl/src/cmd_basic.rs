//! init, doctor, secrets, config, daemon.

use std::io::{BufRead, IsTerminal, Write};
use std::os::fd::AsFd;
use std::path::PathBuf;

use clap::Args;
use serde_json::{json, Value};

use hrd_core::config::Config;
use hrd_core::proto::{Check, CheckStatus, ConfigChange, ConfigView, Request};
use hrd_core::redact::Passphrase;
use hrd_core::{fsutil, Error, Result};
use hrd_proc::hostcheck;

use crate::util::{table, Out};
use crate::{ConfigCmd, Ctx, DaemonCmd, SecretsCmd};

#[derive(Args)]
pub struct InitArgs {
    /// Write the example configuration even if a file exists (the old one is kept as .bak)
    #[arg(long)]
    force: bool,
}

/// A line typed without echo, from a terminal; from a pipe, the first line.
pub fn read_secret(prompt: &str) -> Result<Passphrase> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        let mut s = String::new();
        stdin
            .lock()
            .read_line(&mut s)
            .map_err(|e| Error::io("read the passphrase", e))?;
        return Ok(Passphrase::new(
            s.trim_end_matches(['\n', '\r']).to_string(),
        ));
    }
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let fd = stdin.as_fd();
    let old = rustix::termios::tcgetattr(fd)
        .map_err(|e| Error::io("read the terminal settings", e.into()))?;
    let mut quiet = old.clone();
    quiet.local_modes.remove(rustix::termios::LocalModes::ECHO);
    rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Flush, &quiet)
        .map_err(|e| Error::io("turn echo off", e.into()))?;
    let mut s = String::new();
    let r = stdin.lock().read_line(&mut s);
    let _ = rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Flush, &old);
    eprintln!();
    r.map_err(|e| Error::io("read the passphrase", e))?;
    Ok(Passphrase::new(
        s.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

fn print_checks(out: &Out, checks: &[Check]) -> bool {
    let mut failed = false;
    if out.json {
        out.data(&checks);
        return checks.iter().any(|c| c.status == CheckStatus::Fail);
    }
    let rows: Vec<Vec<String>> = checks
        .iter()
        .map(|c| {
            failed |= c.status == CheckStatus::Fail;
            let tag = match c.status {
                CheckStatus::Ok => "ok",
                CheckStatus::Info => "info",
                CheckStatus::Warn => "WARN",
                CheckStatus::Fail => "FAIL",
                CheckStatus::Unknown => "unknown",
            };
            vec![tag.into(), c.title.clone(), c.detail.clone()]
        })
        .collect();
    print!("{}", table(&["", "CHECK", "DETAIL"], &rows, &[]));
    for c in checks
        .iter()
        .filter(|c| matches!(c.status, CheckStatus::Fail | CheckStatus::Warn))
    {
        if let Some(f) = &c.fix {
            println!("  fix ({}): {f}", c.id);
        }
    }
    failed
}

pub fn doctor(ctx: &Ctx) -> Result<()> {
    let (cfg, cfg_problem) = match Config::load(&ctx.layout.config_file()) {
        Ok(c) => (c, None),
        Err(e) => (Config::default(), Some(e.to_string())),
    };
    // With a daemon running, it reports the same host checks plus its own view.
    let checks: Vec<Check> = match ctx.client() {
        Ok(mut c) => c.call(Request::DaemonDoctor)?,
        Err(e) => {
            let mut v = vec![Check {
                id: "daemon".into(),
                title: "daemon".into(),
                status: CheckStatus::Warn,
                detail: e.to_string(),
                fix: Some("systemctl start hrdd".into()),
            }];
            v.extend(hostcheck::host_checks(&ctx.layout, &cfg));
            v
        }
    };
    let mut checks = checks;
    if let Some(p) = cfg_problem {
        checks.insert(
            0,
            Check {
                id: "config".into(),
                title: "configuration".into(),
                status: CheckStatus::Fail,
                detail: p,
                fix: Some(format!(
                    "edit {}; `hrdd --check-config` validates it",
                    ctx.layout.config_file().display()
                )),
            },
        );
    }
    if print_checks(&ctx.out, &checks) {
        return Err(Error::Internal("one or more checks failed".into()));
    }
    Ok(())
}

pub fn init(ctx: &Ctx, a: InitArgs) -> Result<()> {
    let l = &ctx.layout;
    let cfg_path = l.config_file();
    if fsutil::euid() != 0 && std::env::var_os(hrd_core::layout::ROOT_ENV).is_none() {
        return Err(Error::Denied(
            "init writes under /etc and /var; run it as root (sudo hrdctl init)".into(),
        ));
    }
    let mut done = Vec::new();
    if let Some(dir) = cfg_path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::io(format!("create {}", dir.display()), e))?;
    }
    if cfg_path.exists() && !a.force {
        done.push(format!(
            "{} exists; left alone (use --force to replace it)",
            cfg_path.display()
        ));
    } else {
        if cfg_path.exists() {
            std::fs::rename(&cfg_path, cfg_path.with_extension("toml.bak"))
                .map_err(|e| Error::io("keep the old configuration", e))?;
        }
        // The annotated example, so the file explains itself. The defaults are
        // what a missing key means either way.
        let text = EXAMPLE_CONFIG.to_string();
        fsutil::atomic_write(&cfg_path, text.as_bytes(), 0o644)?;
        done.push(format!("wrote {}", cfg_path.display()));
    }
    let cfg = Config::load(&cfg_path)?;
    let svc = lookup_ids(&cfg.service.user, &cfg.service.group);
    for (p, mode) in [(&l.state_dir, 0o700), (&l.log_dir, 0o700)] {
        fsutil::ensure_private_dir(p, mode)?;
        if let Some((uid, gid)) = svc {
            let _ = rustix::fs::chown(
                p.as_path(),
                Some(rustix::fs::Uid::from_raw(uid)),
                Some(rustix::fs::Gid::from_raw(gid)),
            );
        }
        done.push(format!("ready: {}", p.display()));
    }
    if svc.is_none() {
        done.push(format!("the user {} / group {} do not exist yet: install the package or create them (docs/install.md)", cfg.service.user, cfg.service.group));
    }
    let checks = hostcheck::host_checks(l, &cfg);
    if ctx.out.json {
        ctx.out.value(&json!({ "done": done, "checks": checks }));
        return Ok(());
    }
    for d in &done {
        println!("{d}");
    }
    println!();
    print_checks(&ctx.out, &checks);
    println!(
        "\nNothing was started, no account was touched and no network was changed.\nNext:\n  1. systemctl enable --now hrd-netd hrdd\n  2. hrdctl secrets unlock --create\n  3. hrdctl runtime import --apk /path/to/roblox.apk\n  4. hrdctl network add NAME --wireguard-config FILE   (per group)\n  5. hrdctl account add NAME; hrdctl account login NAME\nSee docs/install.md."
    );
    Ok(())
}

const EXAMPLE_CONFIG: &str = include_str!("../../../config/hrdd.toml.example");

#[allow(dead_code)]
const EXAMPLE_HEADER: &str = "# hrdd.toml: the settings the daemon starts with. Only what you change matters;\n# anything left out keeps the value shown. Unknown keys are errors.\n# Values changed with `hrdctl config set` are kept separately and override this file.\n# Nothing in this file is a secret, and nothing here is a statement about what Roblox allows.\n\n";

fn lookup_ids(user: &str, group: &str) -> Option<(u32, u32)> {
    let uid = std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.first() == Some(&user)).then(|| f.get(2)?.parse().ok())?
        })?;
    let gid = std::fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.first() == Some(&group)).then(|| f.get(2)?.parse().ok())?
        })?;
    Some((uid, gid))
}

pub fn secrets(ctx: &Ctx, c: SecretsCmd) -> Result<()> {
    let mut cl = ctx.client()?;
    match c {
        SecretsCmd::Status => {
            let v: Value = cl.call(Request::SecretsStatus)?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                println!(
                    "secret store: {} ({})",
                    v["state"].as_str().unwrap_or("?"),
                    v["detail"].as_str().unwrap_or("")
                );
            }
        }
        SecretsCmd::Lock => {
            let v: Value = cl.call(Request::SecretsLock)?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                println!("secret store: {}", v["state"].as_str().unwrap_or("?"));
            }
        }
        SecretsCmd::Unlock {
            create,
            passphrase_file,
        } => {
            let pass = match passphrase_file {
                Some(p) => {
                    fsutil::require_private_file(&p)?;
                    let b = fsutil::read_limited(&p, 4096)?;
                    Passphrase::new(
                        String::from_utf8_lossy(&b)
                            .trim_end_matches(['\n', '\r'])
                            .to_string(),
                    )
                }
                None => {
                    let p = read_secret(if create {
                        "new keyring passphrase: "
                    } else {
                        "keyring passphrase: "
                    })?;
                    if create {
                        let again = read_secret("again: ")?;
                        if p.expose() != again.expose() {
                            return Err(Error::invalid("the passphrases differ"));
                        }
                        if p.expose().chars().count() < 12 {
                            return Err(Error::invalid("use at least 12 characters: this passphrase is the only thing protecting every stored session"));
                        }
                    }
                    p
                }
            };
            let v: Value = cl.call(Request::SecretsUnlock {
                passphrase: pass,
                create,
            })?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                println!("secret store: {}", v["state"].as_str().unwrap_or("?"));
                if create {
                    println!("There is no way to recover this passphrase. Without it the stored sessions cannot be read and accounts must sign in again.");
                }
            }
        }
    }
    Ok(())
}

pub fn config(ctx: &Ctx, c: ConfigCmd) -> Result<()> {
    let mut cl = ctx.client()?;
    match c {
        ConfigCmd::Get => {
            let v: ConfigView = cl.call(Request::ConfigGet)?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!(
                    "# file: {}\n# overrides: {} {}\n{}",
                    v.file,
                    v.overrides_file,
                    if v.overrides.as_object().is_some_and(|o| o.is_empty()) {
                        "(none)"
                    } else {
                        "(in effect)"
                    },
                    v.effective.to_toml()?
                );
                for p in &v.problems {
                    eprintln!("problem: {p}");
                }
            }
        }
        ConfigCmd::Set { key, value } => {
            // A number, boolean or JSON value if it parses as one; otherwise text.
            let parsed: Value = serde_json::from_str(&value).unwrap_or(Value::String(value));
            let r: Value = cl.call(Request::ConfigSet {
                changes: vec![ConfigChange {
                    key,
                    value: Some(parsed),
                }],
            })?;
            print_applied(&ctx.out, &r);
        }
        ConfigCmd::Unset { key } => {
            let r: Value = cl.call(Request::ConfigSet {
                changes: vec![ConfigChange { key, value: None }],
            })?;
            print_applied(&ctx.out, &r);
        }
    }
    Ok(())
}

fn print_applied(out: &Out, r: &Value) {
    if out.json {
        out.value(r);
        return;
    }
    for (k, what) in [
        ("live", "in effect now"),
        ("next_start", "takes effect for the next client that starts"),
        ("restart", "needs `systemctl restart hrdd`"),
    ] {
        for key in r[k].as_array().into_iter().flatten() {
            println!("{}: {what}", key.as_str().unwrap_or("?"));
        }
    }
}

pub fn daemon(ctx: &Ctx, c: DaemonCmd) -> Result<()> {
    let mut cl = ctx.client()?;
    match c {
        DaemonCmd::Info => {
            let v: Value = cl.call(Request::DaemonInfo)?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else if let Some(o) = v.as_object() {
                for (k, x) in o {
                    println!("{k}: {x}");
                }
            }
        }
        DaemonCmd::Stop { stop_clients } => {
            let v: Value = cl.call(Request::Shutdown {
                stop_instances: Some(stop_clients),
            })?;
            ctx.out.line(format!(
                "daemon is stopping{}",
                if stop_clients {
                    " and stopping every client"
                } else {
                    "; clients keep running and are adopted by the next daemon"
                }
            ));
            if ctx.out.json {
                ctx.out.value(&v);
            }
        }
    }
    let _: Option<PathBuf> = None;
    Ok(())
}
