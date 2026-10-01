//! Accounts, and the sign-in console.
//!
//! Signing in needs a person: a password, maybe a code from a phone, maybe a
//! puzzle. The console shows the client's frame in the terminal and relays what
//! the operator types, one action per line they enter. It runs no script and
//! repeats nothing; the password is read without echo, sent once and forgotten.

use std::io::{BufRead, IsTerminal, Write};
use std::time::{Duration, Instant};

use serde_json::Value;

use hrd_core::ids::AccountName;
use hrd_core::model::State;
use hrd_core::proto::{
    AccountView, ExportedAccount, LoginAction, LoginKey, LoginView, Request, ShotView,
};
use hrd_core::{fsutil, Error, Result};

use crate::cmd_basic::read_secret;
use crate::util::{opt, table};
use crate::{AccountCmd, Ctx};

pub fn account(ctx: &Ctx, c: AccountCmd) -> Result<()> {
    match c {
        AccountCmd::Add {
            name,
            labels,
            note,
            group,
        } => {
            let v: AccountView = ctx.client()?.call(Request::AccountAdd {
                name,
                labels,
                note,
                group,
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!(
                    "account {} added (no session yet: hrdctl account login {})",
                    v.name, v.name
                );
            }
        }
        AccountCmd::List { group, label } => {
            let v: Vec<AccountView> = ctx.client()?.call(Request::AccountList)?;
            let v: Vec<AccountView> = v
                .into_iter()
                .filter(|a| {
                    group.as_ref().is_none_or(|g| a.group.as_ref() == Some(g))
                        && label.as_ref().is_none_or(|l| a.labels.contains(l))
                })
                .collect();
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                let rows: Vec<Vec<String>> = v
                    .iter()
                    .map(|a| {
                        vec![
                            a.name.to_string(),
                            opt(&a.group),
                            format!("{:?}", a.auth).to_lowercase(),
                            a.state.to_string(),
                            a.labels.join(","),
                            a.auth_detail
                                .clone()
                                .unwrap_or_default()
                                .chars()
                                .take(60)
                                .collect(),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    table(
                        &[
                            "ACCOUNT",
                            "GROUP",
                            "SESSION",
                            "STATE",
                            "LABELS",
                            "SESSION NOTE"
                        ],
                        &rows,
                        &[]
                    )
                );
                println!("session: none = nothing stored; stored = an item exists (not proof Roblox accepts it); verified = a client was seen signed in; required = a client reached the sign-in screen.");
            }
        }
        AccountCmd::Set {
            name,
            labels,
            note,
            mode,
        } => {
            let v: AccountView = ctx.client()?.call(Request::AccountSet {
                name,
                labels,
                note,
                mode,
            })?;
            if ctx.out.json {
                ctx.out.data(&v);
            } else {
                println!("account {} updated", v.name);
            }
        }
        AccountCmd::Logout { name } => {
            let v: Value = ctx.client()?.call(Request::AccountLogout { name })?;
            ctx.out.line(format!(
                "{}: stored session erased ({} item(s))",
                v["account"].as_str().unwrap_or(""),
                v["stored_items_erased"]
            ));
            if ctx.out.json {
                ctx.out.value(&v);
            }
        }
        AccountCmd::Remove { name, yes } => {
            let confirm = if yes {
                name.to_string()
            } else {
                if !std::io::stdin().is_terminal() {
                    return Err(Error::invalid(
                        "not a terminal: pass --yes to remove without being asked",
                    ));
                }
                eprint!("This deletes {name}'s profile, logs and stored session. Type the account name to confirm: ");
                let mut s = String::new();
                std::io::stdin()
                    .lock()
                    .read_line(&mut s)
                    .map_err(|e| Error::io("read", e))?;
                s.trim().to_string()
            };
            let v: Value = ctx
                .client()?
                .call(Request::AccountRemove { name, confirm })?;
            ctx.out.line(format!(
                "removed {} ({} stored item(s) erased)",
                v["removed"].as_str().unwrap_or(""),
                v["stored_items_erased"]
            ));
            if ctx.out.json {
                ctx.out.value(&v);
            }
        }
        AccountCmd::Export { file } => {
            let v: Vec<ExportedAccount> = ctx.client()?.call(Request::AccountExport)?;
            let text = serde_json::to_string_pretty(&v).unwrap_or_default();
            match file {
                Some(p) => {
                    fsutil::atomic_write(&p, text.as_bytes(), 0o600)?;
                    ctx.out.line(format!(
                        "wrote {} account(s) to {} (names, labels, groups: no secrets)",
                        v.len(),
                        p.display()
                    ));
                }
                None => println!("{text}"),
            }
        }
        AccountCmd::Import { file, replace } => {
            let b = fsutil::read_limited(&file, 16 << 20)?;
            let accounts: Vec<ExportedAccount> = serde_json::from_slice(&b)
                .map_err(|e| Error::invalid(format!("{}: {e}", file.display())))?;
            let v: Value = ctx
                .client()?
                .call(Request::AccountImport { accounts, replace })?;
            if ctx.out.json {
                ctx.out.value(&v);
            } else {
                println!(
                    "added {}, updated {}, skipped {} existing",
                    v["added"],
                    v["updated"],
                    v["skipped_existing"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0)
                );
            }
        }
        AccountCmd::Login {
            name,
            detach,
            attach,
            columns,
        } => login(ctx, name, detach, attach, columns)?,
    }
    Ok(())
}

// ------------------------------------------------------------------ console

fn view(ctx: &Ctx, name: &AccountName) -> Result<LoginView> {
    ctx.client()?
        .call(Request::LoginStatus { name: name.clone() })
}

fn login(ctx: &Ctx, name: AccountName, detach: bool, attach: bool, columns: u32) -> Result<()> {
    if ctx.out.json {
        return Err(Error::invalid(
            "the sign-in console is interactive; use it without --json",
        ));
    }
    if !attach {
        let v: LoginView = ctx
            .client()?
            .call(Request::LoginStart { name: name.clone() })?;
        println!("sign-in client for {} is {} ...", v.account, v.state);
    }
    // Wait for the client to show its first screen.
    let t0 = Instant::now();
    let mut last = String::new();
    loop {
        let v = view(ctx, &name)?;
        if !v.running {
            return Err(Error::unavailable(format!(
                "the sign-in session ended: {}",
                v.detail.unwrap_or_else(|| v.state.to_string())
            )));
        }
        if v.screen.is_some() {
            break;
        }
        let msg = v.detail.clone().unwrap_or_default();
        if msg != last {
            println!("  {}: {msg}", v.state);
            last = msg;
        }
        if t0.elapsed() > Duration::from_secs(600) {
            return Err(Error::unavailable(
                "the client did not reach a screen in 10 minutes (see `hrdctl logs`)",
            ));
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    if detach {
        println!("ready. Attach with: hrdctl account login {name} --attach");
        return Ok(());
    }
    let v = view(ctx, &name)?;
    if !v.console {
        println!("the console is switched off (login.console = false); the client is running but cannot be driven from here");
        return Ok(());
    }
    println!("Sign-in console for {name}. Type 'help' for commands. Leaving with 'detach' keeps the client running; 'quit' stops it.");
    let auto = true;
    show(ctx, &name, columns)?;
    loop {
        let v = view(ctx, &name)?;
        if v.signed_in {
            println!("signed in: the session is being stored. Verify with `hrdctl account list`.");
            return Ok(());
        }
        if !v.running {
            return if v.state == State::Stopped {
                println!(
                    "the sign-in session ended: {}",
                    v.detail.unwrap_or_default()
                );
                Ok(())
            } else {
                Err(Error::unavailable(format!(
                    "the sign-in session ended: {}",
                    v.detail.unwrap_or_else(|| v.state.to_string())
                )))
            };
        }
        eprint!("login:{name}> ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        // The lock is taken per line and released before any command runs:
        // `password` reads stdin again and std's stdin lock is not reentrant.
        if std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| Error::io("read", e))?
            == 0
        {
            println!("\ninput closed; leaving the client running (attach again with --attach)");
            return Ok(());
        }
        let line = line.trim_end_matches(['\n', '\r']);
        let (cmd, rest) = line.split_once(' ').unwrap_or((line, ""));
        let act: Option<LoginAction> = match cmd {
            "" => None,
            "help" | "?" => {
                println!("  shot                 show the client's current frame\n  click X Y            click at pixel X,Y of the frame (coordinates are on the rulers)\n  type TEXT            type text into the focused field (echoed here)\n  password             type a password (asked without echo; never stored or logged)\n  key NAME             enter, tab, backspace, escape, space, up, down, left, right\n  status               the session's state\n  detach               leave, keep the client running\n  quit                 stop the sign-in client");
                None
            }
            "shot" => {
                show(ctx, &name, columns)?;
                None
            }
            "status" => {
                let v = view(ctx, &name)?;
                println!(
                    "  {} screen {} expires {}",
                    v.state,
                    opt(&v.screen),
                    v.expires_at
                        .map(hrd_core::time::rfc3339)
                        .unwrap_or_default()
                );
                None
            }
            "detach" => return Ok(()),
            "quit" => {
                let _: Value = ctx
                    .client()?
                    .call(Request::LoginCancel { name: name.clone() })?;
                println!("sign-in client is stopping");
                return Ok(());
            }
            "click" => {
                let p: Vec<&str> = rest.split_whitespace().collect();
                match (
                    p.first().and_then(|x| x.parse().ok()),
                    p.get(1).and_then(|x| x.parse().ok()),
                ) {
                    (Some(x), Some(y)) => Some(LoginAction::Click { x, y }),
                    _ => {
                        println!("  usage: click X Y");
                        None
                    }
                }
            }
            "type" => Some(LoginAction::Text {
                text: rest.to_string(),
            }),
            "password" => {
                let p = read_secret("password (not shown): ")?;
                Some(LoginAction::Text {
                    text: p.expose().to_string(),
                })
            }
            "key" => match rest.trim() {
                "enter" => Some(LoginAction::Key {
                    key: LoginKey::Enter,
                }),
                "tab" => Some(LoginAction::Key { key: LoginKey::Tab }),
                "backspace" => Some(LoginAction::Key {
                    key: LoginKey::Backspace,
                }),
                "escape" => Some(LoginAction::Key {
                    key: LoginKey::Escape,
                }),
                "space" => Some(LoginAction::Key {
                    key: LoginKey::Space,
                }),
                "up" => Some(LoginAction::Key { key: LoginKey::Up }),
                "down" => Some(LoginAction::Key {
                    key: LoginKey::Down,
                }),
                "left" => Some(LoginAction::Key {
                    key: LoginKey::Left,
                }),
                "right" => Some(LoginAction::Key {
                    key: LoginKey::Right,
                }),
                _ => {
                    println!("  usage: key enter|tab|backspace|escape|space|up|down|left|right");
                    None
                }
            },
            other => {
                println!("  unknown command {other:?}; 'help' lists them");
                None
            }
        };
        if let Some(a) = act {
            let r: Result<Value> = ctx.client()?.call(Request::LoginInput {
                name: name.clone(),
                action: a,
            });
            match r {
                Ok(_) => {
                    if auto {
                        std::thread::sleep(Duration::from_millis(1500));
                        show(ctx, &name, columns)?;
                    }
                }
                Err(e) => println!("  not sent: {e}"),
            }
        }
    }
}

fn show(ctx: &Ctx, name: &AccountName, columns: u32) -> Result<()> {
    let s: ShotView = ctx
        .client()?
        .call(Request::LoginShot { name: name.clone() })?;
    let png = hrd_net::base64::decode(&s.png_base64)
        .ok_or_else(|| Error::Protocol("bad screenshot encoding".into()))?;
    let path = std::env::temp_dir().join(format!("hrd-login-{name}-{}.png", std::process::id()));
    fsutil::atomic_write(&path, &png, 0o600)?;
    match render_preview(&png, columns.clamp(40, 240)) {
        Ok(text) => print!("{text}"),
        Err(e) => println!("(no preview: {e})"),
    }
    println!("frame {}x{} px, full image: {} (copy it with scp; it is deleted when you leave the console)", s.width, s.height, path.display());
    register_cleanup(path);
    Ok(())
}

fn register_cleanup(path: std::path::PathBuf) {
    // The file lives until the process ends; the OS temp dir is private to us
    // only when TMPDIR is, so remove it at exit on a best-effort basis.
    static PATHS: std::sync::Mutex<Vec<std::path::PathBuf>> = std::sync::Mutex::new(Vec::new());
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            for p in PATHS.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
                let _ = std::fs::remove_file(p);
            }
        }
    }
    thread_local!(static G: Guard = const { Guard });
    PATHS.lock().unwrap_or_else(|e| e.into_inner()).push(path);
    G.with(|_| {});
}

/// The frame as half-block characters with true-colour escapes, between two
/// rulers in frame pixels so a click position can be read off.
pub fn render_preview(png_bytes: &[u8], columns: u32) -> std::result::Result<String, String> {
    let dec = png::Decoder::new(std::io::Cursor::new(png_bytes));
    let mut reader = dec.read_info().map_err(|e| e.to_string())?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;
    let (w, h) = (info.width as usize, info.height as usize);
    let ch = match info.color_type {
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        _ => return Err("unsupported PNG colour type".into()),
    };
    let px = |x: usize, y: usize| -> (u8, u8, u8) {
        let i = (y.min(h - 1) * w + x.min(w - 1)) * ch;
        match ch {
            1 | 2 => (buf[i], buf[i], buf[i]),
            _ => (buf[i], buf[i + 1], buf[i + 2]),
        }
    };
    let cols = (columns as usize).min(w).max(1);
    let step_x = w as f64 / cols as f64;
    let cell_h = step_x * 2.0; // a character cell is about twice as tall as wide
    let rows = ((h as f64 / cell_h).ceil() as usize).max(1);
    let mut out = String::new();
    // Top ruler.
    out.push_str("     ");
    let mut x = 0usize;
    while x < cols {
        let label = format!("{}", (x as f64 * step_x) as usize);
        out.push_str(&label);
        let pad = 10usize.saturating_sub(label.len());
        out.push_str(&" ".repeat(pad));
        x += 10;
    }
    out.push('\n');
    for r in 0..rows {
        out.push_str(&format!("{:>4} ", (r as f64 * cell_h) as usize));
        for c in 0..cols {
            let sx = (c as f64 * step_x) as usize;
            let top = px(sx, (r as f64 * cell_h) as usize);
            let bot = px(sx, ((r as f64 + 0.5) * cell_h) as usize);
            out.push_str(&format!(
                "\x1b[38;2;{};{};{};48;2;{};{};{}m\u{2580}",
                top.0, top.1, top.2, bot.0, bot.1, bot.2
            ));
        }
        out.push_str("\x1b[0m\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid_png(w: u32, h: u32, rgb: [u8; 3]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, w, h);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            let mut wr = enc.write_header().unwrap();
            let data: Vec<u8> = (0..w * h).flat_map(|_| rgb).collect();
            wr.write_image_data(&data).unwrap();
        }
        out
    }

    #[test]
    fn a_frame_becomes_rulers_and_coloured_cells() {
        let p = solid_png(640, 360, [10, 200, 30]);
        let s = render_preview(&p, 80).unwrap();
        assert!(s.contains("38;2;10;200;30"));
        assert!(s.lines().count() > 10);
        assert!(
            s.lines().next().unwrap().contains("80"),
            "ruler labels are frame pixels"
        );
        assert!(render_preview(b"not a png", 80).is_err());
    }
}
