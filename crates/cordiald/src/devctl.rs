//! The sign-in console's link to a sign-in client.
//!
//! Cordial has a small development control surface (`devctl.rs` upstream): a
//! Unix socket that takes one text line per command and answers `ok ...` or
//! `err ...`. The daemon starts it **only** for sign-in runs, in a directory only
//! the service user can enter, and only ever sends four kinds of line: a
//! screenshot request, a click, typed text and a key. Each is one operator
//! action; there is no loop, no timer and no replay here.
//!
//! The text of a `text` action can be a password. It is written to the socket and
//! forgotten: it is not logged, not stored and not echoed in an error.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use hrd_core::proto::{LoginAction, ShotView};
use hrd_core::time::now_unix;
use hrd_core::{Error, Result};

fn exchange(sock: &Path, line: &str, timeout: Duration) -> Result<String> {
    let mut s = UnixStream::connect(sock).map_err(|e| {
        Error::unavailable(format!(
            "the sign-in client's control surface is not reachable yet ({e}); wait for it to start"
        ))
    })?;
    s.set_read_timeout(Some(timeout))
        .and_then(|_| s.set_write_timeout(Some(timeout)))
        .map_err(|e| Error::io("socket timeout", e))?;
    s.write_all(line.as_bytes())
        .and_then(|_| s.write_all(b"\n"))
        .map_err(|e| Error::io("write to the sign-in client", e))?;
    let mut reply = String::new();
    // A reply is one short line; a client that never ends its line cannot make
    // the daemon buffer more than this.
    BufReader::new((&s).take(1 << 20)).take_line(&mut reply)?;
    Ok(reply)
}

trait TakeLine {
    fn take_line(&mut self, out: &mut String) -> Result<()>;
}

impl<R: BufRead> TakeLine for R {
    fn take_line(&mut self, out: &mut String) -> Result<()> {
        self.read_line(out)
            .map_err(|e| Error::io("read from the sign-in client", e))?;
        Ok(())
    }
}

fn check_ok(reply: &str, what: &str) -> Result<()> {
    let r = reply.trim();
    if r == "ok" || r.starts_with("ok ") {
        Ok(())
    } else if r.is_empty() {
        Err(Error::unavailable(format!(
            "the sign-in client did not answer {what}"
        )))
    } else {
        // Replies never contain the typed text, but cap what is passed on.
        Err(Error::unavailable(format!(
            "the sign-in client refused {what}: {}",
            r.chars().take(200).collect::<String>()
        )))
    }
}

/// Turn an action into the one line that performs it.
pub fn line_for(action: &LoginAction, max_text: usize) -> Result<String> {
    match action {
        LoginAction::Click { x, y } => {
            if *x > 16384 || *y > 16384 {
                return Err(Error::invalid("click coordinates are outside any frame"));
            }
            Ok(format!("click {x} {y}"))
        }
        LoginAction::Key { key } => Ok(format!("tap {}", key.evdev())),
        LoginAction::Text { text } => {
            if text.is_empty() {
                return Err(Error::invalid("there is no text to type"));
            }
            if text.chars().count() > max_text {
                return Err(Error::invalid(format!(
                    "at most {max_text} characters per request"
                )));
            }
            if text.chars().any(|c| c == '\n' || c == '\r' || c == '\0') {
                return Err(Error::invalid(
                    "text may not contain a line break (use the Enter key)",
                ));
            }
            Ok(format!("text {text}"))
        }
    }
}

pub fn perform(sock: &Path, action: &LoginAction, max_text: usize) -> Result<()> {
    let line = line_for(action, max_text)?;
    let reply = exchange(sock, &line, Duration::from_secs(5))?;
    check_ok(&reply, "the action")
}

/// PNG dimensions from its header, without decoding the image.
pub fn png_size(b: &[u8]) -> Option<(u32, u32)> {
    if b.len() < 24 || &b[..8] != b"\x89PNG\r\n\x1a\n" || &b[12..16] != b"IHDR" {
        return None;
    }
    Some((
        u32::from_be_bytes(b[16..20].try_into().ok()?),
        u32::from_be_bytes(b[20..24].try_into().ok()?),
    ))
}

pub fn screenshot(sock: &Path, file: &Path) -> Result<ShotView> {
    let _ = std::fs::remove_file(file);
    let reply = exchange(
        sock,
        &format!("screenshot {}", file.display()),
        Duration::from_secs(15),
    )?;
    check_ok(&reply, "the screenshot")?;
    let bytes = hrd_core::fsutil::read_limited(file, 16 * 1024 * 1024)?;
    let _ = std::fs::remove_file(file);
    let (width, height) =
        png_size(&bytes).ok_or_else(|| Error::unavailable("the screenshot is not a PNG"))?;
    Ok(ShotView {
        width,
        height,
        png_base64: hrd_net::base64::encode(&bytes),
        taken_at: now_unix(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hrd_core::proto::LoginKey;
    use std::os::unix::net::UnixListener;

    #[test]
    fn actions_become_exactly_one_safe_line() {
        assert_eq!(
            line_for(&LoginAction::Click { x: 10, y: 20 }, 10).unwrap(),
            "click 10 20"
        );
        assert_eq!(
            line_for(
                &LoginAction::Key {
                    key: LoginKey::Enter
                },
                10
            )
            .unwrap(),
            "tap 28"
        );
        assert_eq!(
            line_for(
                &LoginAction::Text {
                    text: "abc def".into()
                },
                10
            )
            .unwrap(),
            "text abc def"
        );
        for bad in ["", "a\nscreenshot /etc/x", "a\rb", "0123456789X"] {
            assert!(
                line_for(&LoginAction::Text { text: bad.into() }, 10).is_err(),
                "{bad:?}"
            );
        }
        assert!(line_for(&LoginAction::Click { x: 99999, y: 1 }, 10).is_err());
    }

    #[test]
    fn the_typed_text_is_not_in_errors() {
        let e = line_for(
            &LoginAction::Text {
                text: "secret\nx".into(),
            },
            100,
        )
        .unwrap_err()
        .to_string();
        assert!(!e.contains("secret"), "{e}");
    }

    #[test]
    fn a_fake_surface_round_trips_click_and_screenshot() {
        let d = std::env::temp_dir().join(format!("hrd-devctl-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let sock = d.join("s");
        let l = UnixListener::bind(&sock).unwrap();
        let shot = d.join("shot.png");
        let shot2 = shot.clone();
        let t = std::thread::spawn(move || {
            for s in l.incoming().take(2).flatten() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let mut w = s;
                if line.starts_with("screenshot ") {
                    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
                    png.extend_from_slice(&640u32.to_be_bytes());
                    png.extend_from_slice(&360u32.to_be_bytes());
                    std::fs::write(&shot2, png).unwrap();
                    writeln!(w, "ok 640x360").unwrap();
                } else {
                    assert_eq!(line.trim(), "click 5 6");
                    writeln!(w, "ok").unwrap();
                }
            }
        });
        perform(&sock, &LoginAction::Click { x: 5, y: 6 }, 10).unwrap();
        let v = screenshot(&sock, &shot).unwrap();
        assert_eq!((v.width, v.height), (640, 360));
        assert!(hrd_net::base64::decode(&v.png_base64).is_some());
        t.join().unwrap();
        assert!(perform(&d.join("missing"), &LoginAction::Click { x: 1, y: 1 }, 10).is_err());
        std::fs::remove_dir_all(d).ok();
    }
}
