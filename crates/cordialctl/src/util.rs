//! Output helpers: tables, units, the JSON/plain switch.

use std::io::Write;

use serde::Serialize;
use serde_json::Value;

use hrd_core::time::human_duration;
use hrd_core::Error;

pub const NM: &str = "not measured";

pub fn mib(b: Option<u64>) -> String {
    match b {
        Some(v) => format!("{:.1}", v as f64 / 1048576.0),
        None => "-".into(),
    }
}

pub fn mib_long(b: Option<u64>) -> String {
    match b {
        Some(v) => format!("{:.1} MiB ({} B)", v as f64 / 1048576.0, v),
        None => NM.into(),
    }
}

pub fn pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.0}")).unwrap_or_else(|| "-".into())
}

pub fn age(secs: Option<u64>) -> String {
    secs.map(human_duration).unwrap_or_else(|| "-".into())
}

pub fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    v.as_ref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "-".into())
}

/// Left-aligned columns; `right` marks numeric columns.
pub fn table(head: &[&str], rows: &[Vec<String>], right: &[usize]) -> String {
    let n = head.len();
    let mut w: Vec<usize> = head.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate().take(n) {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let mut out = String::new();
    let line = |cells: Vec<&str>, out: &mut String| {
        for (i, c) in cells.iter().enumerate() {
            let pad = w[i].saturating_sub(c.chars().count());
            if right.contains(&i) {
                out.push_str(&" ".repeat(pad));
                out.push_str(c);
            } else {
                out.push_str(c);
                if i + 1 < n {
                    out.push_str(&" ".repeat(pad));
                }
            }
            if i + 1 < n {
                out.push_str("  ");
            }
        }
        out.push('\n');
    };
    line(head.to_vec(), &mut out);
    for r in rows {
        line(r.iter().map(String::as_str).collect(), &mut out);
    }
    out
}

pub struct Out {
    pub json: bool,
}

impl Out {
    pub fn data<T: Serialize>(&self, v: &T) {
        let s = serde_json::to_string_pretty(v).unwrap_or_else(|_| "null".into());
        println!("{s}");
    }

    pub fn value(&self, v: &Value) {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    }

    pub fn line(&self, s: impl AsRef<str>) {
        if !self.json {
            println!("{}", s.as_ref());
        }
    }

    pub fn warn(&self, s: impl AsRef<str>) {
        eprintln!("cordialctl: {}", s.as_ref());
    }
}

pub fn report_error(json: bool, e: &Error) {
    if json {
        let v = serde_json::json!({ "ok": false, "error": { "code": e.code(), "message": e.to_string() } });
        println!("{v}");
    } else {
        eprintln!("cordialctl: {e}");
        if let Some(h) = hint(e) {
            eprintln!("  {h}");
        }
    }
    let _ = std::io::stdout().flush();
}

fn hint(e: &Error) -> Option<&'static str> {
    match e {
        Error::AuthRequired(_) => Some("sign the account in: cordialctl account login NAME"),
        Error::Denied(_) => Some("this needs a different user (root for network and install steps, a member of the cordial group otherwise)"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align_and_units_say_what_they_are() {
        let t = table(
            &["ID", "RSS"],
            &[
                vec!["alt-1".into(), "12.5".into()],
                vec!["b".into(), "1234.0".into()],
            ],
            &[1],
        );
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "ID       RSS");
        assert_eq!(lines[1], "alt-1   12.5");
        assert_eq!(lines[2], "b     1234.0");
        assert_eq!(mib(None), "-");
        assert_eq!(mib_long(None), "not measured");
        assert!(mib_long(Some(1048576)).starts_with("1.0 MiB"));
    }
}
