//! `cordial-import`: put a Roblox Android build into the runtime store.
//!
//! Normally run by `cordiald` with the operator's APKs passed as inherited file
//! descriptors (`--fd`), so that it reads exactly the files the operator opened.
//! It can also be run by hand as the service user with `--path`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use hrd_core::time::now_unix;
use hrd_core::{Error, Result};
use hrd_import::import::{self, Input, PinnedVerifier, Request};
use hrd_import::store::Store;

const USAGE: &str = "\
usage:
  cordial-import import --store DIR (--path FILE-OR-DIR | --fd N[:NAME])... [--label TEXT]
                        [--make-current] [--trust-sha256 HEX]... [--json]
  cordial-import list   --store DIR [--json]
  cordial-import use    --store DIR VERSION
  cordial-import remove --store DIR VERSION [--in-use VERSION]...
  cordial-import verify --store DIR [VERSION] [--json]

Imports verify the signature against the certificate pinned in upstream
Cordial, check that the certificate contains the signing key, and refuse
archives that are not one consistent build. Nothing is published unless every
check passes.
";

struct Args {
    cmd: String,
    store: Option<PathBuf>,
    paths: Vec<PathBuf>,
    fds: Vec<(i32, String)>,
    label: Option<String>,
    make_current: bool,
    trust: Vec<String>,
    json: bool,
    in_use: Vec<String>,
    positional: Vec<String>,
}

fn parse(argv: Vec<String>) -> std::result::Result<Args, String> {
    let mut it = argv.into_iter();
    let cmd = it.next().ok_or("missing command")?;
    let mut a = Args {
        cmd,
        store: None,
        paths: vec![],
        fds: vec![],
        label: None,
        make_current: false,
        trust: vec![],
        json: false,
        in_use: vec![],
        positional: vec![],
    };
    while let Some(arg) = it.next() {
        let mut value = |what: &str| it.next().ok_or(format!("{what} needs a value"));
        match arg.as_str() {
            "--store" => a.store = Some(PathBuf::from(value("--store")?)),
            "--path" => a.paths.push(PathBuf::from(value("--path")?)),
            "--fd" => {
                let v = value("--fd")?;
                let (n, name) = v.split_once(':').map(|(n, name)| (n, name.to_string())).unwrap_or((v.as_str(), String::new()));
                let n: i32 = n.parse().map_err(|_| format!("--fd {v:?}: not a descriptor number"))?;
                if n < 3 {
                    return Err("--fd must be 3 or higher".into());
                }
                a.fds.push((n, name));
            }
            "--label" => a.label = Some(value("--label")?),
            "--make-current" => a.make_current = true,
            "--trust-sha256" => {
                let v = value("--trust-sha256")?.to_ascii_lowercase();
                if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("--trust-sha256 wants 64 hex digits".into());
                }
                a.trust.push(v);
            }
            "--json" => a.json = true,
            "--in-use" => a.in_use.push(value("--in-use")?),
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => a.positional.push(arg),
        }
    }
    Ok(a)
}

fn safe_name(s: &str) -> String {
    let base = Path::new(s).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    base.chars().filter(|c| c.is_ascii_graphic()).take(96).collect()
}

fn expand_inputs(a: &Args) -> Result<Vec<Input>> {
    let mut out = Vec::new();
    for (n, name) in &a.fds {
        let f = File::open(format!("/proc/self/fd/{n}")).map_err(|e| Error::io(format!("open inherited descriptor {n}"), e))?;
        let given = if name.is_empty() { format!("fd{n}") } else { safe_name(name) };
        out.push(Input { file: f, given_name: given });
    }
    for p in &a.paths {
        let md = std::fs::metadata(p).map_err(|e| Error::io(format!("stat {}", p.display()), e))?;
        if md.is_dir() {
            let mut names: Vec<PathBuf> = std::fs::read_dir(p)
                .map_err(|e| Error::io(format!("read {}", p.display()), e))?
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("apk")))
                .filter(|p| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false))
                .collect();
            names.sort();
            if names.is_empty() {
                return Err(Error::invalid(format!("{} holds no .apk files", p.display())));
            }
            for n in names {
                let f = File::open(&n).map_err(|e| Error::io(format!("open {}", n.display()), e))?;
                out.push(Input { file: f, given_name: safe_name(&n.to_string_lossy()) });
            }
        } else {
            let f = File::open(p).map_err(|e| Error::io(format!("open {}", p.display()), e))?;
            out.push(Input { file: f, given_name: safe_name(&p.to_string_lossy()) });
        }
    }
    Ok(out)
}

fn run(a: Args) -> Result<()> {
    let store = Store::new(a.store.clone().ok_or_else(|| Error::invalid("--store is required"))?);
    match a.cmd.as_str() {
        "import" => {
            let inputs = expand_inputs(&a)?;
            let verifier = PinnedVerifier::with_extra(&a.trust);
            if !a.trust.is_empty() {
                eprintln!("progress: trusting {} extra certificate fingerprint(s) named on the command line", a.trust.len());
            }
            let report = import::run(
                &store,
                Request { inputs, label: a.label.clone(), make_current: a.make_current, verifier: &verifier, now: now_unix() },
                &mut |line| eprintln!("progress: {line}"),
            )?;
            if a.json {
                println!("{}", serde_json::to_string(&report).map_err(|e| Error::Internal(e.to_string()))?);
            } else {
                println!(
                    "{} runtime {}{}",
                    if report.already_present { "already installed:" } else { "installed:" },
                    report.version,
                    if report.made_current { " (now current)" } else { "" }
                );
                for w in &report.warnings {
                    println!("warning: {w}");
                }
            }
            Ok(())
        }
        "list" => {
            let builds = store.list();
            if a.json {
                let v = serde_json::json!({ "current": store.current(), "previous": store.previous(), "builds": builds });
                println!("{v}");
            } else if builds.is_empty() {
                println!("no runtime is installed");
            } else {
                let cur = store.current();
                let prev = store.previous();
                for b in builds {
                    let mark = if cur.as_deref() == Some(&b.version) {
                        "current"
                    } else if prev.as_deref() == Some(&b.version) {
                        "previous"
                    } else {
                        ""
                    };
                    println!("{:<16} {:<9} {} {}", b.version, mark, hrd_core::time::rfc3339(b.imported_at), if b.is_split() { "split" } else { "monolithic" });
                }
            }
            Ok(())
        }
        "use" => {
            let v = a.positional.first().ok_or_else(|| Error::invalid("use needs a VERSION"))?;
            let _l = store.lock(Duration::from_secs(60))?;
            store.use_version(v)?;
            println!("current runtime is now {v}");
            Ok(())
        }
        "remove" => {
            let v = a.positional.first().ok_or_else(|| Error::invalid("remove needs a VERSION"))?;
            let _l = store.lock(Duration::from_secs(60))?;
            store.remove(v, &a.in_use)?;
            println!("removed runtime {v}");
            Ok(())
        }
        "verify" => {
            let versions: Vec<String> = match a.positional.first() {
                Some(v) => vec![v.clone()],
                None => store.list().into_iter().map(|m| m.version).collect(),
            };
            let mut bad = 0;
            let mut results = Vec::new();
            for v in &versions {
                let problems = import::verify_build(&store, v)?;
                if !problems.is_empty() {
                    bad += 1;
                }
                if a.json {
                    results.push(serde_json::json!({ "version": v, "problems": problems }));
                } else if problems.is_empty() {
                    println!("{v}: ok");
                } else {
                    for p in &problems {
                        println!("{v}: {p}");
                    }
                }
            }
            if a.json {
                println!("{}", serde_json::Value::Array(results));
            }
            if bad > 0 {
                return Err(Error::conflict(format!("{bad} runtime(s) failed verification")));
            }
            Ok(())
        }
        other => Err(Error::invalid(format!("unknown command {other:?}"))),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(argv) {
        Ok(a) => a,
        Err(m) => {
            if !m.is_empty() {
                eprintln!("error: {m}");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let json = args.json;
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "error": { "code": e.code(), "message": e.to_string() } }));
            }
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
