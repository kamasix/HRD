//! `hrd-import`: put a Roblox Android build into the runtime store.
//!
//! Normally run by `hrdd` with the operator's APKs passed as inherited file
//! descriptors (`--fd`), so that it reads exactly the files the operator opened.
//! It can also be run by hand as the service user with `--path`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use hrd_core::time::now_unix;
use hrd_core::{fsutil, Error, Result};
use hrd_import::import::{self, Input, PinnedVerifier, Request};
use hrd_import::store::Store;

const USAGE: &str = "\
usage:
  hrd-import import --store DIR (--path FILE-OR-DIR | --fd N[:NAME])... [--label TEXT]
                        [--make-current] [--trust-sha256 HEX]... [--json]
  hrd-import list   --store DIR [--json]
  hrd-import use    --store DIR VERSION
  hrd-import remove --store DIR VERSION [--in-use VERSION]...
  hrd-import verify --store DIR [VERSION] [--json]
  hrd-import fetch  --into DIR [--version NAME] [--list]
  hrd-import fetch  --check --store DIR   (is the mirror's newest build newer than the current one?)

`fetch` downloads the x86-64 Roblox build from the mirror upstream Cordial uses
(APKPure) into DIR and checks each file against Roblox's pinned signing
certificate; it installs nothing (run `import` on DIR afterwards). `--list`
prints the versions the mirror offers. Needs a network connection.

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
    into: Option<PathBuf>,
    version: Option<String>,
    list: bool,
    check: bool,
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
        into: None,
        version: None,
        list: false,
        check: false,
        positional: vec![],
    };
    while let Some(arg) = it.next() {
        let mut value = |what: &str| it.next().ok_or(format!("{what} needs a value"));
        match arg.as_str() {
            "--store" => a.store = Some(PathBuf::from(value("--store")?)),
            "--path" => a.paths.push(PathBuf::from(value("--path")?)),
            "--fd" => {
                let v = value("--fd")?;
                let (n, name) = v
                    .split_once(':')
                    .map(|(n, name)| (n, name.to_string()))
                    .unwrap_or((v.as_str(), String::new()));
                let n: i32 = n
                    .parse()
                    .map_err(|_| format!("--fd {v:?}: not a descriptor number"))?;
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
            "--into" => a.into = Some(PathBuf::from(value("--into")?)),
            "--version" => a.version = Some(value("--version")?),
            "--list" => a.list = true,
            "--check" => a.check = true,
            "--in-use" => a.in_use.push(value("--in-use")?),
            "-h" | "--help" => return Err(String::new()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => a.positional.push(arg),
        }
    }
    Ok(a)
}

fn safe_name(s: &str) -> String {
    let base = Path::new(s)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    base.chars()
        .filter(|c| c.is_ascii_graphic())
        .take(96)
        .collect()
}

fn expand_inputs(a: &Args) -> Result<Vec<Input>> {
    let mut out = Vec::new();
    for (n, name) in &a.fds {
        let f = File::open(format!("/proc/self/fd/{n}"))
            .map_err(|e| Error::io(format!("open inherited descriptor {n}"), e))?;
        let given = if name.is_empty() {
            format!("fd{n}")
        } else {
            safe_name(name)
        };
        out.push(Input {
            file: f,
            given_name: given,
        });
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
                return Err(Error::invalid(format!(
                    "{} holds no .apk files",
                    p.display()
                )));
            }
            for n in names {
                let f =
                    File::open(&n).map_err(|e| Error::io(format!("open {}", n.display()), e))?;
                out.push(Input {
                    file: f,
                    given_name: safe_name(&n.to_string_lossy()),
                });
            }
        } else {
            let f = File::open(p).map_err(|e| Error::io(format!("open {}", p.display()), e))?;
            out.push(Input {
                file: f,
                given_name: safe_name(&p.to_string_lossy()),
            });
        }
    }
    Ok(out)
}

/// `2.738.0.1397` (the engine's name for a build) and `2.738.1397` (the
/// mirror's) name the same build: compare on major, minor and build.
fn build_key(v: &str) -> Option<(u64, u64, u64)> {
    let n: Vec<u64> = v
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    match n.as_slice() {
        [a, b, c] => Some((*a, *b, *c)),
        [a, b, _, d] => Some((*a, *b, *d)),
        _ => None,
    }
}

fn check(a: &Args) -> Result<()> {
    use cordial_update::provider::mirror;
    let store = Store::new(
        a.store
            .clone()
            .ok_or_else(|| Error::invalid("--check needs --store DIR"))?,
    );
    let offered = mirror::offered().map_err(|e| Error::unavailable(e.to_string()))?;
    let newest = offered
        .iter()
        .max_by_key(|v| build_key(&v.name))
        .ok_or_else(|| Error::unavailable("the mirror lists no versions"))?;
    let installed: Vec<String> = store.list().into_iter().map(|b| b.version).collect();
    let have = installed.iter().filter_map(|v| build_key(v)).max();
    let newer = match (build_key(&newest.name), have) {
        (Some(n), Some(h)) => n > h,
        (Some(_), None) => true,
        _ => false,
    };
    println!(
        "{}",
        serde_json::json!({
            "newest": newest.name,
            "current": store.current(),
            "newer": newer,
        })
    );
    Ok(())
}

fn fetch(a: &Args) -> Result<()> {
    if a.check {
        return check(a);
    }
    use cordial_update::provider::{self, mirror, Cancel, Progress, Provider, Want};
    let unreachable = |e: cordial_update::Unreachable| Error::unavailable(e.to_string());
    if a.list {
        for v in mirror::offered().map_err(unreachable)? {
            println!("{}", v.name);
        }
        return Ok(());
    }
    let into = a
        .into
        .clone()
        .ok_or_else(|| Error::invalid("fetch needs --into DIR"))?;
    fsutil::ensure_private_dir(&into, 0o700)?;
    let cancel = Cancel::new();
    let mut last = String::new();
    let mut show = |p: Progress| {
        let line = match p {
            Progress::Asking { provider } => format!("asking {provider}"),
            Progress::Fetching { file, done, total } => match total {
                Some(t) => format!("downloading {file}: {} of {} MiB", done >> 20, t >> 20),
                None => format!("downloading {file}: {} MiB", done >> 20),
            },
            Progress::Verifying { file } => format!("checking Roblox's signature on {file}"),
        };
        // One line per state or per 25 MiB, not per chunk.
        let key = line.split(':').next().unwrap_or("").to_string();
        if key != last || line.contains("00 of") {
            eprintln!("progress: {line}");
            last = key;
        }
    };
    let (archives, name) = match &a.version {
        None => {
            let got = provider::obtain(Some("apkpure"), Want::Newest, &cancel, &into, &mut show)
                .map_err(unreachable)?;
            (got.archives, got.version.name)
        }
        Some(want) => {
            let offered = mirror::offered().map_err(unreachable)?;
            let v = offered.iter().find(|v| &v.name == want).ok_or_else(|| {
                Error::not_found(format!(
                    "the mirror does not list {want} for x86-64; it lists: {}",
                    offered
                        .iter()
                        .take(12)
                        .map(|v| v.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
            let archives = mirror::ApkPure
                .fetch(v, &cancel, &into, &mut show)
                .map_err(unreachable)?;
            // `obtain` verifies for us; a chosen version is verified here, and
            // again by `import`, against the same pinned certificates.
            let pinned = cordial_update::apk_signature::pinned();
            for f in archives.distinct() {
                cordial_update::apk_signature::verify_signed_by(f, &pinned).map_err(|e| {
                    Error::invalid(format!(
                        "{} is not signed by Roblox's pinned certificate: {e}",
                        f.display()
                    ))
                })?;
            }
            (archives, v.name.clone())
        }
    };
    println!("fetched Roblox {name}");
    for f in archives.distinct() {
        println!("{}", f.display());
    }
    Ok(())
}

fn run(a: Args) -> Result<()> {
    if a.cmd == "fetch" {
        return fetch(&a);
    }
    let store = Store::new(
        a.store
            .clone()
            .ok_or_else(|| Error::invalid("--store is required"))?,
    );
    match a.cmd.as_str() {
        "import" => {
            let inputs = expand_inputs(&a)?;
            let verifier = PinnedVerifier::with_extra(&a.trust);
            if !a.trust.is_empty() {
                eprintln!("progress: trusting {} extra certificate fingerprint(s) named on the command line", a.trust.len());
            }
            let report = import::run(
                &store,
                Request {
                    inputs,
                    label: a.label.clone(),
                    make_current: a.make_current,
                    verifier: &verifier,
                    now: now_unix(),
                },
                &mut |line| eprintln!("progress: {line}"),
            )?;
            if a.json {
                println!(
                    "{}",
                    serde_json::to_string(&report).map_err(|e| Error::Internal(e.to_string()))?
                );
            } else {
                println!(
                    "{} runtime {}{}",
                    if report.already_present {
                        "already installed:"
                    } else {
                        "installed:"
                    },
                    report.version,
                    if report.made_current {
                        " (now current)"
                    } else {
                        ""
                    }
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
                    println!(
                        "{:<16} {:<9} {} {}",
                        b.version,
                        mark,
                        hrd_core::time::rfc3339(b.imported_at),
                        if b.is_split() { "split" } else { "monolithic" }
                    );
                }
            }
            Ok(())
        }
        "use" => {
            let v = a
                .positional
                .first()
                .ok_or_else(|| Error::invalid("use needs a VERSION"))?;
            let _l = store.lock(Duration::from_secs(60))?;
            store.use_version(v)?;
            println!("current runtime is now {v}");
            Ok(())
        }
        "remove" => {
            let v = a
                .positional
                .first()
                .ok_or_else(|| Error::invalid("remove needs a VERSION"))?;
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
                return Err(Error::conflict(format!(
                    "{bad} runtime(s) failed verification"
                )));
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
                println!(
                    "{}",
                    serde_json::json!({ "error": { "code": e.code(), "message": e.to_string() } })
                );
            }
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_key;

    #[test]
    fn the_engines_name_and_the_mirrors_name_for_a_build_compare_equal() {
        assert_eq!(build_key("2.738.0.1397"), build_key("2.738.1397"));
        assert!(build_key("2.738.1397") > build_key("2.734.917"));
        assert!(build_key("2.738.1397") > build_key("2.738.1393"));
        assert_eq!(build_key("garbage"), None);
    }
}
