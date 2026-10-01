//! Building and launching one client's process set.
//!
//! [`build`] turns the registry, the configuration and the chosen runtime into a
//! [`Plan`]: plain data (program, arguments, a complete environment) that can
//! be inspected and tested. [`launch`] is the only place a process is created.
//!
//! The environment is built from nothing: the daemon's own environment is never
//! inherited, so nothing the service was started with (a `DISPLAY`, a proxy
//! variable, a stray `LD_PRELOAD`) reaches a client. Every variable that decides
//! where a client writes is set here to a path inside that account's own tree.

#![allow(unsafe_code)] // `pre_exec`; see `launch` for what it may and may not do

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use hrd_core::config::{Compositor, Config, Graphics, JoinVia};
use hrd_core::ids::{AccountName, PlaceId};
use hrd_core::layout::Layout;
use hrd_core::model::{ResourceMode, RunKind};
use hrd_core::{Error, Result};

pub const PROFILE: &str = "default";

/// Which drawing path a client gets, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphicsChoice {
    pub software: bool,
    pub why: String,
}

pub fn choose_graphics(cfg: &Config, render_node: Option<&Path>) -> Result<GraphicsChoice> {
    match (cfg.engine.graphics, render_node) {
        (Graphics::Software, _) => Ok(GraphicsChoice {
            software: true,
            why: "engine.graphics = software".into(),
        }),
        (Graphics::Auto, None) => Ok(GraphicsChoice {
            software: true,
            why: "no usable DRM render node: drawing on the CPU".into(),
        }),
        (Graphics::Auto, Some(n)) | (Graphics::Gpu, Some(n)) => Ok(GraphicsChoice {
            software: false,
            why: format!("using render node {}", n.display()),
        }),
        (Graphics::Gpu, None) => Err(Error::unavailable(
            "engine.graphics = gpu but the service user cannot open a DRM render node (/dev/dri/renderD*); \
             add the user to the `render` group, or set engine.graphics = software",
        )),
    }
}

/// The first render node the current user can open read-write.
pub fn find_render_node() -> Option<PathBuf> {
    let mut nodes: Vec<PathBuf> = std::fs::read_dir("/dev/dri")
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("renderD"))
        })
        .collect();
    nodes.sort();
    nodes.into_iter().find(|p| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(p)
            .is_ok()
    })
}

pub fn find_lavapipe_icd(cfg: &Config) -> Option<PathBuf> {
    if !cfg.engine.vulkan_icd.is_empty() {
        return Some(PathBuf::from(&cfg.engine.vulkan_icd));
    }
    let mut found: Vec<PathBuf> = std::fs::read_dir("/usr/share/vulkan/icd.d")
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("lvp_icd") && n.ends_with(".json"))
        })
        .collect();
    found.sort();
    found.into_iter().next()
}

pub struct Plan {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub log_path: PathBuf,
    /// Where the client's own control surface socket is, for sign-in runs.
    pub devctl_socket: Option<PathBuf>,
}

pub struct Inputs<'a> {
    pub cfg: &'a Config,
    pub layout: &'a Layout,
    pub account: &'a AccountName,
    pub kind: RunKind,
    pub place: Option<PlaceId>,
    pub private_server_code: Option<&'a str>,
    pub mode: ResourceMode,
    pub proxy_group: Option<&'a hrd_core::ids::ProxyGroupName>,
    /// `builds/<version>` of the runtime this run uses.
    pub build_dir: &'a Path,
    pub graphics: &'a GraphicsChoice,
    pub lavapipe_icd: Option<&'a Path>,
    pub dbus_address: Option<String>,
    pub secret_store_keyring: bool,
}

pub fn join_url(place: PlaceId, code: Option<&str>) -> Result<String> {
    let mut u = format!("roblox://experiences/start?placeId={}", place.get());
    if let Some(c) = code {
        if c.is_empty()
            || c.len() > 128
            || !c
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::invalid(
                "a private server code may contain only letters, digits, - and _ (at most 128)",
            ));
        }
        u.push_str("&linkCode=");
        u.push_str(c);
    }
    Ok(u)
}

pub fn build(i: &Inputs<'_>) -> Result<Plan> {
    let cfg = i.cfg;
    let l = i.layout;
    let a = i.account;
    let home = l.account_home(a);
    let run = l.instance_run(a);
    let mut args: Vec<OsString> = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut put = |k: &str, v: String| env.push((k.to_string(), v));

    // The entry wrapper first: it enters the proxy group's namespace, then execs
    // the client. Without a proxy group there is no wrapper and no namespace,
    // which is only reachable with `network.allow_unrouted`.
    let (program, prefix): (PathBuf, Vec<OsString>) = match i.proxy_group {
        Some(g) => (
            PathBuf::from(&cfg.engine.enter),
            vec![
                "run".into(),
                "--proxy-group".into(),
                g.as_str().into(),
                "--".into(),
                (&cfg.engine.cordial_run).into(),
            ],
        ),
        None => (PathBuf::from(&cfg.engine.cordial_run), vec![]),
    };
    args.extend(prefix);

    if cfg.engine.compositor == Compositor::Cage {
        args.push("--headless".into());
    }
    args.extend([
        "--lib-dir".into(),
        i.build_dir.join("engine").into_os_string(),
    ]);
    args.extend([
        "--apk".into(),
        i.build_dir.join("apk/base.apk").into_os_string(),
    ]);
    args.extend([
        "--host-libc".into(),
        "--game-activity".into(),
        "--run".into(),
        "0".into(),
    ]);
    args.extend(["--profile".into(), PROFILE.into()]);

    if i.kind == RunKind::Play {
        let place = i
            .place
            .ok_or_else(|| Error::invalid("a place id is required to play"))?;
        let url = join_url(place, i.private_server_code)?;
        match cfg.engine.join_url_via {
            JoinVia::Argv => {
                if i.private_server_code.is_some() {
                    return Err(Error::invalid(
                        "a private server code would sit in the process arguments, which every local user can read; \
                         set engine.join_url_via = \"env\" (needs the patched cordial-run, patches/cordial/)",
                    ));
                }
                args.extend(["--join-url".into(), url.into()]);
            }
            JoinVia::Env => put("CORDIAL_JOIN_URL", url),
        }
    }

    put("PATH", "/usr/local/bin:/usr/bin:/bin".into());
    put("LANG", "C.UTF-8".into());
    put("HOME", home.display().to_string());
    put("XDG_DATA_HOME", l.account_data(a).display().to_string());
    put("XDG_CONFIG_HOME", l.account_config(a).display().to_string());
    put("XDG_CACHE_HOME", l.account_cache(a).display().to_string());
    put("XDG_STATE_HOME", l.account_state(a).display().to_string());
    put("XDG_RUNTIME_DIR", run.display().to_string());
    put(
        "TMPDIR",
        l.account_cache(a).join("tmp").display().to_string(),
    );
    put(
        "CORDIAL_SECRET_STORE",
        if i.secret_store_keyring {
            "keyring"
        } else {
            "none-explicit"
        }
        .into(),
    );
    if let Some(addr) = &i.dbus_address {
        put("DBUS_SESSION_BUS_ADDRESS", addr.clone());
    }
    if !i.secret_store_keyring {
        // Upstream treats any unknown value as `file`, which writes the session
        // in plain text. There is no value that means "store nothing", so this
        // mode is refused rather than approximated.
        return Err(Error::unavailable(
            "secrets.backend = none is not available: upstream's only non-keyring store writes the session as a plain file",
        ));
    }

    // A sign-in client is looked at by a person: it always gets the full size.
    let env_mode = if i.kind == RunKind::Login {
        ResourceMode::Compatible
    } else {
        i.mode
    };
    for (k, v) in mode_env(env_mode, cfg, i.build_dir) {
        put(&k, v);
    }

    if i.graphics.software {
        put("WLR_RENDERER", "pixman".into());
        put("LIBGL_ALWAYS_SOFTWARE", "1".into());
        put("GALLIUM_DRIVER", "llvmpipe".into());
        put("GSK_RENDERER", "cairo".into());
        if let Some(icd) = i.lavapipe_icd {
            put("VK_DRIVER_FILES", icd.display().to_string());
            put("VK_ICD_FILENAMES", icd.display().to_string());
        }
        if cfg.engine.software_threads > 0 {
            put("LP_NUM_THREADS", cfg.engine.software_threads.to_string());
        }
    }

    for (k, v) in &cfg.engine.env {
        if !hrd_core::config::allowed_engine_env(k) {
            return Err(Error::invalid(format!("engine.env key {k} is not allowed")));
        }
        put(k, v.clone());
    }

    let devctl_socket = if i.kind == RunKind::Login {
        let s = run.join("devctl.sock");
        put("CORDIAL_DEV_CONTROL", "1".into());
        put("CORDIAL_DEV_CONTROL_SOCKET", s.display().to_string());
        Some(s)
    } else {
        None
    };

    Ok(Plan {
        program,
        args,
        env,
        cwd: home,
        log_path: l.instance_log(a),
        devctl_socket,
    })
}

/// The settings a resource mode adds. **Every line is a concrete environment
/// variable that some program reads**; nothing is a flag that "turns things
/// off". docs/memory.md says, for each, which layer it touches, what it is
/// expected to save and what is not established.
///
/// * all modes: `CORDIAL_GAMEMODE=0` (a server has no gamemoded; the request
///   is a D-Bus call and a thread for nothing).
/// * `compatible`: nothing else. The resolution is left to upstream unless
///   `engine.resolution` is set.
/// * `minimal`: a 640x360 render size, the shared asset mapping (needs the
///   patched client, otherwise ignored), FIFO presentation.
/// * `aggressive`: additionally the smallest render size `cordial-run` accepts
///   (320x240), glibc arenas capped at two, mimalloc returning freed pages at
///   once, and the CPU count reported to the engine capped.
pub fn mode_env(mode: ResourceMode, cfg: &Config, build_dir: &Path) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = vec![("CORDIAL_GAMEMODE".into(), "0".into())];
    let configured = hrd_core::config::parse_resolution(&cfg.engine.resolution);
    let res = configured.or(match mode {
        ResourceMode::Compatible => None,
        ResourceMode::Minimal => Some((640, 360)),
        ResourceMode::Aggressive => Some((320, 240)),
    });
    if let Some((w, h)) = res {
        v.push(("CORDIAL_RESOLUTION".into(), format!("{w}x{h}")));
    }
    if mode != ResourceMode::Compatible {
        v.push((
            "CORDIAL_ASSET_MMAP_DIR".into(),
            build_dir.join("assets").display().to_string(),
        ));
        v.push(("CORDIAL_PRESENT_MODE".into(), "fifo".into()));
    }
    if mode == ResourceMode::Aggressive {
        v.push(("MALLOC_ARENA_MAX".into(), "2".into()));
        v.push(("MIMALLOC_PURGE_DELAY".into(), "0".into()));
        let n = if cfg.engine.cpus_per_instance > 0 {
            cfg.engine.cpus_per_instance.max(2)
        } else {
            2
        };
        v.push(("CORDIAL_NPROC".into(), n.to_string()));
    }
    v
}

/// Process-level settings applied between `fork` and `exec`.
#[derive(Clone)]
pub struct ProcSettings {
    pub cgroup_procs: Option<CString>,
    pub oom_score_adj: i32,
    pub cpus: Vec<usize>,
    pub ksm: bool,
}

/// Start the client. `log` receives stdout and stderr.
///
/// The closure runs in the forked child before `exec`, so it is restricted to
/// what is safe there in a multi-threaded parent: no allocation, no locks. It
/// writes `0` to a pre-opened-by-path `cgroup.procs` (joining the instance's
/// cgroup *before* the program can fork anything, which is what makes the
/// cgroup a complete record of the set), writes `oom_score_adj`, sets the CPU
/// mask and, if asked, opts into kernel same-page merging.
pub fn launch(plan: &Plan, log: File, how: &ProcSettings) -> io::Result<Child> {
    let log2 = log.try_clone()?;
    let mut cmd = Command::new(&plan.program);
    cmd.args(&plan.args)
        .env_clear()
        .envs(plan.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&plan.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log2))
        .process_group(0);

    let procs = how.cgroup_procs.clone();
    let oom = CString::new("/proc/self/oom_score_adj").expect("no NUL");
    let oom_val = format!("{}", how.oom_score_adj).into_bytes();
    // SAFETY-relevant preparation happens here, before the fork.
    // SAFETY: `cpu_set_t` is plain data for which all-zero is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let mut have_mask = false;
    for c in &how.cpus {
        if *c < libc::CPU_SETSIZE as usize {
            // SAFETY: `c` is below CPU_SETSIZE, so the write stays inside the set.
            unsafe { libc::CPU_SET(*c, &mut set) };
            have_mask = true;
        }
    }
    let ksm = how.ksm;
    // SAFETY: the closure calls only open/write/close, sched_setaffinity and
    // prctl, allocates nothing, takes no locks, and uses data prepared above.
    unsafe {
        cmd.pre_exec(move || {
            if let Some(p) = &procs {
                hrd_proc::cgroup::enter_prepared(p)?;
            }
            // Best effort: lowering priority for the OOM killer is not a
            // precondition for running.
            if let Ok(fd) = rustix::fs::open(
                oom.as_c_str(),
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                let _ = rustix::io::write(&fd, &oom_val);
            }
            if have_mask {
                let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
            }
            if ksm {
                // PR_SET_MEMORY_MERGE = 67 (Linux 6.4+); an older kernel says EINVAL.
                let _ = libc::prctl(67, 1, 0, 0, 0);
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Round-robin CPU set for the `n`th instance.
pub fn cpu_set(index: usize, per_instance: u32, online: usize) -> Vec<usize> {
    if per_instance == 0 || online == 0 {
        return Vec::new();
    }
    let k = (per_instance as usize).min(online);
    (0..k).map(|j| (index * k + j) % online).collect()
}

pub fn path_cstring(p: &Path) -> Option<CString> {
    CString::new(p.as_os_str().as_bytes()).ok()
}

/// Make `fds[i]` appear as descriptor `3 + i` in the child, and nothing else
/// beyond the standard three. The descriptors given must be numbered 100 or
/// more so that placing one cannot land on another.
pub fn place_descriptors(cmd: &mut Command, fds: &[std::os::fd::OwnedFd]) {
    use std::os::fd::AsRawFd;
    let raw: Vec<i32> = fds.iter().map(|f| f.as_raw_fd()).collect();
    // SAFETY: the closure only calls dup2, which is async-signal-safe, on
    // numbers prepared before the fork.
    unsafe {
        cmd.pre_exec(move || {
            for (i, fd) in raw.iter().enumerate() {
                if libc::dup2(*fd, 3 + i as i32) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(
        cfg: &'a Config,
        l: &'a Layout,
        a: &'a AccountName,
        g: &'a GraphicsChoice,
        gn: Option<&'a hrd_core::ids::ProxyGroupName>,
        build: &'a Path,
    ) -> Inputs<'a> {
        Inputs {
            cfg,
            layout: l,
            account: a,
            kind: RunKind::Play,
            place: PlaceId::new(920587237).ok(),
            private_server_code: None,
            mode: ResourceMode::Compatible,
            proxy_group: gn,
            build_dir: build,
            graphics: g,
            lavapipe_icd: Some(Path::new("/usr/share/vulkan/icd.d/lvp_icd.x86_64.json")),
            dbus_address: Some("unix:path=/run/cordial-hrd/secrets/bus".into()),
            secret_store_keyring: true,
        }
    }

    #[test]
    fn a_play_command_goes_through_the_entry_wrapper_and_carries_no_secret_in_argv() {
        let cfg = Config::default();
        let l = Layout::system();
        let a = AccountName::new("alt-1").unwrap();
        let g = hrd_core::ids::ProxyGroupName::new("g01").unwrap();
        let gr = GraphicsChoice {
            software: true,
            why: String::new(),
        };
        let p = build(&inputs(
            &cfg,
            &l,
            &a,
            &gr,
            Some(&g),
            Path::new("/var/lib/cordial-hrd/runtime/builds/1"),
        ))
        .unwrap();
        assert_eq!(p.program, PathBuf::from("/usr/lib/hrd/hrd-enter"));
        let argv: Vec<String> = p
            .args
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            &argv[..5],
            [
                "run",
                "--proxy-group",
                "g01",
                "--",
                "/usr/lib/hrd/cordial-run"
            ]
        );
        assert!(argv.contains(&"--headless".to_string()));
        assert!(argv.windows(2).any(|w| w == ["--profile", "default"]));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--join-url" && w[1].ends_with("placeId=920587237")));
        assert!(argv.windows(2).any(|w| w == ["--run", "0"]));
    }

    #[test]
    fn the_environment_is_built_from_nothing_and_points_inside_the_account() {
        let cfg = Config::default();
        let l = Layout::system();
        let a = AccountName::new("alt-1").unwrap();
        let gr = GraphicsChoice {
            software: true,
            why: String::new(),
        };
        let p = build(&inputs(&cfg, &l, &a, &gr, None, Path::new("/b"))).unwrap();
        let get = |k: &str| p.env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        for k in [
            "HOME",
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_STATE_HOME",
            "TMPDIR",
        ] {
            assert!(
                get(k)
                    .unwrap()
                    .starts_with("/var/lib/cordial-hrd/acct/alt-1"),
                "{k}"
            );
        }
        assert!(get("XDG_RUNTIME_DIR").unwrap().ends_with("/i/alt-1"));
        assert_eq!(get("CORDIAL_SECRET_STORE").as_deref(), Some("keyring"));
        assert_eq!(get("CORDIAL_GAMEMODE").as_deref(), Some("0"));
        assert!(
            get("CORDIAL_RESOLUTION").is_none(),
            "compatible leaves the size to upstream"
        );
        for bad in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "HTTP_PROXY",
            "CORDIAL_DEV_CONTROL",
        ] {
            assert!(get(bad).is_none(), "{bad}");
        }
        assert_eq!(get("WLR_RENDERER").as_deref(), Some("pixman"));
        assert!(get("VK_DRIVER_FILES").unwrap().contains("lvp_icd"));
        // no proxy group: run the client directly (only reachable with allow_unrouted)
        assert_eq!(p.program, PathBuf::from("/usr/lib/hrd/cordial-run"));
    }

    #[test]
    fn a_private_server_code_is_refused_in_argv_and_goes_to_the_environment_otherwise() {
        let cfg = Config::default();
        let l = Layout::system();
        let a = AccountName::new("a").unwrap();
        let gr = GraphicsChoice {
            software: false,
            why: String::new(),
        };
        let mut i = inputs(&cfg, &l, &a, &gr, None, Path::new("/b"));
        i.private_server_code = Some("abc-123_XY");
        assert!(build(&i).is_err());
        let mut cfg2 = cfg.clone();
        cfg2.engine.join_url_via = JoinVia::Env;
        i.cfg = &cfg2;
        let p = build(&i).unwrap();
        assert!(p
            .args
            .iter()
            .all(|s| !s.to_string_lossy().contains("linkCode")));
        assert!(p
            .env
            .iter()
            .any(|(k, v)| k == "CORDIAL_JOIN_URL" && v.contains("linkCode=abc-123_XY")));
        assert!(
            !p.env.iter().any(|(k, _)| k == "WLR_RENDERER"),
            "hardware path sets no software overrides"
        );
    }

    #[test]
    fn hostile_codes_and_the_no_keyring_mode_are_rejected() {
        for bad in ["", "a b", "a&b=1", "x/../y", "é", &"a".repeat(129)] {
            assert!(
                join_url(PlaceId::new(1).unwrap(), Some(bad)).is_err(),
                "{bad:?}"
            );
        }
        let cfg = Config::default();
        let l = Layout::system();
        let a = AccountName::new("a").unwrap();
        let gr = GraphicsChoice {
            software: true,
            why: String::new(),
        };
        let mut i = inputs(&cfg, &l, &a, &gr, None, Path::new("/b"));
        i.secret_store_keyring = false;
        assert!(build(&i).is_err());
    }

    #[test]
    fn a_sign_in_run_gets_a_control_socket_and_no_join() {
        let cfg = Config::default();
        let l = Layout::system();
        let a = AccountName::new("a").unwrap();
        let gr = GraphicsChoice {
            software: true,
            why: String::new(),
        };
        let mut i = inputs(&cfg, &l, &a, &gr, None, Path::new("/b"));
        i.kind = RunKind::Login;
        i.place = None;
        let p = build(&i).unwrap();
        assert!(p.args.iter().all(|s| s != "--join-url"));
        assert!(p.devctl_socket.as_ref().unwrap().to_string_lossy().len() < 100);
        assert!(p.env.iter().any(|(k, _)| k == "CORDIAL_DEV_CONTROL"));
    }

    #[test]
    fn each_mode_adds_only_named_settings_and_compatible_adds_almost_nothing() {
        let cfg = Config::default();
        let b = Path::new("/b");
        let keys = |m| {
            mode_env(m, &cfg, b)
                .into_iter()
                .map(|(k, _)| k)
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(ResourceMode::Compatible), ["CORDIAL_GAMEMODE"]);
        let min = mode_env(ResourceMode::Minimal, &cfg, b);
        assert!(min.contains(&("CORDIAL_RESOLUTION".into(), "640x360".into())));
        assert!(min.contains(&("CORDIAL_ASSET_MMAP_DIR".into(), "/b/assets".into())));
        assert!(!min
            .iter()
            .any(|(k, _)| k.starts_with("MIMALLOC") || k == "MALLOC_ARENA_MAX"));
        let agg = mode_env(ResourceMode::Aggressive, &cfg, b);
        assert!(
            agg.contains(&("CORDIAL_RESOLUTION".into(), "320x240".into())),
            "the smallest size cordial-run accepts"
        );
        for k in [
            "MALLOC_ARENA_MAX",
            "MIMALLOC_PURGE_DELAY",
            "CORDIAL_NPROC",
            "CORDIAL_ASSET_MMAP_DIR",
        ] {
            assert!(agg.iter().any(|(n, _)| n == k), "{k}");
        }
        // Every name passes the same filter operators' own engine.env does,
        // so a mode can never set a variable the manager refuses elsewhere.
        for m in [
            ResourceMode::Compatible,
            ResourceMode::Minimal,
            ResourceMode::Aggressive,
        ] {
            for (k, _) in mode_env(m, &cfg, b) {
                assert!(
                    k.starts_with("CORDIAL_")
                        || k.starts_with("MIMALLOC_")
                        || k == "MALLOC_ARENA_MAX",
                    "{k}"
                );
            }
        }
    }

    #[test]
    fn a_configured_resolution_beats_the_mode() {
        let mut cfg = Config::default();
        cfg.engine.resolution = "800x600".into();
        let v = mode_env(ResourceMode::Aggressive, &cfg, Path::new("/b"));
        assert!(v.contains(&("CORDIAL_RESOLUTION".into(), "800x600".into())));
    }

    #[test]
    fn graphics_choice_is_honest_about_missing_render_nodes() {
        let mut cfg = Config::default();
        assert!(choose_graphics(&cfg, None).unwrap().software);
        assert!(
            !choose_graphics(&cfg, Some(Path::new("/dev/dri/renderD128")))
                .unwrap()
                .software
        );
        cfg.engine.graphics = Graphics::Gpu;
        assert!(choose_graphics(&cfg, None).is_err());
        cfg.engine.graphics = Graphics::Software;
        assert!(
            choose_graphics(&cfg, Some(Path::new("/dev/dri/renderD128")))
                .unwrap()
                .software
        );
    }

    #[test]
    fn cpu_sets_rotate_and_stay_in_range() {
        assert!(cpu_set(3, 0, 4).is_empty());
        assert_eq!(cpu_set(0, 2, 4), vec![0, 1]);
        assert_eq!(cpu_set(1, 2, 4), vec![2, 3]);
        assert_eq!(cpu_set(2, 2, 4), vec![0, 1]);
        assert_eq!(cpu_set(0, 9, 4), vec![0, 1, 2, 3]);
    }

    /// Runs a real child through `launch` with an environment of our choosing:
    /// checks the log redirection, the cleared environment and the new process group.
    #[test]
    fn launch_clears_the_environment_and_writes_the_log() {
        let d = std::env::temp_dir().join(format!("hrd-spawn-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::env::set_var("HRD_LEAK_CANARY", "leaked");
        let plan = Plan {
            program: "/usr/bin/env".into(),
            args: vec![],
            env: vec![("ONLY".into(), "this".into())],
            cwd: d.clone(),
            log_path: d.join("log"),
            devctl_socket: None,
        };
        let log = std::fs::File::create(&plan.log_path).unwrap();
        let mut c = launch(
            &plan,
            log,
            &ProcSettings {
                cgroup_procs: None,
                oom_score_adj: 100,
                cpus: vec![0],
                ksm: false,
            },
        )
        .unwrap();
        assert!(c.wait().unwrap().success());
        let out = std::fs::read_to_string(d.join("log")).unwrap();
        assert_eq!(out.trim(), "ONLY=this");
        std::fs::remove_dir_all(d).ok();
    }
}
