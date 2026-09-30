//! Checks about the machine, shared by `cordialctl doctor` (which must work
//! when the daemon is down) and the daemon.
//!
//! Each check says what it looked at. A check that cannot be made is `Unknown`,
//! never a pass. Nothing here modifies the system.

use std::path::{Path, PathBuf};

use hrd_core::config::{Config, Graphics};
use hrd_core::layout::Layout;
use hrd_core::proto::{Check, CheckStatus};

use crate::{cgroup, procfs};

fn c(
    id: &str,
    title: &str,
    status: CheckStatus,
    detail: impl Into<String>,
    fix: Option<&str>,
) -> Check {
    Check {
        id: id.into(),
        title: title.into(),
        status,
        detail: detail.into(),
        fix: fix.map(str::to_string),
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

fn is_exec(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn user_exists(name: &str) -> Option<u32> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.first() == Some(&name)).then(|| f.get(2)?.parse().ok())?
        })
}

fn has_file_capability(p: &Path) -> Option<bool> {
    let mut buf = [0u8; 64];
    match rustix::fs::getxattr(p, "security.capability", &mut buf) {
        Ok(n) => Some(n > 0),
        Err(rustix::io::Errno::NODATA) => Some(false),
        Err(_) => None,
    }
}

pub fn render_node() -> Option<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir("/dev/dri")
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("renderD"))
        })
        .collect();
    v.sort();
    v.into_iter().next()
}

pub fn host_checks(layout: &Layout, cfg: &Config) -> Vec<Check> {
    use CheckStatus::{Fail, Info, Unknown, Warn};
    let ok = CheckStatus::Ok;
    let mut out = Vec::new();

    // Who runs things.
    let me = rustix::process::getuid().as_raw();
    match user_exists(&cfg.service.user) {
        Some(0) => out.push(c(
            "user",
            "service user",
            Fail,
            format!(
                "{} is uid 0; clients must not run as root",
                cfg.service.user
            ),
            Some("use a dedicated unprivileged user (the .deb creates `cordial`)"),
        )),
        Some(uid) => out.push(c(
            "user",
            "service user",
            ok,
            format!("{} (uid {uid}) exists and is not root", cfg.service.user),
            None,
        )),
        None => out.push(c(
            "user",
            "service user",
            Fail,
            format!("no user {}", cfg.service.user),
            Some("install the package, or create the user with `adduser --system`"),
        )),
    }
    if me == 0 {
        out.push(c("running-as", "this process", Info, "running as root (fine for a check; the daemon and every client run as the service user)", None));
    }

    // Kernel and cgroups.
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    out.push(c("kernel", "kernel", Info, rel.trim().to_string(), None));
    match cgroup::find_mount() {
        None => out.push(c("cgroup2", "cgroup v2", Fail, "no cgroup2 mount found: processes of an instance cannot be owned as a set (falls back to process groups, which a program can leave)", Some("boot with systemd.unified_cgroup_hierarchy=1 (default on Debian 11+)"))),
        Some(m) => {
            let ctl = std::fs::read_to_string(m.join("cgroup.controllers")).unwrap_or_default();
            let have: Vec<&str> = ctl.split_whitespace().collect();
            let missing: Vec<&str> = ["memory", "pids", "cpu"].into_iter().filter(|w| !have.contains(w)).collect();
            if missing.is_empty() {
                out.push(c("cgroup2", "cgroup v2", ok, format!("mounted at {}; controllers: {}", m.display(), have.join(" ")), None));
            } else {
                out.push(c("cgroup2", "cgroup v2", Warn, format!("mounted at {} but lacks controllers: {}", m.display(), missing.join(", ")), Some("add cgroup_enable=memory to the kernel command line if memory is missing")));
            }
            if !m.join("cgroup.kill").exists() && !m.join("system.slice/cgroup.kill").exists() {
                out.push(c("cgroup-kill", "cgroup.kill", Info, "not present (kernel older than 5.14): sets are ended by a kill loop that repeats until the cgroup is empty", None));
            }
        }
    }
    out.push(if Path::new("/proc/pressure/memory").exists() {
        c(
            "psi",
            "pressure stall information",
            ok,
            "/proc/pressure available: start admission can use memory and CPU pressure",
            None,
        )
    } else {
        c(
            "psi",
            "pressure stall information",
            Warn,
            "/proc/pressure is missing: starts are admitted on free memory alone",
            Some("boot with psi=1"),
        )
    });

    // Memory and CPUs.
    match procfs::read_meminfo() {
        Ok(m) => out.push(c(
            "memory",
            "memory",
            Info,
            format!(
                "total {} MiB, available {} MiB, swap total {} MiB",
                m.total.unwrap_or(0) / 1048576,
                m.available.unwrap_or(0) / 1048576,
                m.swap_total.unwrap_or(0) / 1048576
            ),
            None,
        )),
        Err(e) => out.push(c(
            "memory",
            "memory",
            Unknown,
            format!("/proc/meminfo: {e}"),
            None,
        )),
    }
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    out.push(c("cpus", "CPUs", Info, format!("{cpus} online"), None));

    // Drawing.
    let node = render_node();
    let lvp = std::fs::read_dir("/usr/share/vulkan/icd.d")
        .ok()
        .map(|d| {
            d.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("lvp_icd"))
        })
        .unwrap_or(false);
    let software = match cfg.engine.graphics {
        Graphics::Software => true,
        Graphics::Gpu => false,
        Graphics::Auto => node.is_none(),
    };
    match (&cfg.engine.graphics, &node) {
        (Graphics::Gpu, None) => out.push(c("graphics", "graphics", Fail, "engine.graphics = gpu but /dev/dri has no render node", Some("set engine.graphics = software (or auto) on a machine without a GPU"))),
        (_, None) => out.push(c("graphics", "graphics", Info, "no DRM render node: every frame is drawn on the CPU (llvmpipe/lavapipe, pixman). That costs CPU per client, continuously; see docs/gpu-less.md for what to expect", None)),
        (_, Some(n)) => out.push(c("graphics", "graphics", Info, format!("render node {} present; the service user must be able to open it (group `render`)", n.display()), None)),
    }
    if software {
        out.push(if lvp || !cfg.engine.vulkan_icd.is_empty() {
            c("lavapipe", "software Vulkan", ok, "lavapipe ICD found", None)
        } else {
            c("lavapipe", "software Vulkan", Fail, "no lavapipe ICD (lvp_icd*.json): without a Vulkan device the engine cannot draw on this machine", Some("apt install mesa-vulkan-drivers"))
        });
    }

    // Programs.
    let run_fix = "build the patched upstream client (docs/build.md) and install it at this path; the .deb does not contain it";
    for (id, path, fix) in [
        (
            "cordial-run",
            PathBuf::from(&cfg.engine.cordial_run),
            run_fix,
        ),
        (
            "cordial-enter",
            PathBuf::from(&cfg.engine.enter),
            "install the cordial-hrd package",
        ),
        (
            "cordial-import",
            PathBuf::from(&cfg.engine.importer),
            "install the cordial-hrd package",
        ),
    ] {
        let (title, need) = (id, true);
        out.push(if is_exec(&path) {
            c(id, title, ok, path.display().to_string(), None)
        } else {
            c(
                id,
                title,
                if need { Fail } else { Warn },
                format!("{} is missing or not executable", path.display()),
                Some(fix),
            )
        });
    }
    let enter = PathBuf::from(&cfg.engine.enter);
    if is_exec(&enter) {
        out.push(match has_file_capability(&enter) {
            Some(true) => c("enter-cap", "cordial-enter capability", ok, "carries a file capability (cap_sys_admin)", None),
            Some(false) => c("enter-cap", "cordial-enter capability", Fail, "no file capability: clients cannot enter their group's namespace", Some("setcap cap_sys_admin+ep /usr/lib/cordial-hrd/cordial-enter (the package does this)")),
            None => c("enter-cap", "cordial-enter capability", Unknown, "could not read extended attributes", None),
        });
    }
    if cfg.engine.compositor == hrd_core::config::Compositor::Cage {
        out.push(match find_in_path("cage") {
            Some(p) => c(
                "cage",
                "cage (nested compositor)",
                ok,
                p.display().to_string(),
                None,
            ),
            None => c(
                "cage",
                "cage (nested compositor)",
                Fail,
                "cage is not installed: --headless cannot start",
                Some("apt install cage"),
            ),
        });
    }
    for (bin, pkg) in [
        ("busctl", "systemd"),
        ("dbus-daemon", "dbus-daemon"),
        ("gnome-keyring-daemon", "gnome-keyring"),
    ] {
        out.push(match find_in_path(bin) {
            Some(p) => c(bin, bin, ok, p.display().to_string(), None),
            None => c(
                bin,
                bin,
                Fail,
                format!("{bin} is missing: the secret store cannot run"),
                Some(format!("apt install {pkg}").as_str()),
            ),
        });
    }
    for bin in ["nft", "ip"] {
        out.push(match find_in_path(bin) {
            Some(p) => c(bin, bin, ok, p.display().to_string(), None),
            None => c(
                bin,
                bin,
                Warn,
                format!("{bin} is missing: network groups cannot be applied"),
                Some("apt install nftables iproute2"),
            ),
        });
    }

    // Directories.
    for (id, p) in [
        ("state-dir", &layout.state_dir),
        ("log-dir", &layout.log_dir),
    ] {
        match rustix::fs::statvfs(p.as_path()) {
            Ok(s) => {
                let free = s.f_bavail.saturating_mul(s.f_frsize);
                let st = if free < 2 << 30 { Warn } else { ok };
                out.push(c(
                    id,
                    id,
                    st,
                    format!("{}: {} MiB free", p.display(), free / 1048576),
                    (st == Warn).then_some(
                        "the runtime store is about 0.5 GiB and each account's cache and logs grow",
                    ),
                ));
            }
            Err(_) => out.push(c(
                id,
                id,
                Unknown,
                format!("{} does not exist yet", p.display()),
                None,
            )),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checks_run_anywhere_and_never_panic_or_claim_what_is_missing() {
        let l = Layout::under(Path::new("/nonexistent-hrd"));
        let mut cfg = Config::default();
        cfg.engine.cordial_run = "/nonexistent/cordial-run".into();
        let checks = host_checks(&l, &cfg);
        assert!(checks.iter().any(|x| x.id == "graphics"));
        let run = checks.iter().find(|x| x.id == "cordial-run").unwrap();
        assert_eq!(run.status, CheckStatus::Fail);
        assert!(checks.iter().all(|x| !x.title.is_empty()));
    }

    #[test]
    fn a_gpu_required_but_absent_is_a_failure_not_a_fallback() {
        let l = Layout::under(Path::new("/nonexistent-hrd"));
        let mut cfg = Config::default();
        cfg.engine.graphics = Graphics::Gpu;
        let g = host_checks(&l, &cfg)
            .into_iter()
            .find(|x| x.id == "graphics")
            .unwrap();
        if render_node().is_none() {
            assert_eq!(g.status, CheckStatus::Fail);
        }
    }
}
