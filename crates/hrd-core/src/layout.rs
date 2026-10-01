//! Where everything lives.
//!
//! The manager keeps the six kinds of thing the brief asks to be separated in
//! six different places, so that a backup, a permission review or a `rm -rf`
//! can be aimed at one of them:
//!
//! | what | where | who can touch it |
//! |---|---|---|
//! | global configuration | `/etc/cordial-hrd` | root writes, service reads |
//! | registry (accounts, groups, network metadata) | `/var/lib/cordial-hrd/registry.json` | service user |
//! | per-account private data (profiles, client storage) | `/var/lib/cordial-hrd/acct/<account>` | service user, `0700` |
//! | runtime (the unpacked Roblox build, shared, read-only to clients) | `/var/lib/cordial-hrd/runtime` | service user writes at import only |
//! | secrets | the Secret Service keyring under `/var/lib/cordial-hrd/secrets`; WireGuard keys under the helper's own root-only directory | see docs/security.md |
//! | logs | `/var/log/cordial-hrd` | service user |
//!
//! Every path below is derived from four roots, so the same code runs against
//! `/` in production and against a scratch directory in a test.

use std::path::{Path, PathBuf};

use crate::ids::{AccountName, NetworkName, ProxyGroupName};

#[derive(Debug, Clone)]
pub struct Layout {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub run_dir: PathBuf,
    /// Named network namespaces and the files generated for them. Deliberately
    /// **not** under `run_dir`: that directory belongs to the service user, and a
    /// directory the service user could rename is one the entry wrapper could
    /// not trust. This one has a root-owned parent (`/run`) and is written only
    /// by the privileged helper.
    pub netns_root: PathBuf,
    pub log_dir: PathBuf,
    /// The privileged helper's own state. Root-owned; the service user cannot
    /// read it, which is the point: WireGuard private keys live here.
    pub netd_state_dir: PathBuf,
}

/// Environment variable that relocates the whole layout under one directory.
/// For development and tests; a packaged install never sets it.
pub const ROOT_ENV: &str = "HRD_ROOT";

/// The name it had before the rename to HRD, still honoured when `HRD_ROOT` is
/// not set.
const LEGACY_ROOT_ENV: &str = "CORDIAL_HRD_ROOT";

impl Layout {
    /// The packaged layout.
    pub fn system() -> Self {
        Layout {
            config_dir: "/etc/cordial-hrd".into(),
            state_dir: "/var/lib/cordial-hrd".into(),
            run_dir: "/run/cordial-hrd".into(),
            netns_root: "/run/cordial-hrd-netns".into(),
            log_dir: "/var/log/cordial-hrd".into(),
            netd_state_dir: "/var/lib/cordial-hrd-netd".into(),
        }
    }

    /// Everything beneath `root`, for a run that must not touch the system.
    pub fn under(root: &Path) -> Self {
        Layout {
            config_dir: root.join("etc"),
            state_dir: root.join("var/lib"),
            run_dir: root.join("run"),
            netns_root: root.join("run-netns"),
            log_dir: root.join("var/log"),
            netd_state_dir: root.join("var/lib-netd"),
        }
    }

    /// `HRD_ROOT` if set, the system layout otherwise.
    pub fn from_env() -> Self {
        match std::env::var_os(ROOT_ENV).or_else(|| std::env::var_os(LEGACY_ROOT_ENV)) {
            Some(r) if !r.is_empty() => Layout::under(Path::new(&r)),
            _ => Layout::system(),
        }
    }

    /// The daemon's configuration file. An install made before the rename to HRD
    /// has `cordiald.toml`; it is used for as long as there is no `hrdd.toml`,
    /// so that an upgrade does not quietly fall back to the defaults.
    pub fn config_file(&self) -> PathBuf {
        let current = self.config_dir.join("hrdd.toml");
        let legacy = self.config_dir.join("cordiald.toml");
        if !current.exists() && legacy.exists() {
            legacy
        } else {
            current
        }
    }

    pub fn control_socket(&self) -> PathBuf {
        self.run_dir.join("control.sock")
    }

    pub fn netd_socket(&self) -> PathBuf {
        // In the root-owned directory, not in `run_dir`: the service user owns
        // `run_dir` and could put its own socket where the client connects.
        self.netns_dir().join("netd.sock")
    }

    pub fn registry_file(&self) -> PathBuf {
        self.state_dir.join("registry.json")
    }

    /// One JSON file per account holding the last run's record. Small, rewritten
    /// atomically at each state change, and the thing a restarted daemon reads
    /// to find out what it was in the middle of.
    pub fn instances_dir(&self) -> PathBuf {
        self.state_dir.join("instances")
    }

    pub fn instance_record(&self, a: &AccountName) -> PathBuf {
        self.instances_dir().join(format!("{a}.json"))
    }

    pub fn daemon_lock(&self) -> PathBuf {
        self.state_dir.join("hrdd.lock")
    }

    /// Per-account root. `HOME` and every `XDG_*_HOME` of the account's client
    /// point inside it, so nothing the client writes can land in another
    /// account's tree or in the service user's real home.
    pub fn account_home(&self, a: &AccountName) -> PathBuf {
        self.state_dir.join("acct").join(a.as_str())
    }

    pub fn account_data(&self, a: &AccountName) -> PathBuf {
        self.account_home(a).join("data")
    }

    pub fn account_config(&self, a: &AccountName) -> PathBuf {
        self.account_home(a).join("config")
    }

    pub fn account_cache(&self, a: &AccountName) -> PathBuf {
        self.account_home(a).join("cache")
    }

    pub fn account_state(&self, a: &AccountName) -> PathBuf {
        self.account_home(a).join("state")
    }

    /// The profile directory upstream Cordial derives from `XDG_DATA_HOME`.
    /// Holds the flock the client takes on itself (ADR-012).
    pub fn account_profile(&self, a: &AccountName, profile: &str) -> PathBuf {
        self.account_data(a)
            .join("cordial")
            .join("profiles")
            .join(profile)
    }

    /// The instance's private `XDG_RUNTIME_DIR`: its own Wayland socket, its own
    /// control socket, invisible to every other instance.
    pub fn instance_run(&self, a: &AccountName) -> PathBuf {
        self.run_dir.join("i").join(a.as_str())
    }

    pub fn instance_log(&self, a: &AccountName) -> PathBuf {
        self.log_dir.join(format!("{a}.log"))
    }

    pub fn runtime_store(&self) -> PathBuf {
        self.state_dir.join("runtime")
    }

    /// Where `gnome-keyring-daemon` keeps its encrypted collections.
    pub fn secrets_data(&self) -> PathBuf {
        self.state_dir.join("secrets")
    }

    /// The private session bus the Secret Service lives on, and its runtime
    /// directory. A filesystem socket, not an abstract one: abstract sockets
    /// belong to a network namespace and would be unreachable from inside a
    /// group's.
    pub fn secrets_run(&self) -> PathBuf {
        self.run_dir.join("secrets")
    }

    pub fn secrets_bus(&self) -> PathBuf {
        self.secrets_run().join("bus")
    }

    /// Named network namespaces, one bind-mounted file per proxy group.
    pub fn netns_dir(&self) -> PathBuf {
        self.netns_root.clone()
    }

    pub fn netns_file(&self, g: &ProxyGroupName) -> PathBuf {
        self.netns_dir().join(g.as_str())
    }

    /// `resolv.conf` and `nsswitch.conf` the wrapper overlays inside a proxy group's
    /// namespace. Generated by the privileged helper.
    pub fn netns_resolv(&self, g: &ProxyGroupName) -> PathBuf {
        self.netns_dir().join(format!("{g}.resolv.conf"))
    }

    pub fn netns_nsswitch(&self, g: &ProxyGroupName) -> PathBuf {
        self.netns_dir().join(format!("{g}.nsswitch.conf"))
    }

    pub fn netd_keys_dir(&self) -> PathBuf {
        self.netd_state_dir.join("keys")
    }

    pub fn netd_key_file(&self, n: &NetworkName) -> PathBuf {
        self.netd_keys_dir().join(format!("{n}.key"))
    }

    pub fn netd_manifest(&self) -> PathBuf {
        self.netd_state_dir.join("applied.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_stays_under_the_chosen_root() {
        let root = Path::new("/tmp/hrd-test-root");
        let l = Layout::under(root);
        let a = AccountName::new("alt-1").unwrap();
        let g = ProxyGroupName::new("g01").unwrap();
        for p in [
            l.config_file(),
            l.control_socket(),
            l.registry_file(),
            l.instance_record(&a),
            l.account_profile(&a, "default"),
            l.instance_run(&a),
            l.instance_log(&a),
            l.runtime_store(),
            l.secrets_bus(),
            l.netns_file(&g),
            l.netd_manifest(),
        ] {
            assert!(p.starts_with(root), "{} escapes the root", p.display());
        }
    }

    #[test]
    fn an_older_install_keeps_its_configuration_file() {
        let root = std::env::temp_dir().join(format!("hrd-layout-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let l = Layout::under(&root);
        std::fs::create_dir_all(&l.config_dir).unwrap();
        // Nothing yet: the current name.
        assert!(l.config_file().ends_with("hrdd.toml"));
        // Only the old name exists: it is used, so an upgrade keeps the settings.
        std::fs::write(l.config_dir.join("cordiald.toml"), "").unwrap();
        assert!(l.config_file().ends_with("cordiald.toml"));
        // Once the new file exists it wins.
        std::fs::write(l.config_dir.join("hrdd.toml"), "").unwrap();
        assert!(l.config_file().ends_with("hrdd.toml"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn accounts_do_not_share_any_writable_path() {
        let l = Layout::system();
        let a = AccountName::new("a").unwrap();
        let b = AccountName::new("b").unwrap();
        let pa = [
            l.account_data(&a),
            l.account_config(&a),
            l.account_cache(&a),
            l.account_state(&a),
            l.instance_run(&a),
            l.instance_log(&a),
        ];
        let pb = [
            l.account_data(&b),
            l.account_config(&b),
            l.account_cache(&b),
            l.account_state(&b),
            l.instance_run(&b),
            l.instance_log(&b),
        ];
        for x in &pa {
            for y in &pb {
                assert!(
                    !x.starts_with(y) && !y.starts_with(x),
                    "{} overlaps {}",
                    x.display(),
                    y.display()
                );
            }
        }
    }

    #[test]
    fn the_key_directory_is_outside_the_service_users_state() {
        let l = Layout::system();
        assert!(!l.netd_keys_dir().starts_with(&l.state_dir));
    }

    #[test]
    fn the_namespace_directory_is_not_inside_anything_the_service_user_owns() {
        for l in [Layout::system(), Layout::under(Path::new("/x"))] {
            for owned in [&l.run_dir, &l.state_dir, &l.log_dir, &l.config_dir] {
                assert!(
                    !l.netns_dir().starts_with(owned),
                    "{} is inside {}",
                    l.netns_dir().display(),
                    owned.display()
                );
            }
        }
    }
}
