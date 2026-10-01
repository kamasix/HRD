//! `hrdd.toml`.
//!
//! Every number here is an operator decision or a stated assumption, and the
//! defaults say which. Nothing in this file is a claim about what Roblox, the
//! kernel or the hardware will tolerate: `max_instances` is the manager's own
//! design target, `assumed_start_peak_mib` is a first guess to be replaced by
//! what `hrdctl stats` shows on the real machine, and a proxy group's capacity
//! is an organisational limit.
//!
//! Unknown keys are an error. A typo in a limit that silently falls back to a
//! default is the kind of mistake that is discovered at 300 instances.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fsutil;
use crate::model::ResourceMode;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub service: ServiceCfg,
    pub control: ControlCfg,
    pub scheduler: SchedulerCfg,
    pub resources: ResourcesCfg,
    pub engine: EngineCfg,
    pub stats: StatsCfg,
    pub secrets: SecretsCfg,
    pub network: NetworkCfg,
    pub logs: LogsCfg,
    pub login: LoginCfg,
    pub runtime: RuntimeCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServiceCfg {
    /// The unprivileged user the daemon and every client run as. `doctor`
    /// checks it exists and is not root; the daemon itself refuses to run as
    /// uid 0.
    pub user: String,
    pub group: String,
}

impl Default for ServiceCfg {
    fn default() -> Self {
        ServiceCfg {
            user: "cordial".into(),
            group: "cordial".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ControlCfg {
    /// Octal mode of the control socket. `0660` with the socket's group set to
    /// the service group lets members of that group operate the fleet.
    pub socket_mode: String,
    /// Extra uids accepted on the control socket in addition to root and the
    /// service user. Access is also limited by the socket's file mode; this is
    /// the second check, made with `SO_PEERCRED`.
    pub allowed_uids: Vec<u32>,
}

impl Default for ControlCfg {
    fn default() -> Self {
        ControlCfg {
            socket_mode: "0660".into(),
            allowed_uids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDaemonStop {
    /// Leave running instances alone; a restarted daemon adopts them.
    Keep,
    /// Stop every instance first.
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SchedulerCfg {
    /// The most instances the manager will register as live at once. The
    /// manager's design target, **not** a statement about what any machine can
    /// run: each engine is on the order of a gigabyte (docs/memory.md).
    pub max_instances: u32,
    /// How many starts may be in flight at once. Starting is the expensive
    /// part: decompression, relocation, asset loading, the first network
    /// round trips. `0` chooses from the machine: see
    /// [`auto_concurrent_starts`].
    pub max_concurrent_starts: u32,
    /// Minimum gap between beginning two starts, in milliseconds.
    pub min_start_interval_ms: u64,
    /// How long `starting` may last before the instance is declared failed.
    pub start_timeout_s: u64,
    /// How long `joining` may last before the instance is declared failed.
    pub join_timeout_s: u64,
    /// Seconds between the polite stop request and killing the whole set.
    pub stop_grace_s: u64,
    /// A start is deferred while available memory (after reserving for starts
    /// already in flight) would fall below this.
    pub min_available_mem_mib: u64,
    /// What one start is assumed to add before there is a measurement. Replaced
    /// by the observed peak of finished starts as soon as there is one.
    pub assumed_start_peak_mib: u64,
    /// A start is deferred while the kernel's memory pressure ("some", 10 s
    /// average, percent) is above this. 0 disables the check.
    pub max_memory_pressure_avg10: f64,
    /// The same for CPU pressure. A start is mostly CPU for its first minute,
    /// and on a machine with few cores and no GPU the clients already running
    /// are using the CPU to draw; starting one more on top of that slows every
    /// session down. 0 disables the check.
    pub max_cpu_pressure_avg10: f64,
    /// After the engine reports a disconnection, how long to wait for it to
    /// join somewhere else (a teleport) before the session is called
    /// disconnected and its processes are released.
    pub disconnect_grace_s: u64,
    pub on_daemon_stop: OnDaemonStop,
}

impl Default for SchedulerCfg {
    fn default() -> Self {
        SchedulerCfg {
            max_instances: 300,
            max_concurrent_starts: 0,
            min_start_interval_ms: 3000,
            start_timeout_s: 300,
            join_timeout_s: 300,
            stop_grace_s: 20,
            min_available_mem_mib: 2048,
            assumed_start_peak_mib: 1536,
            max_memory_pressure_avg10: 20.0,
            max_cpu_pressure_avg10: 75.0,
            disconnect_grace_s: 20,
            on_daemon_stop: OnDaemonStop::Keep,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResourcesCfg {
    pub default_mode: ResourceMode,
    /// cgroup `memory.high` per instance in MiB: the kernel throttles and
    /// reclaims above it rather than killing. 0 leaves it unset.
    pub memory_high_mib: u64,
    /// cgroup `memory.max` per instance in MiB: above it the kernel OOM-kills
    /// inside the instance. A limit here only ever makes a process die; it
    /// does not make it smaller. 0 leaves it unset.
    pub memory_max_mib: u64,
    /// cgroup `memory.swap.max` in MiB. Unset by default: pushing an engine to
    /// swap lowers RSS and makes nothing cheaper.
    pub swap_max_mib: Option<u64>,
    /// cgroup `cpu.weight` (1-10000). The default share is 100.
    pub cpu_weight: u32,
    /// cgroup `pids.max`.
    pub pids_max: u32,
    /// Written to `/proc/<pid>/oom_score_adj` so that under memory pressure the
    /// kernel prefers a client to the manager, the keyring or sshd.
    pub oom_score_adj: i32,
    /// Ask the kernel to merge identical anonymous pages across clients
    /// (`prctl(PR_SET_MEMORY_MERGE)`, Linux 6.4+). Off by default: it costs CPU
    /// in `ksmd`, which is not attributed to any client, and whether the engine
    /// has enough identical pages to pay for it is unmeasured.
    pub ksm: bool,
}

impl Default for ResourcesCfg {
    fn default() -> Self {
        ResourcesCfg {
            default_mode: ResourceMode::Compatible,
            memory_high_mib: 0,
            memory_max_mib: 0,
            swap_max_mib: None,
            cpu_weight: 100,
            pids_max: 2048,
            oom_score_adj: 300,
            ksm: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compositor {
    /// Upstream's `--headless`: each client runs inside its own nested `cage`
    /// on wlroots' headless backend. The only compositor arrangement that has
    /// been exercised upstream.
    Cage,
    /// Use whatever display the environment already provides. For a machine
    /// that has one; the manager does not start anything.
    External,
}

/// How the join link reaches the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinVia {
    /// `--join-url` in the process arguments, which upstream's `cordial-run`
    /// supports and every local user can read in `/proc/<pid>/cmdline`. Refused
    /// for links that carry a private-server code.
    Argv,
    /// `CORDIAL_JOIN_URL` in the environment (readable by the same user only).
    /// **Needs the patched `cordial-run`** (patches/cordial/); an unpatched
    /// build ignores the variable and never joins.
    Env,
}

/// What draws the client's frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Graphics {
    /// Use a DRM render node if the service user can open one, software
    /// otherwise. `doctor` says which was chosen and why.
    Auto,
    /// CPU rendering only: llvmpipe for GL, lavapipe for Vulkan, pixman in the
    /// nested compositor, cairo in GTK. Nothing touches `/dev/dri`. This is
    /// what a server without a graphics card uses, and it costs CPU on every
    /// frame of every client (docs/gpu-less.md).
    Software,
    /// Require a render node; refuse to start a client without one rather
    /// than fall back to drawing on the CPU.
    Gpu,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EngineCfg {
    pub compositor: Compositor,
    pub join_url_via: JoinVia,
    pub graphics: Graphics,
    /// Threads llvmpipe/lavapipe may use per client (`LP_NUM_THREADS`) when
    /// drawing in software. 0 leaves the Mesa default, which is one per core
    /// *per client*: with several clients on few cores that oversubscribes
    /// badly, so `1` is usually the right value on such a machine.
    pub software_threads: u32,
    /// Pin each client to this many CPUs, chosen round-robin. 0 leaves the
    /// scheduler alone. Affinity does not change how many CPUs the engine sees
    /// (`sysconf` ignores it), so this limits contention, not the engine's
    /// thread count.
    pub cpus_per_instance: u32,
    /// Path of the lavapipe ICD file. Empty searches
    /// `/usr/share/vulkan/icd.d/lvp_icd*.json`.
    pub vulkan_icd: String,
    /// Path of the `cordial-run` built from the patched upstream tree.
    pub cordial_run: String,
    /// Path of the per-instance launcher that becomes `cordial-run` (or `cage`)
    /// after entering the proxy group's namespace.
    pub enter: String,
    /// Path of `hrd-import`, which the daemon runs (as the service user,
    /// with the operator's files passed as descriptors) to install a runtime.
    pub importer: String,
    /// Render resolution, `WIDTHxHEIGHT`. Empty uses the resource mode's
    /// value. Smaller is cheaper for the open layer's swapchain and
    /// compositor surface and says nothing about the engine's own memory.
    pub resolution: String,
    /// Extra environment for the client. Only `CORDIAL_*` and `MIMALLOC_*` names
    /// are accepted; see docs/memory.md for which are known to do something.
    pub env: BTreeMap<String, String>,
}

impl Default for EngineCfg {
    fn default() -> Self {
        EngineCfg {
            compositor: Compositor::Cage,
            join_url_via: JoinVia::Argv,
            graphics: Graphics::Auto,
            software_threads: 0,
            cpus_per_instance: 0,
            vulkan_icd: String::new(),
            cordial_run: "/usr/lib/hrd/cordial-run".into(),
            enter: "/usr/lib/hrd/hrd-enter".into(),
            importer: "/usr/lib/hrd/hrd-import".into(),
            resolution: String::new(),
            env: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StatsCfg {
    /// Seconds between samples of cheap counters: cgroup files, `/proc/<pid>/stat`.
    pub interval_s: u64,
    /// Seconds between `smaps_rollup` reads, which walk the process's memory
    /// map and cost accordingly. 0 turns PSS/USS sampling off.
    pub pss_interval_s: u64,
}

impl Default for StatsCfg {
    fn default() -> Self {
        StatsCfg {
            interval_s: 5,
            pss_interval_s: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackend {
    /// `org.freedesktop.secrets` on a private bus, served by a headless
    /// `gnome-keyring-daemon`, unlocked by a passphrase the operator types.
    SecretService,
    /// Explicitly keep no session. Every start needs an interactive login.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecretsCfg {
    pub backend: SecretBackend,
    /// Path of the keyring daemon and of the session bus daemon.
    pub keyring_daemon: String,
    pub dbus_daemon: String,
}

impl Default for SecretsCfg {
    fn default() -> Self {
        SecretsCfg {
            backend: SecretBackend::SecretService,
            keyring_daemon: "/usr/bin/gnome-keyring-daemon".into(),
            dbus_daemon: "/usr/bin/dbus-daemon".into(),
        }
    }
}

/// Keeping the Roblox build up to date.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeCfg {
    /// Look for a newer x86-64 Roblox build from time to time, download it,
    /// check it against Roblox's pinned signing certificate and install it.
    /// Off by default: the daemon makes no network request of its own until you
    /// turn this on. Running clients keep the build they started with; only
    /// clients started afterwards use the new one.
    pub auto_update: bool,
    /// Hours between checks. A check is one small request; a download happens
    /// only when the mirror has a newer build than the installed one.
    pub check_interval_h: u64,
    /// Select the new build for future starts once it is installed. Off: it is
    /// installed and `runtime use VERSION` (or the panel) selects it.
    pub make_current: bool,
}

impl Default for RuntimeCfg {
    fn default() -> Self {
        RuntimeCfg {
            auto_update: false,
            check_interval_h: 6,
            make_current: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkCfg {
    /// Permit proxy groups with no proxy. Off: an account whose proxy group has
    /// no tunnel is refused, because "no tunnel" must never quietly mean "the
    /// server's own address".
    pub allow_unrouted: bool,
    /// How old a WireGuard handshake may be before the network is reported
    /// `unverified`, in seconds. WireGuard re-handshakes about every two
    /// minutes while traffic flows.
    pub handshake_max_age_s: u64,
}

impl Default for NetworkCfg {
    fn default() -> Self {
        NetworkCfg {
            allow_unrouted: false,
            handshake_max_age_s: 180,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogsCfg {
    /// Size above which an instance log is copied to `.1` and truncated (also during a run), or moved to `.1` at the next start.
    pub max_bytes: u64,
}

impl Default for LogsCfg {
    fn default() -> Self {
        LogsCfg {
            max_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoginCfg {
    /// A sign-in session is stopped after this long whatever happens.
    pub timeout_s: u64,
    /// Let the operator send clicks, keys and text to a *sign-in* client from
    /// `hrdctl` or the panel, one action per request, to type a password or
    /// confirm a code. It exists only for sessions started by `account login`;
    /// clients that play never have a control surface. Off: sign in on a
    /// machine with a display instead (docs/accounts.md).
    pub console: bool,
    /// Longest text one console request may type.
    pub max_text_len: usize,
}

impl Default for LoginCfg {
    fn default() -> Self {
        LoginCfg {
            timeout_s: 900,
            console: true,
            max_text_len: 256,
        }
    }
}

/// What `max_concurrent_starts = 0` means on this machine: one start at a time
/// on a small machine or when every frame is drawn on the CPU, more where there
/// are cores to spare. A guess, stated as one; `stats` shows the real peak.
pub fn auto_concurrent_starts(cpus: usize, software_graphics: bool) -> u32 {
    let per = if software_graphics { 4 } else { 2 };
    (cpus / per).clamp(1, 8) as u32
}

/// Programs the packages installed before the rename to HRD, which
/// `hrdctl init` wrote into the configuration file as explicit values. A file
/// that still says one of these means "the default", and the program is now
/// somewhere else, so the old value is read as the new default instead of
/// pointing the daemon at a file that no longer exists.
const LEGACY_PROGRAM_PATHS: [(&str, &str); 3] = [
    (
        "/usr/lib/cordial-hrd/cordial-run",
        "/usr/lib/hrd/cordial-run",
    ),
    (
        "/usr/lib/cordial-hrd/cordial-enter",
        "/usr/lib/hrd/hrd-enter",
    ),
    (
        "/usr/lib/cordial-hrd/cordial-import",
        "/usr/lib/hrd/hrd-import",
    ),
];

impl Config {
    /// Read the three program paths written by an older `init` as the current
    /// defaults. Exact matches only: a path the operator chose is left alone.
    pub fn upgrade_legacy_paths(&mut self) {
        for slot in [
            &mut self.engine.cordial_run,
            &mut self.engine.enter,
            &mut self.engine.importer,
        ] {
            if let Some((_, new)) = LEGACY_PROGRAM_PATHS.iter().find(|(old, _)| slot == old) {
                *slot = (*new).to_string();
            }
        }
    }

    /// Load `path`; a missing file yields the defaults.
    pub fn load(path: &Path) -> Result<Config> {
        match fsutil::read_limited_opt(path, 256 * 1024)? {
            None => Ok(Config::default()),
            Some(bytes) => {
                let text = std::str::from_utf8(&bytes).map_err(|_| {
                    Error::invalid(format!("{} is not valid UTF-8", path.display()))
                })?;
                let mut cfg: Config = toml::from_str(text)
                    .map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
                cfg.upgrade_legacy_paths();
                cfg.validate()?;
                Ok(cfg)
            }
        }
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| Error::Internal(format!("serialise configuration: {e}")))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        fsutil::atomic_write(path, self.to_toml()?.as_bytes(), 0o644)
    }

    /// Every problem, not just the first, so one edit fixes them all.
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        if !(1..=24 * 30).contains(&self.runtime.check_interval_h) {
            p.push(format!(
                "runtime.check_interval_h = {} is outside 1..=720",
                self.runtime.check_interval_h
            ));
        }
        let s = &self.scheduler;
        if s.max_instances == 0 || s.max_instances > 10_000 {
            p.push(format!(
                "scheduler.max_instances = {} is outside 1..=10000",
                s.max_instances
            ));
        }
        if s.max_concurrent_starts > 64 {
            p.push(format!(
                "scheduler.max_concurrent_starts = {} is outside 0..=64 (0 chooses from the machine)",
                s.max_concurrent_starts
            ));
        }
        if !(0.0..=100.0).contains(&s.max_cpu_pressure_avg10) {
            p.push("scheduler.max_cpu_pressure_avg10 must be 0..=100".into());
        }
        if s.disconnect_grace_s > 600 {
            p.push("scheduler.disconnect_grace_s must be at most 600".into());
        }
        if self.login.timeout_s < 60 || self.login.timeout_s > 86_400 {
            p.push("login.timeout_s must be 60..=86400".into());
        }
        if self.login.max_text_len == 0 || self.login.max_text_len > 1024 {
            p.push("login.max_text_len must be 1..=1024".into());
        }
        if self.engine.software_threads > 64 {
            p.push("engine.software_threads must be at most 64".into());
        }
        if self.engine.cpus_per_instance > 256 {
            p.push("engine.cpus_per_instance must be at most 256".into());
        }
        if !self.engine.vulkan_icd.is_empty() && !self.engine.vulkan_icd.starts_with('/') {
            p.push("engine.vulkan_icd must be an absolute path or empty".into());
        }
        if s.stop_grace_s == 0 || s.stop_grace_s > 600 {
            p.push("scheduler.stop_grace_s must be 1..=600".into());
        }
        if s.start_timeout_s < 30 || s.join_timeout_s < 30 {
            p.push("scheduler.start_timeout_s and join_timeout_s must be at least 30".into());
        }
        if !(0.0..=100.0).contains(&s.max_memory_pressure_avg10) {
            p.push("scheduler.max_memory_pressure_avg10 must be 0..=100".into());
        }
        let r = &self.resources;
        if r.memory_high_mib != 0 && r.memory_max_mib != 0 && r.memory_high_mib > r.memory_max_mib {
            p.push("resources.memory_high_mib must not exceed resources.memory_max_mib".into());
        }
        if !(1..=10_000).contains(&r.cpu_weight) {
            p.push("resources.cpu_weight must be 1..=10000".into());
        }
        if r.pids_max == 0 {
            p.push("resources.pids_max must be positive".into());
        }
        if !(-1000..=1000).contains(&r.oom_score_adj) {
            p.push("resources.oom_score_adj must be -1000..=1000".into());
        }
        if u32::from_str_radix(self.control.socket_mode.trim_start_matches('0'), 8)
            .map(|m| m > 0o777)
            .unwrap_or(true)
            && self.control.socket_mode != "0"
        {
            p.push(format!(
                "control.socket_mode {:?} is not an octal mode",
                self.control.socket_mode
            ));
        }
        if !self.engine.resolution.is_empty() && parse_resolution(&self.engine.resolution).is_none()
        {
            p.push(format!(
                "engine.resolution {:?} must look like 1280x720",
                self.engine.resolution
            ));
        }
        for (k, v) in &self.engine.env {
            if !allowed_engine_env(k) {
                p.push(format!(
                    "engine.env key {k:?} is not allowed: only CORDIAL_* and MIMALLOC_* names"
                ));
            }
            if v.contains('\0') || v.contains('\n') {
                p.push(format!(
                    "engine.env value for {k} contains a control character"
                ));
            }
        }
        for (name, path) in [
            ("engine.cordial_run", &self.engine.cordial_run),
            ("engine.enter", &self.engine.enter),
            ("engine.importer", &self.engine.importer),
        ] {
            if !path.starts_with('/') {
                p.push(format!("{name} must be an absolute path"));
            }
        }
        if self.service.user == "root" {
            p.push("service.user must not be root".into());
        }
        p
    }

    pub fn validate(&self) -> Result<()> {
        let p = self.problems();
        if p.is_empty() {
            Ok(())
        } else {
            Err(Error::invalid(format!(
                "invalid configuration:\n  - {}",
                p.join("\n  - ")
            )))
        }
    }
}

/// `WIDTHxHEIGHT` within what `cordial-run` accepts (it falls back to 1280x720
/// for anything under 320x240).
pub fn parse_resolution(s: &str) -> Option<(u32, u32)> {
    let (w, h) = s.split_once('x')?;
    let (w, h): (u32, u32) = (w.parse().ok()?, h.parse().ok()?);
    ((320..=7680).contains(&w) && (240..=4320).contains(&h)).then_some((w, h))
}

/// The environment names an operator may pass to a client. Anything else could
/// redirect the dynamic loader, the profile root or the secret store, each of
/// which this manager sets deliberately.
pub fn allowed_engine_env(name: &str) -> bool {
    let shaped = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !shaped {
        return false;
    }
    // Names the manager owns. A `CORDIAL_*` variable that would undo an
    // isolation guarantee is refused even though it matches the prefix.
    const OWNED: &[&str] = &[
        "CORDIAL_SECRET_STORE",
        "CORDIAL_PROFILE_ROOT",
        "CORDIAL_NETWORK",
        "CORDIAL_HEADLESS_CHILD",
        "CORDIAL_TRUSTED_CERTIFICATES",
        "CORDIAL_APK",
        "CORDIAL_APK_DIR",
        "CORDIAL_DEV_CONTROL",
    ];
    if OWNED.contains(&name) {
        return false;
    }
    name.starts_with("CORDIAL_") || name.starts_with("MIMALLOC_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_round_trip() {
        let c = Config::default();
        c.validate().unwrap();
        let text = c.to_toml().unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        back.validate().unwrap();
        assert_eq!(back.scheduler.max_instances, 300);
    }

    #[test]
    fn a_typo_is_an_error_not_a_default() {
        let e = toml::from_str::<Config>("[scheduler]\nmax_concurent_starts = 9\n").unwrap_err();
        assert!(e.to_string().contains("max_concurent_starts"), "{e}");
    }

    #[test]
    fn problems_are_collected() {
        let mut c = Config::default();
        c.scheduler.max_concurrent_starts = 65;
        c.resources.memory_high_mib = 4096;
        c.resources.memory_max_mib = 1024;
        c.engine.env.insert("LD_PRELOAD".into(), "/tmp/x.so".into());
        c.engine.resolution = "big".into();
        let p = c.problems();
        assert!(p.len() >= 4, "{p:?}");
    }

    #[test]
    fn engine_env_cannot_undo_an_isolation_guarantee() {
        for bad in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "HOME",
            "XDG_DATA_HOME",
            "PATH",
            "CORDIAL_SECRET_STORE",
            "CORDIAL_PROFILE_ROOT",
            "cordial_x",
            "CORDIAL-X",
            "",
        ] {
            assert!(!allowed_engine_env(bad), "{bad:?} must be refused");
        }
        for good in [
            "CORDIAL_RESOLUTION",
            "MIMALLOC_PURGE_DELAY",
            "CORDIAL_NO_VULKAN",
        ] {
            assert!(allowed_engine_env(good), "{good:?}");
        }
    }

    #[test]
    fn resolutions() {
        assert_eq!(parse_resolution("1280x720"), Some((1280, 720)));
        assert_eq!(parse_resolution("320x240"), Some((320, 240)));
        for s in [
            "",
            "x",
            "1280",
            "0x0",
            "319x240",
            "320x239",
            "99999x1",
            "1280X720",
            "-1x5",
            "1280x720 ",
        ] {
            assert_eq!(parse_resolution(s), None, "{s:?}");
        }
    }

    #[test]
    fn auto_concurrency_is_modest_on_small_machines() {
        assert_eq!(auto_concurrent_starts(4, true), 1);
        assert_eq!(auto_concurrent_starts(4, false), 2);
        assert_eq!(auto_concurrent_starts(1, false), 1);
        assert_eq!(auto_concurrent_starts(64, false), 8);
        assert_eq!(auto_concurrent_starts(0, true), 1);
    }

    #[test]
    fn the_shipped_example_parses_and_says_what_the_defaults_say() {
        // max_concurrent_starts is 0 (auto) in the example and 2 in the defaults.
        let text = include_str!("../../../config/hrdd.toml.example");
        let c: Config =
            toml::from_str(text).expect("the example must be valid TOML with known keys");
        c.validate().unwrap();
        let d = Config::default();
        assert_eq!(c.scheduler.max_instances, d.scheduler.max_instances);
        assert_eq!(
            c.scheduler.disconnect_grace_s,
            d.scheduler.disconnect_grace_s
        );
        assert_eq!(c.resources.default_mode, d.resources.default_mode);
        assert_eq!(c.engine.graphics, d.engine.graphics);
        assert_eq!(c.engine.cordial_run, d.engine.cordial_run);
        assert_eq!(c.login.timeout_s, d.login.timeout_s);
        assert!(!c.network.allow_unrouted);
    }

    #[test]
    fn program_paths_written_by_an_older_init_are_read_as_the_new_defaults() {
        let old = "[engine]\n\
            cordial_run = \"/usr/lib/cordial-hrd/cordial-run\"\n\
            enter = \"/usr/lib/cordial-hrd/cordial-enter\"\n\
            importer = \"/usr/lib/cordial-hrd/cordial-import\"\n";
        let mut c: Config = toml::from_str(old).unwrap();
        c.upgrade_legacy_paths();
        let d = Config::default();
        assert_eq!(c.engine.cordial_run, d.engine.cordial_run);
        assert_eq!(c.engine.enter, d.engine.enter);
        assert_eq!(c.engine.importer, d.engine.importer);

        // A path somebody chose themselves is never rewritten.
        let mut own: Config = toml::from_str("[engine]\nenter = \"/opt/mine/enter\"\n").unwrap();
        own.upgrade_legacy_paths();
        assert_eq!(own.engine.enter, "/opt/mine/enter");
    }

    #[test]
    fn a_missing_file_gives_the_defaults() {
        let c = Config::load(Path::new("/nonexistent/hrdd.toml")).unwrap();
        assert_eq!(
            c.scheduler.max_concurrent_starts, 0,
            "0 means: choose from the machine"
        );
    }
}
