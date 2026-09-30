//! The registry: what the operator has configured, and the record of what each
//! instance last did.
//!
//! **Nothing in this module is a secret.** Sessions live in the Secret Service
//! keyring (see docs/security.md) and WireGuard keys in the privileged
//! helper's root-only directory; the registry holds names, relations and
//! public parameters only, so it can be exported, diffed and shown in a bug
//! report.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::ids::{AccountName, GroupName, NetworkName, PlaceId};

/// Bumped when the on-disk shape changes incompatibly. The daemon refuses a
/// registry with a schema newer than it understands rather than guessing.
pub const REGISTRY_SCHEMA: u32 = 1;

// ---------------------------------------------------------------------------
// Instance state
// ---------------------------------------------------------------------------

/// What the manager believes about an instance.
///
/// The names are the ones the brief lists. The rule that matters is about what
/// is *not* a reason to move forward: a running process is not `connected`,
/// and neither is a successfully spawned command. `Connected` requires a
/// signal from the runtime that says so; without one the honest answer for a
/// live process is [`State::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Registered, nothing running, nothing known to be wrong.
    Configured,
    /// Cannot start (or was started and found) without a session the operator
    /// has to provide. The reason says which.
    AuthRequired,
    /// Waiting in the start queue.
    Queued,
    /// The process set exists; the engine has not yet reached the point where
    /// it could join anything.
    Starting,
    /// A join was requested and the runtime has not yet said it is in the game.
    Joining,
    /// The runtime reported, through a signal this manager trusts, that the
    /// client is in the experience.
    Connected,
    /// The runtime reported losing the game connection, or the process ended
    /// after having been connected. The manager stops the process set and does
    /// **not** start it again.
    Disconnected,
    /// Stopped on request, or exited cleanly with nothing to report.
    Stopped,
    /// Could not start, crashed, was killed by the kernel, or timed out
    /// starting.
    Failed,
    /// A process exists but no reliable signal says what it is doing, or the
    /// record could not be reconciled with reality after a manager restart.
    Unknown,
}

impl State {
    pub const ALL: [State; 10] = [
        State::Configured,
        State::AuthRequired,
        State::Queued,
        State::Starting,
        State::Joining,
        State::Connected,
        State::Disconnected,
        State::Stopped,
        State::Failed,
        State::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            State::Configured => "configured",
            State::AuthRequired => "auth_required",
            State::Queued => "queued",
            State::Starting => "starting",
            State::Joining => "joining",
            State::Connected => "connected",
            State::Disconnected => "disconnected",
            State::Stopped => "stopped",
            State::Failed => "failed",
            State::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        State::ALL.iter().copied().find(|st| st.as_str() == s)
    }

    /// States in which the manager expects a process set to exist. `Unknown` is
    /// deliberately included: a process that exists but cannot be classified
    /// is exactly the case that must not be forgotten.
    pub fn expects_processes(self) -> bool {
        matches!(
            self,
            State::Starting | State::Joining | State::Connected | State::Unknown
        )
    }

    /// States from which `instance start` is accepted.
    pub fn can_start(self) -> bool {
        matches!(
            self,
            State::Configured
                | State::AuthRequired
                | State::Disconnected
                | State::Stopped
                | State::Failed
        )
    }

    /// States that occupy a slot: counted against the group capacity check at
    /// start and shown as "live" in summaries.
    pub fn is_live(self) -> bool {
        matches!(self, State::Queued) || self.expects_processes()
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Resource modes
// ---------------------------------------------------------------------------

/// How much of the optional machinery a client runs with.
///
/// Each mode is a *set of concrete settings* listed in `docs/memory.md`; none
/// is a flag that "turns off assets". What a mode cannot do, because the
/// closed engine decides it, is listed there too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMode {
    /// Upstream behaviour, unchanged except for the isolation every mode gets
    /// (private directories, no plaintext session, network namespace).
    #[default]
    Compatible,
    /// Also switches off the optional open-layer components that were
    /// confirmed unnecessary for a session nobody is looking at.
    Minimal,
    /// Also applies limits that can cost throughput or hide symptoms. Only
    /// items with an implementation appear here.
    Aggressive,
}

impl ResourceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceMode::Compatible => "compatible",
            ResourceMode::Minimal => "minimal",
            ResourceMode::Aggressive => "aggressive",
        }
    }
}

impl std::str::FromStr for ResourceMode {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "compatible" => Ok(ResourceMode::Compatible),
            "minimal" => Ok(ResourceMode::Minimal),
            "aggressive" => Ok(ResourceMode::Aggressive),
            _ => Err(crate::Error::invalid(format!(
                "unknown resource mode {s:?}; expected compatible, minimal or aggressive"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Accounts, groups, networks
// ---------------------------------------------------------------------------

/// What is known about whether an account can sign in. **Never** a claim that
/// a session is valid unless it was observed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthStatus {
    /// Not determined: the secret store was locked or unreachable when asked.
    #[default]
    Unknown,
    /// Nothing is stored for this profile.
    None,
    /// An item exists in the secret store. Whether Roblox still accepts it is
    /// not known.
    Stored,
    /// A client using this session was seen signed in.
    Verified,
    /// A client started and reached a signed-out screen, or the operator
    /// logged the account out.
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthInfo {
    #[serde(default)]
    pub status: AuthStatus,
    /// When `status` was last established, unix seconds.
    #[serde(default)]
    pub checked_at: Option<u64>,
    /// Why, in words the operator can act on.
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: AccountName,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub group: Option<GroupName>,
    #[serde(default)]
    pub note: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub auth: AuthInfo,
    /// Overrides the daemon-wide resource mode for this account.
    #[serde(default)]
    pub mode: Option<ResourceMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: GroupName,
    /// The tunnel this group's clients leave through. `None` means the group
    /// has no network and its instances are refused unless the operator has
    /// set `allow_unrouted = true` in the daemon configuration.
    #[serde(default)]
    pub network: Option<NetworkName>,
    /// How many accounts may be assigned. An organisational limit chosen by the
    /// operator; **not** a number Roblox documents.
    pub capacity: u32,
    #[serde(default)]
    pub note: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetBackend {
    /// A Linux network namespace holding one WireGuard interface.
    WireguardNetns,
}

/// How IPv6 is treated inside a group's namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Policy {
    /// Send it through the tunnel if the tunnel config carries an IPv6 address
    /// and a `::/0` route; otherwise block it.
    #[default]
    Auto,
    /// Disable IPv6 in the namespace regardless of the tunnel config.
    Block,
}

/// Where the operator expects a group's traffic to appear from. The two halves
/// are kept apart on purpose.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExitInfo {
    /// What the operator configured, for example the public address the gateway
    /// maps this group to. Nothing verifies it.
    #[serde(default)]
    pub configured: Option<IpAddr>,
    /// What a probe actually saw. Filled only by `network check`.
    #[serde(default)]
    pub observed: Option<ObservedExit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedExit {
    pub address: IpAddr,
    /// `stun` proves the UDP path; `http` proves only TCP.
    pub via: ProbeKind,
    pub at: u64,
    /// The server asked, so the operator can tell a STUN reply from their own
    /// gateway from one from somebody else's.
    pub server: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Stun,
    Http,
}

/// The public, non-secret half of an imported WireGuard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub name: NetworkName,
    pub backend: NetBackend,
    /// Where the private key is kept. A reference, never the key:
    /// `netd:<name>` means the privileged helper's root-only store.
    pub secret_ref: String,
    pub endpoint: String,
    pub peer_public_key: String,
    pub addresses: Vec<String>,
    pub dns: Vec<IpAddr>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    #[serde(default)]
    pub ipv6: Ipv6Policy,
    #[serde(default)]
    pub exit: ExitInfo,
    /// STUN server for `network check`. Unset by default: the manager does not
    /// contact a third party the operator did not name.
    #[serde(default)]
    pub stun_server: Option<String>,
    /// Upper bound on clients across all groups using this network.
    #[serde(default)]
    pub max_clients: Option<u32>,
    pub created_at: u64,
}

/// Whether a network can carry a group's traffic right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    /// Never applied.
    NotApplied,
    /// Namespace and interface exist and a recent handshake was seen.
    Ready,
    /// Applied but no handshake yet, or an old one. Traffic may still work; the
    /// manager will not claim it does.
    Unverified,
    /// Something the apply should have created is missing.
    Broken,
    /// The helper could not be asked.
    Unknown,
}

// ---------------------------------------------------------------------------
// The registry file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    pub schema: u32,
    #[serde(default)]
    pub accounts: BTreeMap<AccountName, Account>,
    #[serde(default)]
    pub groups: BTreeMap<GroupName, Group>,
    #[serde(default)]
    pub networks: BTreeMap<NetworkName, Network>,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            schema: REGISTRY_SCHEMA,
            accounts: BTreeMap::new(),
            groups: BTreeMap::new(),
            networks: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Instance record
// ---------------------------------------------------------------------------

/// How the process set was identified when the record was written. Enough to
/// tell, after a restart, whether a pid still means what it meant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdent {
    /// The first process of the set.
    pub pid: u32,
    /// Field 22 of `/proc/<pid>/stat`: clock ticks after boot at which the
    /// process started. With the pid it names one process for the life of the
    /// machine; a reused pid has a different start time.
    pub start_ticks: u64,
    /// The cgroup the set lives in, relative to the cgroup root. Empty when the
    /// manager could not create one and is falling back to the weaker pgid
    /// ownership, which `doctor` reports.
    #[serde(default)]
    pub cgroup: String,
    /// Process group of the set, used when there is no cgroup.
    #[serde(default)]
    pub pgid: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitRecord {
    #[serde(default)]
    pub code: Option<i32>,
    #[serde(default)]
    pub signal: Option<i32>,
    /// The kernel OOM-killed something in the set.
    #[serde(default)]
    pub oom_killed: bool,
    /// The exit status could not be observed, for example because the manager
    /// was restarted while the set ran.
    #[serde(default)]
    pub unobserved: bool,
}

/// Facts the runtime has reported about itself, each with the time it was seen.
/// A field is `None` when it was never observed, which is not the same as
/// false.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Signals {
    #[serde(default)]
    pub engine_loaded_at: Option<u64>,
    #[serde(default)]
    pub signed_in_at: Option<u64>,
    #[serde(default)]
    pub signed_out_at: Option<u64>,
    /// The last `app ready: <screen>` the engine printed.
    #[serde(default)]
    pub screen: Option<String>,
    #[serde(default)]
    pub join_requested_at: Option<u64>,
    #[serde(default)]
    pub connected_at: Option<u64>,
    /// Place the client reported joining, which need not be the one asked for
    /// (an experience can teleport).
    #[serde(default)]
    pub joined_place: Option<u64>,
    #[serde(default)]
    pub disconnected_at: Option<u64>,
    /// The number in the engine's `Disconnection Notification. Reason: N`, the
    /// only machine-readable reason the open layer has access to. What N means
    /// is Roblox's, and this manager does not interpret it.
    #[serde(default)]
    pub disconnect_code: Option<i64>,
}

/// Why a process set was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    /// Joins an experience.
    #[default]
    Play,
    /// A sign-in session: no join, and the only kind with the operator's
    /// login console attached.
    Login,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceRecord {
    pub id: AccountName,
    /// Increments on every start; distinguishes this run's log lines and
    /// records from the previous one's.
    pub run: u64,
    pub state: State,
    /// Why the instance is in this state, in words.
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub place_id: Option<PlaceId>,
    #[serde(default)]
    pub group: Option<GroupName>,
    pub mode: ResourceMode,
    /// Runtime build this run uses, by engine version. Fixed at start, so a
    /// later `runtime use` does not change a running instance's files.
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub queued_at: Option<u64>,
    #[serde(default)]
    pub started_at: Option<u64>,
    pub state_since: u64,
    #[serde(default)]
    pub ended_at: Option<u64>,
    #[serde(default)]
    pub process: Option<ProcessIdent>,
    #[serde(default)]
    pub exit: Option<ExitRecord>,
    #[serde(default)]
    pub signals: Signals,
    #[serde(default)]
    pub kind: RunKind,
    /// The largest `memory.current` (or, without the memory controller, the
    /// largest summed RSS) seen while the run was `starting`. Feeds the start
    /// scheduler's estimate of what the next start will cost.
    #[serde(default)]
    pub start_peak_bytes: Option<u64>,
}

impl InstanceRecord {
    pub fn new(id: AccountName, now: u64) -> Self {
        InstanceRecord {
            id,
            run: 0,
            state: State::Configured,
            reason: None,
            place_id: None,
            group: None,
            mode: ResourceMode::Compatible,
            runtime: None,
            queued_at: None,
            started_at: None,
            state_since: now,
            ended_at: None,
            process: None,
            exit: None,
            signals: Signals::default(),
            kind: RunKind::Play,
            start_peak_bytes: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_names_round_trip() {
        for s in State::ALL {
            assert_eq!(State::parse(s.as_str()), Some(s));
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
        assert_eq!(State::parse("running"), None);
    }

    #[test]
    fn unknown_keeps_its_process_expectation() {
        // A process of unknown purpose must still be supervised and stoppable.
        assert!(State::Unknown.expects_processes());
        assert!(!State::Connected.can_start());
        assert!(State::Disconnected.can_start());
        assert!(State::Queued.is_live() && !State::Queued.expects_processes());
    }

    #[test]
    fn the_registry_carries_no_field_that_could_hold_a_secret() {
        // Serialise a fully populated network and make sure the JSON contains
        // none of the words that would indicate key material.
        let n = Network {
            name: NetworkName::new("de-1").unwrap(),
            backend: NetBackend::WireguardNetns,
            secret_ref: "netd:de-1".into(),
            endpoint: "203.0.113.1:51820".into(),
            peer_public_key: "AAAA".into(),
            addresses: vec!["10.0.0.2/32".into()],
            dns: vec![],
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: None,
            persistent_keepalive: Some(25),
            ipv6: Ipv6Policy::Auto,
            exit: ExitInfo::default(),
            stun_server: None,
            max_clients: None,
            created_at: 0,
        };
        let json = serde_json::to_string(&n).unwrap().to_ascii_lowercase();
        assert!(!json.contains("private"), "{json}");
        assert!(!json.contains("preshared"), "{json}");
    }

    #[test]
    fn a_default_registry_round_trips() {
        let r = Registry::default();
        let s = serde_json::to_string(&r).unwrap();
        let back: Registry = serde_json::from_str(&s).unwrap();
        assert_eq!(back.schema, REGISTRY_SCHEMA);
    }
}
