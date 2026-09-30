//! The control protocol between `cordialctl` and `cordiald`.
//!
//! Newline-delimited JSON over a Unix stream socket: one request per line,
//! answered by one response line, except for the two streaming requests
//! (`subscribe`, `logs` with `follow`) which are answered by event lines until
//! either side closes. A line is limited to [`MAX_LINE`] bytes.
//!
//! There is deliberately no authentication beyond the socket itself: the
//! daemon checks the peer's uid with `SO_PEERCRED` and the socket's file mode
//! decides who can connect at all. Anyone who can talk to this socket can do
//! anything the manager can do, which is exactly as much as the service user
//! can do anyway (docs/security.md).
//!
//! One request carries file descriptors: `runtime_import` passes the APKs as
//! `SCM_RIGHTS` so that the daemon reads exactly the files the operator
//! opened, whatever their paths or permissions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{AccountName, GroupName, NetworkName, PlaceId};
use crate::model::{AuthStatus, Network, Readiness, ResourceMode, State};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_LINE: usize = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: u64,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "args", rename_all = "snake_case")]
pub enum Request {
    /// First message of a session; the daemon answers with its version.
    Hello { client: String, protocol: u32 },
    DaemonInfo,
    /// Server-side health checks (the parts that need the daemon's view).
    DaemonDoctor,
    /// Ask the daemon to exit. Instances follow `scheduler.on_daemon_stop`
    /// unless `stop_instances` overrides it.
    Shutdown { stop_instances: Option<bool> },

    // -- accounts ---------------------------------------------------------
    AccountAdd { name: AccountName, labels: Vec<String>, note: Option<String>, group: Option<GroupName> },
    AccountList,
    AccountSet { name: AccountName, labels: Option<Vec<String>>, note: Option<String>, mode: Option<ResourceMode> },
    /// `confirm` must equal the account name; checked by the daemon so that no
    /// client can skip it.
    AccountRemove { name: AccountName, confirm: String },
    /// Erase the stored session. Refused while the instance is live.
    AccountLogout { name: AccountName },
    /// Start an interactive sign-in session for the account and keep it until
    /// it succeeds, is cancelled or times out.
    LoginStart { name: AccountName },
    LoginStatus { name: AccountName },
    LoginCancel { name: AccountName },
    /// Metadata only; never contains anything secret.
    AccountExport,
    AccountImport { accounts: Vec<ExportedAccount>, replace: bool },

    // -- groups -----------------------------------------------------------
    GroupCreate { name: GroupName, network: Option<NetworkName>, capacity: u32, note: Option<String> },
    GroupList,
    GroupAssign { group: GroupName, accounts: Vec<AccountName>, create_missing: bool },
    GroupRemove { name: GroupName },

    // -- networks ---------------------------------------------------------
    /// Register the public half of an imported configuration. The private key
    /// goes to the privileged helper, not through here.
    NetworkRegister { network: Network },
    NetworkList,
    NetworkRemove { name: NetworkName },
    NetworkPlan,
    NetworkApply { prune: bool },
    NetworkCheck { name: NetworkName },
    NetworkSet { name: NetworkName, configured_exit: Option<String>, stun_server: Option<String>, max_clients: Option<u32> },

    // -- instances --------------------------------------------------------
    InstanceStart { account: AccountName, place_id: PlaceId, group: Option<GroupName>, private_server_code: Option<String>, mode: Option<ResourceMode> },
    InstanceStop { id: AccountName, force: bool },
    GroupStart { group: GroupName, place_id: PlaceId, private_server_code: Option<String>, mode: Option<ResourceMode> },
    StopAll { force: bool },
    QueueList,
    QueueCancel { ids: Vec<AccountName>, all: bool },

    // -- observation ------------------------------------------------------
    Status { filter: Filter },
    Stats { filter: Filter },
    Logs { id: AccountName, lines: usize, follow: bool },
    Subscribe,

    // -- runtime store ----------------------------------------------------
    /// File descriptors, one per entry of `files` and in the same order, are
    /// attached to this message.
    RuntimeImport { files: Vec<ImportFile>, label: Option<String>, make_current: bool },
    RuntimeList,
    RuntimeUse { version: String },
    RuntimeRemove { version: String },

    // -- secrets ----------------------------------------------------------
    SecretsStatus,
    /// Creates the keyring if it does not exist (`create: true`) or unlocks it.
    /// The passphrase is held in memory only for the duration of the call.
    SecretsUnlock { passphrase: String, create: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFile {
    /// Basename as the operator named it. Informational and recorded as
    /// provenance; never used as a path.
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default)]
    pub states: Vec<State>,
    #[serde(default)]
    pub group: Option<GroupName>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub accounts: Vec<AccountName>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub id: u64,
    #[serde(flatten)]
    pub body: ResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseBody {
    Ok { ok: bool, data: serde_json::Value },
    Err { ok: bool, error: WireError },
    /// One line of a stream.
    Event { event: serde_json::Value },
    /// End of a stream.
    End { end: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub code: String,
    pub message: String,
}

impl ResponseEnvelope {
    pub fn ok(id: u64, data: impl Serialize) -> Self {
        ResponseEnvelope {
            id,
            body: ResponseBody::Ok { ok: true, data: serde_json::to_value(data).unwrap_or(serde_json::Value::Null) },
        }
    }

    pub fn err(id: u64, e: &crate::Error) -> Self {
        ResponseEnvelope {
            id,
            body: ResponseBody::Err { ok: false, error: WireError { code: e.code().into(), message: e.to_string() } },
        }
    }

    pub fn event(id: u64, ev: impl Serialize) -> Self {
        ResponseEnvelope {
            id,
            body: ResponseBody::Event { event: serde_json::to_value(ev).unwrap_or(serde_json::Value::Null) },
        }
    }

    pub fn end(id: u64) -> Self {
        ResponseEnvelope { id, body: ResponseBody::End { end: true } }
    }
}

// ---------------------------------------------------------------------------
// Views returned by the daemon
// ---------------------------------------------------------------------------

/// A measurement that may not exist. `None` means "not measured" or
/// "unavailable"; it is never shown as zero.
pub type Measured<T> = Option<T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceView {
    pub id: AccountName,
    pub state: State,
    pub reason: Option<String>,
    pub group: Option<GroupName>,
    pub place_id: Option<PlaceId>,
    pub run: u64,
    pub runtime: Option<String>,
    pub mode: ResourceMode,
    pub auth: AuthStatus,
    pub state_since: u64,
    pub started_at: Option<u64>,
    pub uptime_s: Option<u64>,
    pub queue_position: Option<u32>,
    pub pid: Option<u32>,
    pub mem: Option<MemoryView>,
    pub cpu_percent: Measured<f64>,
    pub processes: Measured<u32>,
    pub threads: Measured<u32>,
    /// Latest lines that explain the state, already scrubbed.
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryView {
    pub rss_bytes: Measured<u64>,
    pub pss_bytes: Measured<u64>,
    /// Private clean + private dirty: what would be freed by killing the
    /// process set, ignoring shared pages.
    pub uss_bytes: Measured<u64>,
    pub swap_bytes: Measured<u64>,
    /// `memory.current` of the instance's cgroup: includes page cache charged
    /// to it, so it is not comparable with RSS or PSS.
    pub cgroup_current_bytes: Measured<u64>,
    pub cgroup_peak_bytes: Measured<u64>,
    /// When the PSS figures were taken, unix seconds.
    pub pss_sampled_at: Measured<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountView {
    pub name: AccountName,
    pub labels: Vec<String>,
    pub group: Option<GroupName>,
    pub note: Option<String>,
    pub auth: AuthStatus,
    pub auth_detail: Option<String>,
    pub auth_checked_at: Option<u64>,
    pub state: State,
    pub mode: Option<ResourceMode>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupView {
    pub name: GroupName,
    pub network: Option<NetworkName>,
    pub capacity: u32,
    pub assigned: u32,
    pub live: u32,
    pub network_ready: Option<Readiness>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkView {
    pub network: Network,
    pub readiness: Readiness,
    pub reason: Option<String>,
    pub groups: Vec<GroupName>,
    pub assigned_clients: u32,
    pub latest_handshake_age_s: Measured<u64>,
    pub rx_bytes: Measured<u64>,
    pub tx_bytes: Measured<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedAccount {
    pub name: AccountName,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub group: Option<GroupName>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub mode: Option<ResourceMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeView {
    pub version: String,
    pub current: bool,
    pub previous: bool,
    pub imported_at: u64,
    pub signer_sha256: String,
    pub engine_sha256: String,
    pub split: bool,
    pub in_use_by: Vec<AccountName>,
    pub size_bytes: Measured<u64>,
}

/// One row of the `stats` output: a class of process, summed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassStats {
    pub processes: u32,
    pub threads: u32,
    pub rss_bytes: Measured<u64>,
    pub pss_bytes: Measured<u64>,
    pub uss_bytes: Measured<u64>,
    pub swap_bytes: Measured<u64>,
    pub cpu_percent: Measured<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatsView {
    /// Seconds between the start of the window the CPU figures cover and now.
    pub cpu_window_s: Measured<f64>,
    pub manager: ClassStats,
    /// `cordial-run` and everything sharing its executable.
    pub engines: ClassStats,
    pub compositors: ClassStats,
    /// `deno`, `bwrap`, `WebKit*`, the keyring and anything else in an
    /// instance cgroup that is none of the above.
    pub helpers: ClassStats,
    pub total: ClassStats,
    pub instances: u32,
    pub sampled_at: Measured<u64>,
    /// cgroup-level sum of `memory.current` over instances; a different
    /// quantity from the per-process sums above, shown beside them so the
    /// difference is visible.
    pub cgroup_current_bytes: Measured<u64>,
    pub mem_available_bytes: Measured<u64>,
    pub memory_pressure_some_avg10: Measured<f64>,
    pub cache_disk_bytes: Measured<u64>,
    /// Bytes through each group's tunnel, if the helper could be asked.
    pub network: BTreeMap<String, NetTraffic>,
    /// Kernel same-page merging counters, present only when KSM is on.
    pub ksm: Option<KsmView>,
    /// What could not be measured and why, e.g. "memory controller not delegated".
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetTraffic {
    pub rx_bytes: Measured<u64>,
    pub tx_bytes: Measured<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KsmView {
    pub pages_shared: u64,
    pub pages_sharing: u64,
    pub run: u64,
}

/// What `subscribe` streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    State { id: AccountName, from: State, to: State, reason: Option<String>, at: u64 },
    Log { id: AccountName, line: String },
    Notice { message: String },
}

/// Encode one protocol line (including the newline).
pub fn encode_line<T: Serialize>(v: &T) -> crate::Result<Vec<u8>> {
    let mut b = serde_json::to_vec(v).map_err(|e| crate::Error::Internal(format!("encode: {e}")))?;
    if b.len() >= MAX_LINE {
        return Err(crate::Error::Protocol(format!("message of {} bytes exceeds the {MAX_LINE} byte limit", b.len())));
    }
    b.push(b'\n');
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_with_the_envelope_flattened() {
        let req = RequestEnvelope {
            id: 7,
            request: Request::InstanceStart {
                account: AccountName::new("alt-1").unwrap(),
                place_id: PlaceId::new(920587237).unwrap(),
                group: None,
                private_server_code: None,
                mode: Some(ResourceMode::Minimal),
            },
        };
        let line = encode_line(&req).unwrap();
        let text = std::str::from_utf8(&line).unwrap();
        assert!(text.contains("\"cmd\":\"instance_start\""), "{text}");
        assert!(text.contains("\"id\":7"), "{text}");
        let back: RequestEnvelope = serde_json::from_slice(&line).unwrap();
        assert_eq!(back.id, 7);
        assert!(matches!(back.request, Request::InstanceStart { .. }));
    }

    #[test]
    fn a_hostile_name_cannot_get_through_deserialisation() {
        let bad = r#"{"id":1,"cmd":"instance_stop","args":{"id":"../../etc/passwd","force":false}}"#;
        assert!(serde_json::from_str::<RequestEnvelope>(bad).is_err());
    }

    #[test]
    fn responses_are_distinguishable() {
        let ok = serde_json::to_string(&ResponseEnvelope::ok(1, vec![1, 2])).unwrap();
        let err = serde_json::to_string(&ResponseEnvelope::err(2, &crate::Error::not_found("x"))).unwrap();
        let ev = serde_json::to_string(&ResponseEnvelope::event(3, Event::Notice { message: "hi".into() })).unwrap();
        let end = serde_json::to_string(&ResponseEnvelope::end(3)).unwrap();
        assert!(ok.contains("\"ok\":true"));
        assert!(err.contains("\"code\":\"not_found\""));
        assert!(ev.contains("\"event\""));
        assert!(end.contains("\"end\":true"));
        let back: ResponseEnvelope = serde_json::from_str(&err).unwrap();
        assert!(matches!(back.body, ResponseBody::Err { .. }));
        let back: ResponseEnvelope = serde_json::from_str(&end).unwrap();
        assert!(matches!(back.body, ResponseBody::End { .. }));
    }

    #[test]
    fn oversized_messages_are_refused() {
        let big = Request::Hello { client: "x".repeat(MAX_LINE), protocol: 1 };
        assert!(encode_line(&RequestEnvelope { id: 1, request: big }).is_err());
    }
}
