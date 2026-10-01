//! The wire between the unprivileged manager and `hrd-netd`.
//!
//! Same framing as the control protocol (one JSON object per line). The
//! helper is root; the manager is not. **The manager can only name things**:
//! a group, a network, an IPv6 policy. It cannot give the helper an address, a
//! command, a path or a route. Everything that becomes a system change is
//! derived inside the helper from the configuration it stored itself, so a
//! compromised manager can ask for a group to be applied or removed and cannot
//! make the helper do anything else.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use hrd_core::ids::{GroupName, NetworkName};
use hrd_core::model::Ipv6Policy;

use crate::ipnet::IpNet;
use crate::plan::{GroupSpec, Plan};

/// One request line: an id the reply echoes, and the request flattened beside
/// it, the same shape the control protocol uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetdEnvelope {
    pub id: u64,
    #[serde(flatten)]
    pub req: NetdRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "args", rename_all = "snake_case")]
pub enum NetdRequest {
    Ping,
    /// Parse, validate and store a WireGuard file. The text contains the
    /// private key; the helper keeps it in its root-only directory.
    PutNetwork {
        name: NetworkName,
        config: String,
        dns: Vec<IpAddr>,
    },
    DeleteNetwork {
        name: NetworkName,
    },
    ListNetworks,
    Plan {
        groups: Vec<GroupSpec>,
        prune: bool,
    },
    Apply {
        groups: Vec<GroupSpec>,
        prune: bool,
        allow_disruptive: Vec<GroupName>,
    },
    Teardown {
        group: GroupName,
        allow_disruptive: bool,
    },
    Status {
        groups: Vec<GroupName>,
    },
    /// Send one UDP question from inside the group's namespace and report the
    /// address the far end saw.
    ProbeStun {
        group: GroupName,
        server: String,
    },
}

/// The non-secret description of a stored network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub name: NetworkName,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: String,
    pub peer_public_key: String,
    /// Derived from the private key, for the gateway's peer list.
    pub client_public_key: String,
    pub mtu: Option<u16>,
    pub persistent_keepalive: Option<u16>,
    pub carries_ipv6: bool,
    pub has_preshared_key: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupStatus {
    pub group: Option<GroupName>,
    pub network: Option<NetworkName>,
    pub namespace_present: bool,
    pub interface_present: bool,
    pub link_up: bool,
    /// Unix seconds of the last completed handshake; `None` if there has never
    /// been one.
    pub latest_handshake: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub applied_hash: Option<String>,
    pub ipv6_blocked: Option<bool>,
    pub endpoint: Option<String>,
    /// What is wrong, in words.
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StunResult {
    pub address: IpAddr,
    pub port: u16,
    pub server: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyOutcome {
    pub group: GroupName,
    pub ok: bool,
    pub action: crate::plan::Action,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanReply {
    pub plan: Plan,
    /// The same steps as text, with the helper's directories filled in.
    pub text: Vec<String>,
    pub ipv6: Vec<(GroupName, Ipv6Policy)>,
}
