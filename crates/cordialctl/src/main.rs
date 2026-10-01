//! `cordialctl`: the command line for the Cordial fleet manager.
//!
//! Everything goes through the daemon's control socket except the few commands
//! that have to work without it (`init`, `doctor`, `gateway plan`) and
//! `network add`, which hands a WireGuard key to the privileged helper directly
//! so that the key never passes through the daemon.

mod cmd_accounts;
mod cmd_basic;
mod cmd_fleet;
mod cmd_net;
#[cfg(feature = "tui")]
mod tui;
mod util;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use hrd_core::ids::{AccountName, GroupName, NetworkName, PlaceId};
use hrd_core::layout::Layout;
use hrd_core::model::{ResourceMode, State};
use hrd_core::wire::Client;
use hrd_core::Result;

use crate::util::Out;

#[derive(Parser)]
#[command(
    name = "cordialctl",
    version,
    about = "Manage many Cordial clients from the terminal",
    long_about = "Manage many Cordial clients from the terminal.\n\n\
        The daemon (cordiald) starts with no clients. A client starts only when you tell it to and is never started again by the manager: a disconnected or failed session stays that way, with its reason, until you start it.",
    after_help = "Exit codes: 0 ok, 1 error, 2 bad usage or invalid input, 3 not found, 4 conflict, 5 unavailable (daemon, helper, runtime, secret store), 6 authentication required, 7 permission denied."
)]
struct Cli {
    /// Print machine-readable JSON instead of text
    #[arg(long, global = true)]
    json: bool,
    /// Control socket of cordiald
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// Seconds to wait for the daemon to answer
    #[arg(long, global = true, default_value_t = 60, value_name = "SECONDS")]
    timeout: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check the prerequisites and create the configuration skeleton (needs root)
    Init(cmd_basic::InitArgs),
    /// Check this machine and the running daemon; says what to fix
    Doctor,
    /// Install and choose the Roblox Android build the clients run
    #[command(subcommand)]
    Runtime(RuntimeCmd),
    /// Register, sign in and remove accounts
    #[command(subcommand)]
    Account(AccountCmd),
    /// WireGuard networks that groups leave through
    #[command(subcommand)]
    Network(NetworkCmd),
    /// Groups of accounts sharing one exit
    #[command(subcommand)]
    Group(GroupCmd),
    /// Start and stop single clients
    #[command(subcommand)]
    Instance(InstanceCmd),
    /// Stop every client (queued ones are cancelled)
    StopAll {
        /// Kill at once instead of asking the clients to exit first
        #[arg(long)]
        force: bool,
    },
    /// What every account's client is doing
    Status(StatusArgs),
    /// Memory, CPU and traffic: manager, engines, compositors, helpers, total
    Stats {
        /// Also list every instance with its own figures
        #[arg(long)]
        per_instance: bool,
    },
    /// A client's log (scrubbed of credentials)
    Logs {
        id: AccountName,
        /// How many of the last lines to show
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Keep printing new lines; Ctrl-C leaves the client running
        #[arg(short, long)]
        follow: bool,
    },
    /// The start queue
    #[command(subcommand)]
    Queue(QueueCmd),
    /// The keyring that holds sessions
    #[command(subcommand)]
    Secrets(SecretsCmd),
    /// Daemon settings (overrides kept in the state directory)
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Files for the VPS that terminates the tunnels (printed, never applied)
    #[command(subcommand)]
    Gateway(GatewayCmd),
    /// The daemon itself
    #[command(subcommand)]
    Daemon(DaemonCmd),
    /// Full-screen terminal panel; leaving it does not stop any client
    Tui,
}

#[derive(Subcommand)]
enum RuntimeCmd {
    /// Verify and install a Roblox Android build from files you downloaded
    Import {
        /// An APK, or a directory of APKs (base and split APKs of one build)
        #[arg(long, required = true, value_name = "PATH")]
        apk: Vec<PathBuf>,
        #[arg(long)]
        label: Option<String>,
        /// Install it but keep the current build selected
        #[arg(long)]
        keep_current: bool,
    },
    /// Download the x86-64 Roblox build from the mirror upstream Cordial uses,
    /// check it against Roblox's signing certificate and install it
    Fetch {
        /// A version name from `--list` (default: the newest the mirror has)
        #[arg(long, value_name = "NAME")]
        version: Option<String>,
        /// Only list the versions the mirror offers
        #[arg(long)]
        list: bool,
        /// Install it but keep the current build selected
        #[arg(long)]
        keep_current: bool,
    },
    List,
    /// Choose the build new clients start with (running ones keep theirs)
    Use {
        version: String,
    },
    Remove {
        version: String,
    },
}

#[derive(Subcommand)]
enum AccountCmd {
    Add {
        name: AccountName,
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        group: Option<GroupName>,
    },
    /// Sign the account in on this machine (you type the password; it is not stored)
    Login {
        name: AccountName,
        /// Start the session and return; attach later with `account login NAME --attach`
        #[arg(long)]
        detach: bool,
        /// Attach to a sign-in session that is already running
        #[arg(long)]
        attach: bool,
        /// Columns of the terminal preview of the client's frame
        #[arg(long, default_value_t = 100)]
        columns: u32,
    },
    List {
        #[arg(long)]
        group: Option<GroupName>,
        #[arg(long)]
        label: Option<String>,
    },
    Set {
        name: AccountName,
        #[arg(long = "label")]
        labels: Option<Vec<String>>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        mode: Option<ResourceMode>,
    },
    /// Erase the stored session (the account stays registered)
    Logout { name: AccountName },
    /// Remove the account, its profile and its stored session
    Remove {
        name: AccountName,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Metadata only: names, labels, groups. Never a secret
    Export {
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
    },
    Import {
        file: PathBuf,
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Subcommand)]
enum NetworkCmd {
    /// Import a WireGuard file. The key goes to the privileged helper (run as root)
    Add {
        name: NetworkName,
        #[arg(long, value_name = "PATH")]
        wireguard_config: PathBuf,
        /// DNS server(s) reachable through the tunnel (overrides the file's DNS line)
        #[arg(long)]
        dns: Vec<std::net::IpAddr>,
        /// The public address you expect this tunnel to leave from
        #[arg(long)]
        exit_ip: Option<String>,
        /// host:port of a STUN server you choose, for `network check`
        #[arg(long)]
        stun_server: Option<String>,
        /// Block IPv6 in the group even if the tunnel carries it
        #[arg(long)]
        block_ipv6: bool,
        #[arg(long)]
        max_clients: Option<u32>,
    },
    List,
    /// Show what `apply` would do; changes nothing
    Plan,
    /// Make the system match the plan (namespaces, tunnels, firewall); run as root or the service user
    Apply {
        /// Do not remove namespaces of groups that no longer exist
        #[arg(long)]
        no_prune: bool,
    },
    /// Probe the exit from inside the group's namespace (needs a stun_server)
    Check {
        name: NetworkName,
    },
    Set {
        name: NetworkName,
        #[arg(long)]
        exit_ip: Option<String>,
        #[arg(long)]
        stun_server: Option<String>,
        #[arg(long)]
        max_clients: Option<u32>,
    },
    Remove {
        name: NetworkName,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    Create {
        name: GroupName,
        #[arg(long)]
        network: Option<NetworkName>,
        /// How many accounts may be assigned: your own limit, not a platform number
        #[arg(long)]
        capacity: u32,
        #[arg(long)]
        note: Option<String>,
    },
    /// Put the accounts listed in FILE (one name per line) into the group
    Assign {
        name: GroupName,
        #[arg(long, value_name = "FILE")]
        accounts: PathBuf,
        /// Register accounts that do not exist yet
        #[arg(long)]
        create_missing: bool,
    },
    List,
    Set {
        name: GroupName,
        #[arg(long)]
        capacity: Option<u32>,
        #[arg(long)]
        network: Option<NetworkName>,
        #[arg(long)]
        clear_network: bool,
        #[arg(long)]
        note: Option<String>,
    },
    Remove {
        name: GroupName,
    },
    /// Queue every account of the group
    Start {
        group: GroupName,
        #[arg(long)]
        place_id: PlaceId,
        /// Private-server code; needs engine.join_url_via = "env"
        #[arg(long)]
        private_server_code: Option<String>,
        #[arg(long)]
        mode: Option<ResourceMode>,
    },
}

#[derive(Subcommand)]
enum InstanceCmd {
    Start {
        account: AccountName,
        #[arg(long)]
        place_id: PlaceId,
        #[arg(long)]
        group: Option<GroupName>,
        #[arg(long)]
        private_server_code: Option<String>,
        #[arg(long)]
        mode: Option<ResourceMode>,
    },
    Stop {
        id: AccountName,
        #[arg(long)]
        force: bool,
    },
    /// Everything known about one instance
    Show { id: AccountName },
}

#[derive(Args)]
pub struct StatusArgs {
    /// Only these states (repeatable)
    #[arg(long = "state", value_parser = parse_state)]
    states: Vec<State>,
    /// Only instances that are queued, starting, joining, connected or unknown
    #[arg(long)]
    live: bool,
    #[arg(long)]
    group: Option<GroupName>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long = "account")]
    accounts: Vec<AccountName>,
}

fn parse_state(s: &str) -> std::result::Result<State, String> {
    State::parse(s).ok_or_else(|| {
        format!(
            "unknown state {s:?}; one of: {}",
            State::ALL.map(|s| s.as_str()).join(", ")
        )
    })
}

#[derive(Subcommand)]
enum QueueCmd {
    List,
    Cancel {
        ids: Vec<AccountName>,
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum SecretsCmd {
    Status,
    /// Stop the keyring (locks it again). Refused while clients run
    Lock,
    /// Start the keyring and unlock it with your passphrase (needed after every reboot)
    Unlock {
        /// Make a new keyring with this passphrase
        #[arg(long)]
        create: bool,
        /// Read the passphrase from this file (mode 0600) instead of asking
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    Get,
    /// Change one setting, for example: config set scheduler.max_instances 120
    Set {
        key: String,
        value: String,
    },
    /// Return a setting to the value in the configuration file
    Unset {
        key: String,
    },
}

#[derive(Subcommand)]
enum GatewayCmd {
    /// Write the gateway's WireGuard and nftables files into a directory for you to read and apply
    Plan(cmd_net::GatewayArgs),
}

#[derive(Subcommand)]
enum DaemonCmd {
    Info,
    /// Ask the daemon to exit (clients keep running unless --stop-clients)
    Stop {
        #[arg(long)]
        stop_clients: bool,
    },
}

pub struct Ctx {
    pub out: Out,
    pub socket: PathBuf,
    pub layout: Layout,
    pub timeout: Duration,
}

impl Ctx {
    pub fn client(&self) -> Result<Client> {
        Client::connect(&self.socket, "cordialctl", Some(self.timeout))
    }
}

fn main() -> ExitCode {
    // `cordialctl status | head`: a closed pipe ends the program quietly instead
    // of aborting with a panic message (Rust ignores SIGPIPE, so println! panics).
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let text = info.to_string();
        if text.contains("failed printing to std") {
            std::process::exit(0);
        }
        default_hook(info);
    }));
    let cli = Cli::parse();
    let layout = Layout::from_env();
    let ctx = Ctx {
        out: Out { json: cli.json },
        socket: cli
            .socket
            .clone()
            .unwrap_or_else(|| layout.control_socket()),
        layout,
        timeout: Duration::from_secs(cli.timeout),
    };
    match dispatch(&ctx, cli.cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            util::report_error(cli.json, &e);
            ExitCode::from(e.exit_code())
        }
    }
}

fn dispatch(ctx: &Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Init(a) => cmd_basic::init(ctx, a),
        Cmd::Doctor => cmd_basic::doctor(ctx),
        Cmd::Runtime(c) => cmd_net::runtime(ctx, c),
        Cmd::Account(c) => cmd_accounts::account(ctx, c),
        Cmd::Network(c) => cmd_net::network(ctx, c),
        Cmd::Group(c) => cmd_fleet::group(ctx, c),
        Cmd::Instance(c) => cmd_fleet::instance(ctx, c),
        Cmd::StopAll { force } => cmd_fleet::stop_all(ctx, force),
        Cmd::Status(a) => cmd_fleet::status(ctx, a),
        Cmd::Stats { per_instance } => cmd_fleet::stats(ctx, per_instance),
        Cmd::Logs { id, lines, follow } => cmd_fleet::logs(ctx, id, lines, follow),
        Cmd::Queue(c) => cmd_fleet::queue(ctx, c),
        Cmd::Secrets(c) => cmd_basic::secrets(ctx, c),
        Cmd::Config(c) => cmd_basic::config(ctx, c),
        Cmd::Gateway(GatewayCmd::Plan(a)) => cmd_net::gateway_plan(ctx, a),
        Cmd::Daemon(c) => cmd_basic::daemon(ctx, c),
        Cmd::Tui => {
            #[cfg(feature = "tui")]
            {
                tui::run(ctx)
            }
            #[cfg(not(feature = "tui"))]
            {
                Err(hrd_core::Error::unavailable(
                    "this cordialctl was built without the terminal panel (feature `tui`)",
                ))
            }
        }
    }
}
