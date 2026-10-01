# What was run

**No Roblox client, account, game, engine or multi-instance session was run while
this was written** (there is no APK, account, GPU, display or systemd in the
environment). What was run is this project's own logic:

| what | how | where |
|---|---|---|
| unit tests | `cargo test --workspace`: names and paths, the protocol, configuration, the WireGuard parser (hooks refused), plans, the gateway generator, APK inspection/verification (incl. a forged pairing upstream accepts), the store, the log-signal parser, the state machine, the scheduler, process specs, the log tail, the wire (descriptor passing), statistics parsing | each crate |
| the state machine | `machine.rs` tests: a process alone is never `connected`; a teleport is not a disconnect; an unanswered notice becomes `disconnected` with its code; nothing revives a finished run; nothing restarts | `crates/hrdd` |
| end to end with a **fake client** | `scripts/e2e-fake-client.sh`: a shell script prints the log lines the real client prints; checks queue pacing, all state transitions, no restart after a disconnect, adoption after a daemon restart, stop and stop-all, keyring creation with nothing secret on disk, process ownership through a real cgroup v2 hierarchy | sandbox |
| secret store | `cargo test -p hrdd secrets -- --include-ignored`: creates a keyring with a passphrase, a wrong passphrase gets nothing, nothing on disk holds the passphrase | sandbox |
| privileged pieces on real namespaces | `hrd-netd`'s ignored root test (namespace creation, move and rename of an interface, addresses, routes, default-drop firewall, a second-interface leak blocked, a control without the rules, idempotent teardown) using a veth pair in place of `wg0`; `hrd-enter` run as root and as an unprivileged user, refusing a caller with `no_new_privs`, dropping every capability | sandbox, root |
| the terminal panel | started in a pseudo-terminal, listed an account, exited cleanly on `q` (before the group split; only its columns changed since) | sandbox |
| the groups model | unit tests: the three levels in one snapshot, capacity and names across groups, an assignment that is refused changes nothing, a running account is not moved or removed, a failed write leaves the registry as it was, upgrading a schema 1 registry (and not twice, and refusing a newer or inconsistent one), place and mode resolution, group and proxy-group start/stop | `crates/hrd-core`, `crates/hrdd` |
| the helper's socket and the rule for defining a proxy | `scripts/netd-socket-check.sh`: starts the real `hrd-netd` as root with empty stand-ins for `ip`, `wg` and `nft` (visible only in a private mount namespace), connects as the service user and as root: the socket is `0660 root:<service group>`, the service user may ping and is refused `put_network`, root is not; a service group that does not exist stops the helper with a message | sandbox, root |
| the web page | `node scripts/panel-smoke.mjs URL TOKEN` (needs `playwright-core`): signs in, creates a group, a proxy group and accounts, moves and removes them, opens the menus and settings, fails on any console error. Run in headless Chromium against a real `hrdd` and `hrd-panel`; the network helper was a stand-in, because `ip`, `wg` and `nft` are missing in the sandbox | sandbox |
| the upstream patches | compile-checked and built in release mode against the pinned upstream; the asset mapping has its own test on a real mapping | build copy |
| formatting and lints | `scripts/fmt.sh -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` | |

**Not run, and therefore unverified:** everything that needs the real engine
(that log lines match what the client prints, that sign-in can be completed
through the console, that clients join and stay connected, any memory figure of a
client); WireGuard device creation and a handshake (the sandbox kernel has no
WireGuard); the systemd units (there is no systemd here); the gateway files on a
real VPS; `cage` and lavapipe on a machine without a GPU; the `.deb` on a fresh
Debian 13; arm64.
