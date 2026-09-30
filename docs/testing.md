# What was run

**No Roblox client, account, game, engine or multi-instance session was run while
this was written** (there is no APK, account, GPU, display or systemd in the
environment). What was run is this project's own logic:

| what | how | where |
|---|---|---|
| unit tests | `cargo test --workspace`: names and paths, the protocol, configuration, the WireGuard parser (hooks refused), plans, the gateway generator, APK inspection/verification (incl. a forged pairing upstream accepts), the store, the log-signal parser, the state machine, the scheduler, process specs, the log tail, the wire (descriptor passing), statistics parsing | each crate |
| the state machine | `machine.rs` tests: a process alone is never `connected`; a teleport is not a disconnect; an unanswered notice becomes `disconnected` with its code; nothing revives a finished run; nothing restarts | `crates/cordiald` |
| end to end with a **fake client** | `scripts/e2e-fake-client.sh`: a shell script prints the log lines the real client prints; checks queue pacing, all state transitions, no restart after a disconnect, adoption after a daemon restart, stop and stop-all, keyring creation with nothing secret on disk, process ownership through a real cgroup v2 hierarchy | sandbox |
| secret store | `cargo test -p cordiald secrets -- --include-ignored`: creates a keyring with a passphrase, a wrong passphrase gets nothing, nothing on disk holds the passphrase | sandbox |
| privileged pieces on real namespaces | `cordial-netd`'s ignored root test (namespace creation, move and rename of an interface, addresses, routes, default-drop firewall, a second-interface leak blocked, a control without the rules, idempotent teardown) using a veth pair in place of `wg0`; `cordial-enter` run as root and as an unprivileged user, refusing a caller with `no_new_privs`, dropping every capability | sandbox, root |
| the terminal panel | started in a pseudo-terminal, listed an account, exited cleanly on `q` | sandbox |
| the upstream patches | compile-checked and built in release mode against the pinned upstream; the asset mapping has its own test on a real mapping | build copy |
| formatting and lints | `scripts/fmt.sh -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` | |

**Not run, and therefore unverified:** everything that needs the real engine
(that log lines match what the client prints, that sign-in can be completed
through the console, that clients join and stay connected, any memory figure of a
client); WireGuard device creation and a handshake (the sandbox kernel has no
WireGuard); the systemd units (there is no systemd here); the gateway files on a
real VPS; `cage` and lavapipe on a machine without a GPU; the `.deb` on a fresh
Debian 13; arm64.
