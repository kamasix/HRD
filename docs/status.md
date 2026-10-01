# Status

Labels: **implemented** (written, used by the code paths around it, tested at
least by unit tests); **compiled** (builds, not run for lack of the environment);
**unverified at runtime** (depends on something this project could not run: the
real engine, a WireGuard-capable kernel, systemd, a fresh Debian 13); **blocked**
(by a named dependency); **not implemented**.

No Roblox client, account, game or multi-instance session was run. "Tested" below
means this project's own logic, see [testing.md](testing.md). A build is not
evidence that a session works.

| area | status | notes |
|---|---|---|
| Baseline of upstream | implemented | [BASELINE.md](../BASELINE.md): pinned commit, what works, what is only described, limits found |
| Runtime import (`runtime import/list/use/remove`) | implemented, tested on synthetic APKs | staged copies, signature check **plus** the key/certificate binding upstream lacks (reproduced by a test), classification and consistency checks, traversal/symlink refusal, atomic publish, sealed store, provenance. Not run on a real Roblox build |
| Daemon: registry, queue, admission, stop, adoption | implemented, tested (unit + fake client) | |
| State machine and log signals | implemented, unit-tested | signal patterns read from upstream source; **unverified against a running client** |
| `connected` only from a runtime signal | implemented | the `game: joined place` line; no other path |
| No automatic restart/rejoin/refill | implemented, tested | no edge leads back to `queued` |
| Process ownership by cgroup v2, pgid fallback | implemented; cgroup path exercised in the sandbox | `memory`/`cpu`/`pids` limits need delegated controllers (unverified here) |
| Secrets: private bus + headless keyring | implemented; create/lock/unlock/wrong-passphrase exercised in the sandbox | plaintext fallback refused; same-user limits stated in [security.md](security.md) |
| Sign-in console | implemented, unit-tested with a fake control surface | **unverified**: completing a real sign-in this way |
| Network groups: namespace + fail-closed firewall + DNS overlay | implemented; exercised on real namespaces with a veth stand-in | |
| WireGuard device creation, handshake | compiled; **unverified** | sandbox kernel has no WireGuard |
| `cordial-enter` | implemented; run as root and unprivileged | |
| Observed exit (STUN from inside the namespace) | implemented, parsing unit-tested | **unverified** on a real tunnel |
| Gateway plan (files only) | implemented, unit-tested | never applied anywhere |
| Stats (RSS/PSS/USS/swap/CPU/cgroup/disk/traffic) | implemented; parsing tested; sampled in the sandbox | values for a real client unknown |
| CLI | implemented | all requested commands; `--json`, exit codes, filters |
| Terminal panel | implemented; started in a pty | |
| Web panel | implemented; exercised over TLS with curl and in headless Chromium | not reviewed by a third party |
| Upstream patches | implemented; compile-checked, built, asset patch tested | **unverified** in a running client |
| Resource modes | implemented as environment lists, tested | effect on memory **unmeasured** |
| Headless (`cage`), software drawing | configured | **unverified** on a machine without a GPU; `cordial-run` always links GTK |
| True no-render mode | **not implemented** | does not exist in upstream's open code |
| Shared compositor for several clients | **not implemented** | `cage` is single-client; see [headless.md](headless.md) |
| ~1 MB per session | **not claimed** | [memory.md](memory.md) |
| 300 live clients | **not claimed** | 300 is the manager's target; no such run exists |
| Memory per client | **not measured** | only the manager's own: 3.7-4.7 MiB RSS |
| Debian package | implemented; built; two clean builds byte-identical | not installed on a real Debian 13; client package script written, not run |
| systemd units | written | **unverified** (no systemd here) |
| arm64 | builds for the manager in principle | unverified; upstream lists aarch64 as untested |
| SOCKS5 UDP ASSOCIATE backend | not implemented | TCP-only proxies are not a backend |
| Automatic IP rotation, reconnect, anti-AFK, injector, account creation | not implemented, deliberately | [security.md](security.md) |

## Known open issues from the code reviews

Two independent reviews (security, correctness) were run and their findings
fixed where stated in the commit log. These were **understood and not fixed**:

* Some work still happens with the daemon's lock held (asset-tree copy, cgroup
  creation, `fsync` of state files); a slow disk delays control requests.
* With the process-group fallback (no cgroup delegation) ownership is weaker: a
  client that calls `setsid` leaves the group and is not found. Orphans left in
  the group by a dead leader are tracked. Use the packaged unit (`Delegate=yes`).
* A sign-in run is stopped at the first signed-in screen; whether the client has
  finished writing its session by then is unverified.
* `cordial-enter` does not check the caller against the group assignment (see
  security.md).
* Everything that depends on the real engine's log lines, WireGuard, systemd and
  a Debian 13 install is unverified at runtime.
