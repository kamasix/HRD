# Architecture

## Pieces

```
            operator (SSH)                                   browser (optional)
                 |                                                  |
   cordialctl ---+--- cordialctl tui                        cordial-panel (HTTPS)
                 |                                                  |
                 +------------------ control socket -----------------+
                   /run/cordial-hrd/control.sock  (JSON lines, SO_PEERCRED)
                                      |
                                  cordiald   (service user "cordial", not root)
                   registry, queue, state machine, sampler, secret store supervisor
                     |            |                   |                    |
        cordial-import        netd socket        one cgroup per         private session bus
        (runs as the          /run/cordial-      client set             + gnome-keyring
         service user,        hrd/netd.sock                             (sessions, encrypted)
         files by fd)              |                   |
                             cordial-netd      cordial-enter (file capability)
                             (root, 3 caps)    enters the group's namespace, drops all
                             namespaces,       privilege, execs
                             WireGuard, nft            |
                                              cage (headless)  ->  cordial-run  ->  Roblox engine
                                              one process set per account       (closed, unmodified)
```

* **`cordiald`** is the only long-running manager. It starts with no clients and
  starts one only when a command says so. It is never root.
* **`cordialctl`** and the panel are clients of the control socket. Closing either
  stops nothing.
* **`cordial-netd`** is the only part of the system that is root. It accepts
  *names* (a group, a network) and derives every system change from
  configuration it stored itself. See [networking.md](networking.md).
* **`cordial-enter`** is a static program with one file capability
  (`cap_sys_admin`). It enters a group's network namespace, overlays that group's
  DNS files in a private mount namespace, sets `no_new_privs`, empties every
  capability set, checks that, and only then runs the client.
* **`cordial-import`** verifies and installs a Roblox Android build. The daemon
  runs it with the operator's files passed as descriptors. See
  [install.md](install.md).
* **`cordial-run`** is upstream Cordial's client (patched copy, see
  [build.md](build.md)). One process set is one account, one window, one profile.

## Trust and privilege

| component | runs as | can do | cannot do |
|---|---|---|---|
| `cordiald` | `cordial` | everything the service user can | anything as root |
| a client | `cordial`, no capabilities | its own profile, its group's network | see another namespace's traffic, change its routes |
| `cordial-netd` | root, `CAP_NET_ADMIN CAP_SYS_ADMIN CAP_CHOWN`, `no_new_privs` | create/remove its own namespaces, interfaces, nft tables | run a command from the manager; take an address, path, route or command from it |
| `cordial-enter` | the caller, plus `cap_sys_admin` for the duration of its own setup | enter `/run/cordial-hrd-netns/<group>` | enter any other namespace; keep a capability past its exec |

All clients share one Unix user. **Isolation between accounts is separate
directories, separate cgroups and separate network namespaces; it is not a
security boundary against a compromised client**, which could read another
account's profile directory or ask the shared secret store for another profile's
item. See [security.md](security.md).

## Directories

| what | where | owner |
|---|---|---|
| configuration | `/etc/cordial-hrd/cordiald.toml`, `netd.toml` | root |
| setting overrides | `/var/lib/cordial-hrd/config-overrides.json` | service user |
| registry (accounts, groups, network metadata) | `/var/lib/cordial-hrd/registry.json` | service user |
| per-instance last-run records | `/var/lib/cordial-hrd/instances/<account>.json` | service user |
| per-account private tree (`0700`): profile, engine data, cache, `HOME` | `/var/lib/cordial-hrd/acct/<account>/` | service user |
| runtime store (one installed build, shared, sealed read-only) | `/var/lib/cordial-hrd/runtime/builds/<version>/` | service user |
| secret store (encrypted keyring) | `/var/lib/cordial-hrd/secrets/` | service user |
| logs | `/var/log/cordial-hrd/<account>.log` | service user |
| sockets, per-instance runtime dirs | `/run/cordial-hrd/` | service user |
| network namespaces and generated DNS files | `/run/cordial-hrd-netns/` | root |
| WireGuard private keys, applied-state manifest | `/var/lib/cordial-hrd-netd/` | root |

## The life of an instance

States: `configured`, `auth_required`, `queued`, `starting`, `joining`,
`connected`, `disconnected`, `stopped`, `failed`, `unknown`.

```
configured/stopped/failed/disconnected/auth_required
      | instance start (operator)
      v
   queued --(cancel)--> stopped
      | admitted: concurrency, free memory after reserving in-flight starts,
      |           memory and CPU pressure
      v
  starting --- "[roblox] app ready: Landing" ---> auth_required   (process set released)
      | "[roblox] app ready: Home|RootSwitchNavigator", or the launch line
      v
   joining ----- timeout ---> failed                                (process set released)
      | "[cordial] game: joined place N"   <- the only way to `connected`
      v
  connected --- "Disconnection Notification. Reason: N" arms a grace timer;
      |         a new join cancels it (a teleport); otherwise:
      +-------> disconnected  (reason code recorded, process set released)
      +-- "game: left", or the process ends after being connected --> disconnected
```

* `unknown` is what a live process is when nothing it said settles the question,
  for example after the log no longer shows the run.
* **Nothing restarts.** No transition leads back to `queued`; only `instance
  start` does. A disconnect, a failure and an auth problem all release the
  process set and wait for the operator.
* Signals are matched in `crates/cordiald/src/signals.rs`. They were read from
  upstream's source; none has been observed against a running client in this
  project ([status.md](status.md)).

## Owning a process set

If the service has a delegated cgroup subtree (`Delegate=yes`, the packaged
unit), each client gets `instances/<account>`: the child joins it in `pre_exec`,
before it can fork, so every descendant is inside, whatever it re-executes or
orphans. Ending a set is `cgroup.kill` (or a repeated kill loop on kernels
before 5.14) and waiting for `populated 0`. Without a delegated subtree the
fallback is the process group, which a program can leave; `doctor` says which
mode is in effect. A pid is never trusted alone: records carry the process start
time, and a pid whose start time differs is left alone.

After a daemon restart the records are read, live sets are found again (cgroup,
or pid plus start time) and **their state is re-derived by replaying the log from
the run's banner line**, not taken from what was last written. The queue is not
restored.

## The daemon's threads

Main: the supervisor (twice a second: read logs, detect exits, advance stops,
admit one start). A control-socket acceptor and one thread per connection. A
sampler (stats). A periodic session-presence refresher. One mutex guards the
registry, instance runtime state and queue; slow operations (helper calls, PSS
reads, imports) run with it released.
