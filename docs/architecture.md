# Architecture

## Pieces

```
            operator (SSH)                                   browser (optional)
                 |                                                  |
        hrdctl, hrdctl tui                                 hrd-panel (HTTPS)
                 |                                                  |
                 +------------------ control socket -----------------+
                   /run/cordial-hrd/control.sock  (JSON lines, SO_PEERCRED)
                                      |
                                    hrdd   (service user "cordial", not root)
                   registry, queue, state machine, sampler, secret store supervisor
                     |            |                   |                    |
        hrd-import        netd socket        one cgroup per         private session bus
        (runs as the          /run/cordial-      client set             + gnome-keyring
         service user,        hrd/netd.sock                             (sessions, encrypted)
         files by fd)              |                   |
                             hrd-netd      hrd-enter (file capability)
                             (root, 3 caps)    enters the proxy group's namespace, drops all
                             namespaces,       privilege, execs
                             WireGuard, nft            |
                                              cage (headless)  ->  cordial-run  ->  Roblox engine
                                              one process set per account       (closed, unmodified)
```

* **`hrdd`** is the only long-running manager. It starts with no clients and
  starts one only when a command says so. It is never root.
* **`hrdctl`** and the panel are clients of the control socket. Closing either
  stops nothing.
* **`hrd-netd`** is the only part of the system that is root. It accepts
  *names* (a proxy group, a network) and derives every system change from
  configuration it stored itself. See [networking.md](networking.md).
* **`hrd-enter`** is a static program with one file capability
  (`cap_sys_admin`). It enters a proxy group's network namespace, overlays that
  proxy group's DNS files in a private mount namespace, sets `no_new_privs`, empties
  every capability set, checks that, and only then runs the client.
* **`hrd-import`** verifies and installs a Roblox Android build. The daemon
  runs it with the operator's files passed as descriptors. See
  [install.md](install.md).
* **`cordial-run`** is upstream Cordial's client (patched copy, see
  [build.md](build.md)). One process set is one account, one window, one profile.

## The model

```
group ──< proxy group ──< account
              │
              └── proxy (the code's "network", a WireGuard tunnel): at most one,
                  and a proxy serves one proxy group
```

* a **group** is a name, a Place ID, a resource mode and a note. It is
  organisation only: never a path, a namespace or a cgroup;
* a **proxy group** is a name, the group it is in, a proxy, a capacity and a note.
  Its name is unique across all groups, because it is also the name of its network
  namespace (`/run/cordial-hrd-netns/<name>`) and of the entry the helper keeps;
* an **account** is in at most one proxy group.

A start joins the place of the account's group. The resource mode is the
request's, else the account's, else the group's, else the daemon's default.
`hrdctl tree` and the panel show the three levels; the daemon returns them in
one consistent snapshot (`overview`), so nothing is listed twice or missed between
two calls.

`registry.json` holds this (schema 2). Schema 1 had one kind of group, a network
and the accounts behind it, with the place given at every start. A registry of
that shape is upgraded when the daemon loads it: each old group becomes a group of
the same name holding one proxy group of the same name, so the names the operator
knows and the namespaces the helper already built stay valid. No place is set,
because schema 1 never stored one. The old file is kept beside the new one as
`registry.json.schema1`. A registry whose relations do not hold (an account in a
proxy group that is not there) or whose schema is newer than the daemon is refused,
not guessed at. Records of runs written before the split, and account exports that
say `group`, still read.

## Trust and privilege

| component | runs as | can do | cannot do |
|---|---|---|---|
| `hrdd` | `cordial` | everything the service user can | anything as root |
| a client | `cordial`, no capabilities | its own profile, its proxy group's network | see another namespace's traffic, change its routes |
| `hrd-netd` | root, `CAP_NET_ADMIN CAP_SYS_ADMIN CAP_CHOWN`, `no_new_privs` | create/remove its own namespaces, interfaces, nft tables | run a command from the manager; take an address, path, route or command from it |
| `hrd-enter` | the caller, plus `cap_sys_admin` for the duration of its own setup | enter `/run/cordial-hrd-netns/<proxy group>` | enter any other namespace; keep a capability past its exec |

All clients share one Unix user. **Isolation between accounts is separate
directories, separate cgroups and separate network namespaces; it is not a
security boundary against a compromised client**, which could read another
account's profile directory or ask the shared secret store for another profile's
item. See [security.md](security.md).

## Directories

| what | where | owner |
|---|---|---|
| configuration | `/etc/cordial-hrd/hrdd.toml`, `netd.toml` | root |
| setting overrides | `/var/lib/cordial-hrd/config-overrides.json` | service user |
| registry (accounts, groups, proxy groups, network metadata) | `/var/lib/cordial-hrd/registry.json` | service user |
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
* Signals are matched in `crates/hrdd/src/signals.rs`. They were read from
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
the run's banner line** (the process log, then the engine log). Where the log
says no more than "started", the state written before the restart is kept and
labelled as carried over. A pending disconnect notice is not carried across a
restart, because the two logs cannot be put in time order. A set whose run had
already been decided over (failed, disconnected, stopped) but was still being
taken down is finished off. The queue is not restored.

## The daemon's threads

Main: the supervisor (twice a second: read logs, detect exits, advance stops,
admit one start). A control-socket acceptor and one thread per connection. A
sampler (stats). A periodic session-presence refresher. One mutex guards the
registry, instance runtime state and queue. Helper calls, PSS reads and imports
run with it released. **Not everything does:** while a start is admitted the
supervisor holds it across creating the cgroup, copying the asset tree and
writing state files (fsync), and a slow disk delays every control request for
that long. The private-bus address is checked with a plain `connect`, never with
`busctl`, for this reason. Instances whose process set is still being stopped
cannot be removed, moved to another proxy group or started again until it is gone.
