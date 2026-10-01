# Security model

## What is protected, and from whom

| asset | where it lives | protected from |
|---|---|---|
| Roblox sessions (cookies, identity) | encrypted keyring under `/var/lib/cordial-hrd/secrets`, passphrase typed by you, never on disk | other Unix users, backups of the disk, `git`, logs |
| WireGuard private keys | `/var/lib/cordial-hrd-netd/` (root, `0700`/`0600`) | the service user and every client |
| the registry, records, configuration | no secrets by construction (a test checks the model has no key-shaped field) | - |
| the keyring passphrase | your head; in memory only for the duration of the unlock call | everything |

Directories that hold private data are `0700`, files `0600`. Secrets are never in
arguments (the join link with a private-server code moves to the environment with
the patched client; without it a code is refused), never in logs (log lines shown
by `logs` and the panel pass through a scrubber for cookie, key and token shapes),
never in the repository, packages or CI artifacts.

## What is **not** protected

* **Between accounts.** All clients run as the same Unix user. Separate
  directories, cgroups and namespaces stop honest mix-ups; they do not stop a
  compromised client from reading another account's profile directory or asking
  the shared keyring for another profile's item. One user per account would be
  needed for that and is not offered. Do not describe this as isolation against a
  hostile client.
* **From root, and from anyone who can become the service user.**
* The closed engine is unmodified and trusted no more than any downloaded binary:
  it runs as an unprivileged user with no capabilities, in a namespace that has
  only the tunnel.

## Privilege

* `hrdd` and every client: the `cordial` user, never root. The daemon refuses
  to start as root (`--allow-root` exists for tests).
* `hrd-netd`: root with three capabilities (one of them `CAP_SYS_ADMIN`,
  which is close to root: treat a compromise of this process as a compromise of
  the host) and `no_new_privs`. It takes no commands and no paths. It does take
  a **WireGuard configuration** (its endpoint and keys) - but only from root unless
  you change that: `PutNetwork` is refused for every other caller, so neither the
  manager nor the panel can change where a proxy group's traffic goes
  (`sudo hrdctl proxy add`). **`allow_service_define = true` in the root-owned
  `/etc/cordial-hrd/netd.toml` hands that decision to the service user**, and so to
  the panel: anyone who can sign in to it (and any process of the service user,
  including a compromised client) can then define a proxy, which routes every
  account behind it through an endpoint they chose and gives them that tunnel's
  traffic. It is off by default; turn it on only for a panel you would trust with
  the SSH key to the machine. Planning, applying and removing proxy groups is open
  to the service user either way, and works only on proxies that were defined. Its
  socket is in the root-owned
  `/run/cordial-hrd-netns/` (created `0600` and opened through the descriptor),
  and every client of it checks that the peer is root before sending anything.
  It locates `ip`, `wg`, `nft` in system directories, requires them root-owned,
  and runs them without a shell, with a cleared environment. Private keys are
  stored root-only; **the service user cannot read them**, but it can cause them
  to be used (apply a proxy group).
* `hrd-enter`: one file capability, `cap_sys_admin`, executable by root and
  the service group only. It takes a proxy group *name*, validates it as a slug, opens
  only a file under `/run/cordial-hrd-netns` (a constant: an option that chose the
  directory would let the caller choose the namespace) that must be an `nsfs` file
  owned by root in a root-owned directory not writable by others, and follows no
  symlink. After `setns`, `unshare`, the DNS overlay mounts, it sets
  `no_new_privs`, clears the ambient set, empties the capability sets and reads
  them back; only then does it `exec`. Tested as root and as an unprivileged user,
  including that it refuses a caller that has `no_new_privs` set (the capability is
  then not granted). **Limits:** any process of the service user - including a
  compromised client started *without* a proxy group, or any client that can exec
  it directly - can run `hrd-enter` for *any* proxy group, because the wrapper does
  not check the caller against the proxy group's assignment. Clients started
  through it have `no_new_privs` and cannot re-enter a different namespace, but the
  boundary between proxy groups is not enforced against a hostile same-user
  process. Do not use proxy groups as a security boundary between accounts you do
  not trust equally.
  The unit does **not** set `NoNewPrivileges` for this reason and instead bounds
  the capability set to `CAP_SYS_ADMIN`.
* Settings that widen access (`service.*`, `control.*`, `secrets.*`, the program
  paths, `engine.env`, `network.allow_unrouted`, `login.console`) can only be set
  in the root-owned `/etc/cordial-hrd/hrdd.toml`. `config set` and the panel
  refuse them, and the same keys in the user-writable overrides file are ignored
  (with a log line). A corrupt overrides file is set aside as `.rejected`; the
  daemon still starts.
* The control socket: `0660`, group `cordial`; every connection is also checked
  with `SO_PEERCRED` (root, the daemon's user, configured uids, or a member of the
  socket's group). Whoever passes can do anything the manager can do.

## Inputs treated as hostile

APKs (signature verified against the certificate pinned in upstream Cordial **and
checked to contain the key that signed**, which upstream does not check - BASELINE
item 8, with a test that reproduces the gap; staged private copies, content
classification, path traversal and symlink refusal, atomic publication, sealed
read-only store), WireGuard files (whitelist parser; commands refused), account,
group, proxy group and proxy names (validated types at deserialisation), engine log lines
(substring-matched, length-capped, never executed), paths (derived, never taken
from requests), join links and private-server codes (charset-checked).

## What is deliberately not implemented

Injectors or script execution in Roblox; synthetic input, clicks or anti-AFK for
playing clients; bypassing protections, CAPTCHA, bans or limits; account
creation; IP rotation; automatic reconnect, restart or refilling after a kick or
disconnect (the state machine has no edge that does it, and a test checks that a
disconnected instance stays disconnected). The sign-in console is the one place
that relays input to a client: one action per line the operator types, only into
a sign-in client, switchable off.

## Reporting

Nothing here has been security-reviewed by anyone else. [status.md](status.md)
says what was run. Report problems privately to the repository owner.
