# Installing on Debian

Target: **Debian 13 (trixie), amd64**, used over SSH, no desktop. Debian 12 and
arm64 build but are not the tested target.

## Names on disk

The programs and services are called `hrdd`, `hrdctl`, `hrd-panel`, `hrd-netd`,
`hrd-enter`, `hrd-import`. The directories and the service user keep the names
they had before the project was called HRD: `/etc/cordial-hrd`,
`/var/lib/cordial-hrd`, `/var/lib/cordial-hrd-netd`, `/var/log/cordial-hrd`,
`/run/cordial-hrd`, `/run/cordial-hrd-netns`, user and group `cordial`. This is
deliberate. The client files every saved sign-in under the **full path of the
profile directory** (`/var/lib/cordial-hrd/acct/<account>/...`), so renaming that
directory would sign every account out, and each would have to be signed in again
by hand.

### Upgrading from the package called `cordial-hrd`

`hrd` replaces `cordial-hrd` and `hrd-client` replaces `cordial-hrd-client`
(`apt` removes the old packages when the new ones are installed). Accounts,
sessions, networks and settings stay where they are. What changes:

* the commands and units: `cordialctl` → `hrdctl`, `cordiald` → `hrdd`,
  `cordial-netd` → `hrd-netd`, `cordial-panel` → `hrd-panel`; enable the new units
  (`sudo systemctl enable --now hrd-netd hrdd`, and `hrd-panel` if you use it);
* `/etc/cordial-hrd/cordiald.toml` keeps working under its old name until you
  rename it to `hrdd.toml`; program paths that an older `init` wrote into it are
  read as the new defaults;
* running clients are **not** carried over to the new daemon: stop them first
  (`cordialctl stop-all`);
* the old package's removal tears down the applied network namespaces; run
  `hrdctl network apply` again.

## 1. Packages

The manager package and the client package are separate because the client needs
the GTK stack and is built from a different source tree ([build.md](build.md)).

```
sudo apt install ./hrd_<version>_amd64.deb ./hrd-client_<version>_amd64.deb
sudo apt install cage mesa-vulkan-drivers        # the nested compositor; CPU Vulkan for servers without a GPU
```

`hrd` depends on systemd, iproute2, nftables, wireguard-tools, dbus-daemon,
gnome-keyring, libcap2-bin. **Installing starts nothing**: no service, no client,
no network change; the post-install message lists the next steps. No Fedora
package names are used.

The client needs: `libgtk-4-1` (4.12 or newer), `libadwaita-1-0` (1.5 or newer),
`libvulkan1`, `libcurl3t64-gnutls`/`libcurl3-gnutls`, `libwayland-client0`,
`libwayland-egl1`, `libxkbcommon0`, `libcairo2`, `libpango-1.0-0` and what they
pull in; the client package computes exact dependencies with `dpkg-shlibdeps`.

## 2. First start

```
sudo hrdctl init                                  # config skeleton, checks, nothing started
sudo systemctl enable --now hrd-netd hrdd
sudo adduser "$USER" cordial                          # to use hrdctl without sudo (log in again)
hrdctl doctor                                     # read every FAIL
hrdctl secrets unlock --create                    # new passphrase, 12+ characters
```

Edit `/etc/cordial-hrd/hrdd.toml` (annotated example in
`/usr/share/doc/hrd/hrdd.toml.example`); `hrdd --check-config`
validates it. Settings can also be changed at run time with `hrdctl config set`.

After every **reboot** the keyring is locked: `hrdctl secrets unlock`. Clients
cannot start until you do.

## 3. The Roblox build

The easy way, on the server itself:

```
hrdctl runtime fetch --list      # versions the mirror has for x86-64
hrdctl runtime fetch             # newest; or --version NAME
hrdctl runtime list
```

Keep it current: `hrdctl config set runtime.auto_update true` (or the toggle in the
panel's Ustawienia > Roblox). Every `runtime.check_interval_h` hours (default 6) the
daemon asks the mirror for the newest x86-64 build and, if it is newer than the
newest installed one, downloads, verifies and installs it and selects it for
clients started afterwards; running clients are never touched. `hrdctl runtime
update [--now]` shows the state or checks at once. It is off by default because it
makes the daemon send network requests. If a new build misbehaves,
`hrdctl runtime use OLDER_VERSION` goes back.

This runs upstream Cordial's own downloader (mirror: APKPure, x86-64 only), checks
every file against Roblox's pinned signing certificate, then installs it with the
same checks as `import`. Nothing is installed unless all of it passes. The
download runs as you, not as the daemon, into a private temporary directory that
is removed afterwards. It needs the server to reach the Internet; **unverified
here**: the sandbox this was written in cannot reach the mirror.

Or get the Android build yourself (base APK, and
for a split build the engine split for your CPU):

```
hrdctl runtime import --apk ~/roblox/      # a directory of APKs, or several --apk PATH
hrdctl runtime list
```

The importer stages private copies, checks every archive is one consistent build
(package name, version code, split relations), verifies the signature against the
certificate pinned in upstream Cordial and that the certificate contains the key
that signed, extracts the engine library and the assets with no path traversal or
symlinks, publishes by one atomic rename into a sealed read-only store, writes the
version and provenance, and checks that the result passes the check `cordial-run`
itself will make. Nothing is published unless all of it passes. `runtime use
VERSION` selects another installed build (running clients keep theirs). The APK is
read once, installed once, and used by every client as unchanging files.

## 4. Groups, proxies, accounts, go

A **group** is a game (its Place ID), it holds **proxy groups**, and each proxy
group is one **proxy** (a WireGuard tunnel) with the **accounts** behind it:

```
hrdctl group create adopt-me --place-id 1234567890
sudo hrdctl proxy add de-1 --wireguard-config de-1.conf --exit-ip 203.0.113.11
hrdctl proxy-group create de-1 --group adopt-me --proxy de-1 --capacity 20
hrdctl proxy-group assign de-1 --accounts alt.txt --create-missing    # one name per line
hrdctl proxy plan && hrdctl proxy apply
hrdctl account login alt-01                      # you type the password, per account
hrdctl group start adopt-me
hrdctl tree ; hrdctl status ; hrdctl stats ; hrdctl tui
```

All of it can be done in the web panel instead ([panel.md](panel.md)); defining the
proxy from the panel needs `allow_service_define = true` in
`/etc/cordial-hrd/netd.toml`, otherwise `sudo hrdctl proxy add` as above.

Place ids, account names and addresses are yours; none is built in. See
[operations.md](operations.md) for running it day to day.

### Upgrading from the single-level groups

A registry written before groups were split (a group was a network with its
accounts, and the place was typed at every start) is upgraded the first time the new
daemon starts: each old group becomes a group of the same name with one proxy group
of the same name, in which its accounts and its network stay. No place is set, so
type one into each group (panel, or `hrdctl group set NAME --place-id N`) before
starting it. The old file is kept as `/var/lib/cordial-hrd/registry.json.schema1`;
keep it if you may go back to the older daemon, which cannot read the new one.
Merge groups afterwards by moving proxy groups (`hrdctl proxy-group set NAME --group
OTHER`, or the proxy group's settings in the panel).

## Updating

Install the new `.deb`. The daemon is not restarted by the upgrade's file copy;
`sudo systemctl restart hrdd` does it, and **running clients keep running**
(the service is `KillMode=process`; the new daemon adopts them and re-derives
their state from their logs). Protocol mismatches between `hrdctl` and
`hrdd` are reported, not guessed around.

## Removing

```
hrdctl stop-all
sudo apt remove hrd          # keeps /var/lib/cordial-hrd (accounts, keyring) and /etc/cordial-hrd
sudo apt purge hrd           # deletes them, including stored sessions and WireGuard keys
```

Removal releases this project's network namespaces (and with them the tunnels and
firewall tables inside) and touches nothing else. To undo the gateway, follow the
`README-gateway.txt` that `gateway plan` wrote.

## Example: a 4-core, 16 GB machine with an Intel iGPU (i5-6400T)

Not measured; a starting point. Put it in `/etc/cordial-hrd/hrdd.toml` and
raise the numbers only after watching `hrdctl stats`:

```toml
[scheduler]
max_instances = 6           # RAM, not the manager, is the limit: ~1 GB per engine
max_concurrent_starts = 1   # starts are the expensive moment
min_available_mem_mib = 2048

[engine]
graphics = "auto"           # uses /dev/dri/renderD128 (the cordial user is in `render`); falls back to the CPU
software_threads = 1        # only matters if it falls back to lavapipe
cpus_per_instance = 1
```

`scripts/bootstrap-debian.sh` automates building and installing on Debian 13.

## Troubleshooting: `hrdd` fails to restart ("Device or resource busy")

Seen in `journalctl -u hrdd` as `Failed to spawn 'start' task: Device or
resource busy`. Cause: the service cgroup had delegated controllers enabled for
the clients and, after a restart that left the keyring/bus running
(`KillMode=process`), systemd tried to put the new daemon into that same cgroup.
Fixed by `DelegateSubgroup=manager` in the unit (package 0.1.0 built after this
note; needs systemd 254, Debian 13 has 257). On a machine stuck in the old state,
install the fixed package, then `sudo systemctl stop hrdd`,
`sudo pkill -u cordial -f 'gnome-keyring-daemon|dbus-daemon'`,
`sudo systemctl daemon-reload && sudo systemctl start hrdd`, and
`hrdctl secrets unlock` (killing the keyring locks it).
