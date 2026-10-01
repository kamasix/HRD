# Installing on Debian

Target: **Debian 13 (trixie), amd64**, used over SSH, no desktop. Debian 12 and
arm64 build but are not the tested target.

## 1. Packages

The manager package and the client package are separate because the client needs
the GTK stack and is built from a different source tree ([build.md](build.md)).

```
sudo apt install ./cordial-hrd_<version>_amd64.deb ./cordial-hrd-client_<version>_amd64.deb
sudo apt install cage mesa-vulkan-drivers        # the nested compositor; CPU Vulkan for servers without a GPU
```

`cordial-hrd` depends on systemd, iproute2, nftables, wireguard-tools, dbus-daemon,
gnome-keyring, libcap2-bin. **Installing starts nothing**: no service, no client,
no network change; the post-install message lists the next steps. No Fedora
package names are used.

The client needs: `libgtk-4-1` (4.12 or newer), `libadwaita-1-0` (1.5 or newer),
`libvulkan1`, `libcurl3t64-gnutls`/`libcurl3-gnutls`, `libwayland-client0`,
`libwayland-egl1`, `libxkbcommon0`, `libcairo2`, `libpango-1.0-0` and what they
pull in; the client package computes exact dependencies with `dpkg-shlibdeps`.

## 2. First start

```
sudo cordialctl init                                  # config skeleton, checks, nothing started
sudo systemctl enable --now cordial-netd cordiald
sudo adduser "$USER" cordial                          # to use cordialctl without sudo (log in again)
cordialctl doctor                                     # read every FAIL
cordialctl secrets unlock --create                    # new passphrase, 12+ characters
```

Edit `/etc/cordial-hrd/cordiald.toml` (annotated example in
`/usr/share/doc/cordial-hrd/cordiald.toml.example`); `cordiald --check-config`
validates it. Settings can also be changed at run time with `cordialctl config set`.

After every **reboot** the keyring is locked: `cordialctl secrets unlock`. Clients
cannot start until you do.

## 3. The Roblox build

The easy way, on the server itself:

```
cordialctl runtime fetch --list      # versions the mirror has for x86-64
cordialctl runtime fetch             # newest; or --version NAME
cordialctl runtime list
```

Keep it current: `cordialctl config set runtime.auto_update true` (or the toggle in the
panel's Ustawienia > Roblox). Every `runtime.check_interval_h` hours (default 6) the
daemon asks the mirror for the newest x86-64 build and, if it is newer than the
newest installed one, downloads, verifies and installs it and selects it for
clients started afterwards; running clients are never touched. `cordialctl runtime
update [--now]` shows the state or checks at once. It is off by default because it
makes the daemon send network requests. If a new build misbehaves,
`cordialctl runtime use OLDER_VERSION` goes back.

This runs upstream Cordial's own downloader (mirror: APKPure, x86-64 only), checks
every file against Roblox's pinned signing certificate, then installs it with the
same checks as `import`. Nothing is installed unless all of it passes. The
download runs as you, not as the daemon, into a private temporary directory that
is removed afterwards. It needs the server to reach the Internet; **unverified
here**: the sandbox this was written in cannot reach the mirror.

Or get the Android build yourself (base APK, and
for a split build the engine split for your CPU):

```
cordialctl runtime import --apk ~/roblox/      # a directory of APKs, or several --apk PATH
cordialctl runtime list
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

## 4. Accounts, network, go

```
cordialctl account add alt-01 ; cordialctl account login alt-01
sudo cordialctl network add de-1 --wireguard-config de-1.conf --exit-ip 203.0.113.11
cordialctl group create g01 --network de-1 --capacity 20
cordialctl group assign g01 --accounts g01.txt
cordialctl network plan && cordialctl network apply
cordialctl group start g01 --place-id 1234567890
cordialctl status ; cordialctl stats ; cordialctl tui
```

Place ids, account names and addresses are yours; none is built in. See
[operations.md](operations.md) for running it day to day.

## Updating

Install the new `.deb`. The daemon is not restarted by the upgrade's file copy;
`sudo systemctl restart cordiald` does it, and **running clients keep running**
(the service is `KillMode=process`; the new daemon adopts them and re-derives
their state from their logs). Protocol mismatches between `cordialctl` and
`cordiald` are reported, not guessed around.

## Removing

```
cordialctl stop-all
sudo apt remove cordial-hrd          # keeps /var/lib/cordial-hrd (accounts, keyring) and /etc/cordial-hrd
sudo apt purge cordial-hrd           # deletes them, including stored sessions and WireGuard keys
```

Removal releases this project's network namespaces (and with them the tunnels and
firewall tables inside) and touches nothing else. To undo the gateway, follow the
`README-gateway.txt` that `gateway plan` wrote.

## Example: a 4-core, 16 GB machine with an Intel iGPU (i5-6400T)

Not measured; a starting point. Put it in `/etc/cordial-hrd/cordiald.toml` and
raise the numbers only after watching `cordialctl stats`:

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

## Troubleshooting: `cordiald` fails to restart ("Device or resource busy")

Seen in `journalctl -u cordiald` as `Failed to spawn 'start' task: Device or
resource busy`. Cause: the service cgroup had delegated controllers enabled for
the clients and, after a restart that left the keyring/bus running
(`KillMode=process`), systemd tried to put the new daemon into that same cgroup.
Fixed by `DelegateSubgroup=manager` in the unit (package 0.1.0 built after this
note; needs systemd 254, Debian 13 has 257). On a machine stuck in the old state,
install the fixed package, then `sudo systemctl stop cordiald`,
`sudo pkill -u cordial -f 'gnome-keyring-daemon|dbus-daemon'`,
`sudo systemctl daemon-reload && sudo systemctl start cordiald`, and
`cordialctl secrets unlock` (killing the keyring locks it).
