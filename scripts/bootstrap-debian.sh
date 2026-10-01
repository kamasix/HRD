#!/bin/bash
# Build and install HRD on the Debian 13 machine this is run on.
# Run from the root of the clone:  scripts/bootstrap-debian.sh
#
# It installs build and runtime packages with apt, installs the pinned Rust
# toolchain with rustup (for your user), builds both .deb files and installs
# them, then runs `hrdctl doctor`. It does NOT log in any account, start any
# client, apply any network change or open any port. Everything it prints is
# also written to bootstrap.log next to it. Needs sudo.
set -eu
set -o pipefail

cd "$(dirname "$0")/.."
LOG="$PWD/bootstrap.log"
exec > >(tee -a "$LOG") 2>&1

say() { printf '\n==> %s\n' "$*"; }

[ "$(id -u)" -ne 0 ] || { echo "run as your normal user, not root (it uses sudo where needed)"; exit 1; }
. /etc/os-release
[ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 13 ] || {
  echo "this machine is ${PRETTY_NAME:-unknown}; the package is built and checked for Debian 13 only"; exit 1; }
[ -f third_party/cordial/Cargo.toml ] || {
  say "fetching the pinned upstream Cordial and its submodules"
  git submodule update --init --recursive
}

if dpkg -s cordial-hrd >/dev/null 2>&1; then
  cat <<'WARN'

The package that was called cordial-hrd is installed. It is replaced by hrd (the
same program under its new name). Your accounts, sessions and settings stay where
they are: the directories under /etc, /var/lib and /run keep the name cordial-hrd
on purpose, because the client files every saved sign-in under the full path of
the profile directory.

Clients that are running now are NOT carried over to the new daemon. Stop them
first:   cordialctl stop-all
WARN
  if [ -t 0 ]; then
    read -r -p "Continue? [y/N] " ans
    [ "$ans" = y ] || [ "$ans" = Y ] || { echo "stopped; nothing was changed"; exit 1; }
  fi
fi

say "1/5 packages"
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential clang cmake pkg-config git curl ca-certificates dpkg-dev musl-tools \
  libgtk-4-dev libadwaita-1-dev \
  wireguard-tools nftables iproute2 gnome-keyring libcap2-bin dbus-daemon \
  cage mesa-vulkan-drivers libgl1-mesa-dri

say "2/5 Rust toolchain (pinned by rust-toolchain.toml)"
if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/rustup" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
fi
. "$HOME/.cargo/env"
rustup show active-toolchain >/dev/null 2>&1 || rustup toolchain install --profile minimal
cargo --version

say "3/5 building the manager package"
packaging/build-deb.sh "$PWD/dist"

say "4/5 building the client package (long: compiles upstream Cordial)"
packaging/build-client.sh "$PWD/dist"

say "5/5 installing"
sudo apt-get install -y ./dist/hrd_*.deb ./dist/hrd-client_*.deb

say "check"
sudo systemctl daemon-reload
sudo systemctl enable --now hrdd.service hrd-netd.service || true
sleep 2
hrdctl doctor || true
cat <<'NEXT'

Installed. Nothing has been started and no account exists. Next (docs/install.md):
  sudo adduser "$USER" cordial        # then log out and in again
  hrdctl secrets unlock --create  # choose a passphrase of 12+ characters
  hrdctl runtime import --apk /path/to/roblox.apk
Full log: bootstrap.log
NEXT
