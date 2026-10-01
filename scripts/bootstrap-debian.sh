#!/bin/bash
# Build and install Cordial HRD on the Debian 13 machine this is run on.
# Run from the root of the clone:  scripts/bootstrap-debian.sh
#
# It installs build and runtime packages with apt, installs the pinned Rust
# toolchain with rustup (for your user), builds both .deb files and installs
# them, then runs `cordialctl doctor`. It does NOT log in any account, start any
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
sudo apt-get install -y ./dist/cordial-hrd_*.deb ./dist/cordial-hrd-client_*.deb

say "check"
sudo systemctl daemon-reload
sudo systemctl enable --now cordiald.service cordial-netd.service || true
sleep 2
cordialctl doctor || true
cat <<'NEXT'

Installed. Nothing has been started and no account exists. Next (docs/install.md):
  sudo adduser "$USER" cordial        # then log out and in again
  cordialctl secrets unlock --create  # choose a passphrase of 12+ characters
  cordialctl runtime import --apk /path/to/roblox.apk
Full log: bootstrap.log
NEXT
