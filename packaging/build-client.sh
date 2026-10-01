#!/bin/sh
# Build hrd-client_<version>_<arch>.deb: the patched upstream client.
#
#   packaging/build-client.sh [OUTDIR]
#
# Builds from a patched COPY of the pinned submodule (patches/cordial/apply.sh);
# the submodule is not touched. Needs the toolchain and development packages
# listed in docs/build.md, and should be run on Debian 13 so that the library
# versions recorded in Depends: are the ones the package will meet.
#
# The package holds the client binary and upstream's licence notices. It never
# holds anything from Roblox.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist}
cd "$root"
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
arch=$(dpkg --print-architecture)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The patched copy lives outside this repository, so rustup would not find
# rust-toolchain.toml and would have no default; use the pinned version.
if command -v rustup >/dev/null 2>&1; then
    RUSTUP_TOOLCHAIN=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$root/rust-toolchain.toml")
    export RUSTUP_TOOLCHAIN
fi

patches/cordial/apply.sh "$work/src"
(
    cd "$work/src"
    export CARGO_INCREMENTAL=0
    export RUSTFLAGS="--remap-path-prefix=$work/src=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
    cargo build --release --locked -p cordial-runtime --bin cordial-run
)
pkg=$work/pkg
install -d "$pkg/usr/lib/hrd" "$pkg/usr/share/doc/hrd-client" "$pkg/DEBIAN"
install -m 0755 "$work/src/target/release/cordial-run" "$pkg/usr/lib/hrd/cordial-run"
strip --strip-unneeded "$pkg/usr/lib/hrd/cordial-run"
install -m 0644 "$root/LICENSE" "$pkg/usr/share/doc/hrd-client/copyright"
for f in NOTICE THIRD-PARTY-NOTICES.md; do
    [ -f "$work/src/$f" ] && install -m 0644 "$work/src/$f" "$pkg/usr/share/doc/hrd-client/upstream-$f"
done
install -m 0644 "$root/NOTICE.md" "$pkg/usr/share/doc/hrd-client/NOTICE.md"
install -m 0644 "$root"/patches/cordial/*.patch "$pkg/usr/share/doc/hrd-client/" 

# Depends: from the libraries the binary really links, resolved by dpkg.
mkdir -p "$work/shl/debian" && : > "$work/shl/debian/control"
depends=$(cd "$work/shl" && dpkg-shlibdeps -O -e"$pkg/usr/lib/hrd/cordial-run" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')
size=$(du -sk "$pkg" | cut -f1)
cat > "$pkg/DEBIAN/control" <<CTL
Package: hrd-client
Version: $version
Architecture: $arch
Maintainer: hrd local build <root@localhost>
Installed-Size: $size
Depends: ${depends:-libgtk-4-1, libadwaita-1-0, libvulkan1}, cage
Recommends: mesa-vulkan-drivers
Conflicts: cordial-hrd-client
Replaces: cordial-hrd-client
Section: admin
Priority: optional
Description: Cordial client (patched build) for HRD
 Upstream Cordial's cordial-run, built from a pinned commit with a small patch
 queue (join link from the environment, shared asset mapping, CPU count cap).
 It needs the Roblox Android build, which this package does not contain; import
 it with `hrdctl runtime import`.
CTL
find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$out/hrd-client_${version}_${arch}.deb"
( cd "$out" && sha256sum "hrd-client_${version}_${arch}.deb" )
