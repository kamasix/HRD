#!/bin/sh
# Build hrd_<version>_<arch>.deb, the manager package, from this tree.
#
#   packaging/build-deb.sh [OUTDIR]
#
# Reproducible to the extent a Rust build is: the toolchain is pinned by
# rust-toolchain.toml, dependencies by Cargo.lock (--locked), paths are remapped,
# timestamps are clamped to SOURCE_DATE_EPOCH and files are added in sorted order
# with root ownership. Two builds on the same toolchain and base image should be
# byte-identical; docs/build.md describes how to check, and says what has and has
# not been checked.
#
# The package does not contain cordial-run (see packaging/build-client.sh) and
# never contains anything from Roblox.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist}
cd "$root"

: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64) musl=x86_64-unknown-linux-musl ;;
    arm64) musl=aarch64-unknown-linux-musl ;;
    *) echo "unsupported architecture $arch" >&2; exit 1 ;;
esac

export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$root=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo -C strip=symbols"
cargo build --release --locked -p hrdd -p hrdctl -p hrd-netd -p hrd-import -p hrd-panel
# The entry wrapper is static, so that it depends on no library a client could influence.
cargo build --release --locked -p hrd-enter --target "$musl"

pkg=$(mktemp -d)
shl=$(mktemp -d)
trap 'rm -rf "$pkg" "$shl"' EXIT
tgt=${CARGO_TARGET_DIR:-target}
t=$tgt/release
install -d "$pkg/usr/bin" "$pkg/usr/lib/hrd" "$pkg/usr/lib/systemd/system" "$pkg/usr/lib/sysusers.d" "$pkg/usr/lib/tmpfiles.d" "$pkg/usr/share/doc/hrd" "$pkg/DEBIAN"
install -m 0755 $t/hrdd $t/hrdctl $t/hrd-panel "$pkg/usr/bin/"
install -m 0755 $t/hrd-netd $t/hrd-import "$pkg/usr/lib/hrd/"
install -m 0750 "$tgt/$musl/release/hrd-enter" "$pkg/usr/lib/hrd/hrd-enter"
install -m 0644 packaging/systemd/*.service "$pkg/usr/lib/systemd/system/"
install -m 0644 packaging/sysusers.d/hrd.conf "$pkg/usr/lib/sysusers.d/"
install -m 0644 packaging/tmpfiles.d/hrd.conf "$pkg/usr/lib/tmpfiles.d/"
install -m 0644 config/hrdd.toml.example config/netd.toml.example "$pkg/usr/share/doc/hrd/"
for d in docs/*.md BASELINE.md NOTICE.md README.md; do [ -f "$d" ] && install -m 0644 "$d" "$pkg/usr/share/doc/hrd/"; done
install -m 0644 LICENSE "$pkg/usr/share/doc/hrd/copyright" 2>/dev/null || true

# Libraries the binaries really link, resolved by dpkg against this build host:
# the minimum libc6 is whatever the host had, not a guess.
mkdir -p "$shl/debian" && : > "$shl/debian/control"
shlibs=$(cd "$shl" && dpkg-shlibdeps -O -e"$pkg/usr/bin/hrdd" -e"$pkg/usr/bin/hrdctl" -e"$pkg/usr/bin/hrd-panel" -e"$pkg/usr/lib/hrd/hrd-netd" -e"$pkg/usr/lib/hrd/hrd-import" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')
size=$(du -sk "$pkg" | cut -f1)
sed "s/@VERSION@/$version/; s/@ARCH@/$arch/; s/@SIZE@/$size/; s/@SHLIBS@/${shlibs:-libc6}/" packaging/deb/control.in > "$pkg/DEBIAN/control"
install -m 0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$pkg/DEBIAN/"

# Normalise what goes into the archive.
find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$out/hrd_${version}_${arch}.deb"
( cd "$out" && sha256sum "hrd_${version}_${arch}.deb" )
