#!/bin/sh
# Make a patched COPY of the pinned upstream tree. The submodule itself is never
# modified: it stays exactly at the commit BASELINE.md names.
#
#   patches/cordial/apply.sh DEST
#
# DEST must not exist. Afterwards build in DEST (docs/build.md).
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
dest=${1:?usage: apply.sh DEST}
src=$root/third_party/cordial
[ -f "$src/Cargo.toml" ] || { echo "the upstream submodule is missing: git submodule update --init --recursive" >&2; exit 1; }
[ ! -e "$dest" ] || { echo "$dest already exists" >&2; exit 1; }
mkdir -p "$dest"
tar -C "$src" --exclude=./target --exclude=./.git -cf - . | tar -C "$dest" -xf -
grep -v '^#' "$root/patches/cordial/series" | while read -r p; do
    [ -n "$p" ] || continue
    echo "applying $p"
    patch -p1 -d "$dest" --forward --no-backup-if-mismatch -s < "$root/patches/cordial/$p"
done
echo "patched copy ready: $dest"
