#!/bin/sh
# Format (or check) this workspace's own crates only.
#
# `cargo fmt --all` also formats path dependencies, which includes the pinned
# upstream submodule under third_party/. Upstream is not ours to reformat, so
# list the crates explicitly.
set -eu
cd "$(dirname "$0")/.."
pkgs=""
for d in crates/*/; do
    pkgs="$pkgs -p $(basename "$d")"
done
# shellcheck disable=SC2086
exec cargo fmt $pkgs "$@"
