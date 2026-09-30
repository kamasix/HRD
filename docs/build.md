# Building

## Pins

| | |
|---|---|
| Rust | `rust-toolchain.toml`: 1.94.1 with rustfmt and clippy; targets `x86_64-unknown-linux-gnu`/`-musl` |
| Dependencies | `Cargo.lock` (every build uses `--locked`) |
| Upstream Cordial | submodule `third_party/cordial` at `b0ee9f39f03eae61362edc28214bb1533e87d8d0` (v0.23.0); its own submodules (`libjnivm`, `mcpelauncher-linker`, ...) at the commits recorded in it. No "latest", no branch |

```
git clone --recursive https://github.com/kamasix/HRD
# or, in an existing clone:
git submodule update --init --recursive
```

## The manager (no GTK needed)

```
scripts/fmt.sh -- --check                      # formats this workspace only, never the submodule
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
packaging/build-deb.sh [OUTDIR]                # -> cordial-hrd_<version>_<arch>.deb
```

`scripts/fmt.sh` exists because `cargo fmt --all` also formats path
dependencies, which includes the upstream submodule.

Only `hrd-import` pulls upstream code (`cordial-update`, by path, for APK
inspection and signature verification). Everything else is this project's own
crates. `cordial-enter` is built for a musl target so it is static.

### Reproducibility

`packaging/build-deb.sh` sets `SOURCE_DATE_EPOCH` (the last commit's time unless
you set it), `--remap-path-prefix` for the source tree and the cargo home,
`-C strip=symbols`, adds files with root ownership and clamped mtimes, and
compresses with `xz`. **Checked once:** two builds from the
same tree on the same machine, each with a fresh `CARGO_TARGET_DIR`, produced
byte-identical `.deb` files (same SHA-256). Not checked: a different machine, a
different toolchain install, or a different distribution.

**Build on the oldest system you will install on.** The package's `Depends:` are
computed by `dpkg-shlibdeps` from the binaries on the build host; built on a host
with glibc 2.39, the package asks for `libc6 (>= 2.39)`. Build on Debian 13 to
install on Debian 13.

## The client (needs GTK)

`cordial-run` is upstream's client. It links GTK 4 and libadwaita (see
[headless.md](headless.md) for the measured list), is compiled with clang (AOSP
bionic headers use C11 `_Atomic` in C++), and uses CMake for its native parts.

Debian build dependencies. The build here had a compiler, `clang`, `cmake`, and the
GTK 4 and libadwaita development packages installed; on a minimal system install
whatever `pkg-config`/`cmake` report missing on top of these:

```
sudo apt install build-essential clang cmake pkg-config git libgtk-4-dev libadwaita-1-dev
```

The client is built from a **patched copy** of the submodule; the submodule itself
is never edited:

```
patches/cordial/apply.sh /path/to/patched-copy      # copies, then applies patches/cordial/series
cd /path/to/patched-copy && cargo build --release --locked -p cordial-runtime --bin cordial-run
packaging/build-client.sh [OUTDIR]                  # does both, then -> cordial-hrd-client_<version>_<arch>.deb
```

The patches (each a few dozen lines, each with a rationale in its header):
`0001` join link from `CORDIAL_JOIN_URL`, `0002` assets from a shared mapping of
the extracted tree, `0003` a cap on the CPU count the engine is told. `apply.sh`
was checked to reproduce, byte for byte, the files that were compile-checked.

**What was run:** `cargo check` and a full `cargo build --release` of the patched
copy (Ubuntu 24.04 toolchain, GTK 4.14, libadwaita 1.5); a test that exercises
patch `0002` against a real mapping. **What was not:** a build on Debian 13; any
execution of the built client beyond `--help` (no Roblox files here);
`build-client.sh` end to end; arm64.

## What is never built or shipped

No Roblox file. No APK, engine library, asset or account data is committed, put
in a package or left in CI artifacts; CI for this repository (none is provided)
must not upload any either.
