# Notice: provenance and licences

This project (the fleet manager) is licensed **GPL-3.0-or-later**; the full text is
in [`LICENSE`](LICENSE). It was written for, and builds on, **Cordial**, which is
also GPL-3.0; the two are separate works that meet at a process boundary
(`cordialctl`/`cordiald` start Cordial's `cordial-run` as a child process).

## What is taken from upstream, and how

| | |
|---|---|
| Upstream | Cordial, <https://github.com/luohoa97/cordial> |
| Pinned commit | `b0ee9f39f03eae61362edc28214bb1533e87d8d0` (workspace version 0.23.0) |
| How it is included | git submodule at `third_party/cordial`, **unmodified**. Changes are a patch queue in `patches/cordial/`, applied to a build copy by `patches/cordial/apply.sh`; the submodule is never edited |
| Code compiled into this project's binaries | only the `cordial-update` crate, used by `cordial-import` for archive inspection and APK signature verification (path dependency into the submodule) |
| Code run as a separate program | `cordial-run`, built from the patched copy (docs/build.md) |

Upstream's own `NOTICE` (kept in the submodule) lists its third-party components:
the ported AOSP bionic linker and libjnivm (MIT), libbadcpu (MIT), a web-view
policy derived from mocktail (Apache-2.0), and Rust crates under their own
licences. Those notices apply to `cordial-run` and to the `cordial-hrd-client`
package, which must ship them. Nothing here is endorsed by upstream (BASELINE.md
records upstream's own position on multi-accounting and third-party clients).

## What is not here

No Roblox application, library, asset or account data is in this repository, in
any package built from it, or in any CI artifact. The operator imports a Roblox
Android build from files they obtained themselves; `cordial-import` verifies its
signature against the certificate pinned in upstream Cordial and stores it only
on the target machine.

## Other code

Rust crates from crates.io, at the versions in `Cargo.lock`, each under its own
licence (MIT and Apache-2.0 for the great majority; `cargo tree` lists them).
