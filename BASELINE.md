# BASELINE: what upstream Cordial actually is

This is the state of the code this project builds on, read before anything was
written. It separates what the source **does**, what is only **described**, what
this project has to **implement**, and the limits found. Every statement is
about upstream unless it says otherwise. "Read" means read in source; "run"
means observed running, which nobody on this project has done (see the last
section).

## Pin

| | |
|---|---|
| Upstream | <https://github.com/luohoa97/cordial> |
| Commit | `b0ee9f39f03eae61362edc28214bb1533e87d8d0` ("Bump cordial-bin to 0.23.0"), workspace version 0.23.0 |
| How it is integrated | git submodule at `third_party/cordial`, pinned to that commit; changes to upstream live as a patch queue in `patches/cordial/` and are applied to a build copy, never to the submodule (`docs/build.md`) |
| Its own submodules | `third_party/libjnivm` @ `f24b98c1`, `third_party/mcpelauncher-linker` @ `1ac3ea6c` (and that one's `bionic`, `core`) |
| Licence | GPL-3.0-or-later; MIT (linker, libjnivm, libbadcpu) and Apache-2.0 (mocktail-derived web-view policy) components keep their notices. This project is GPL-3.0-or-later too. See `NOTICE.md` |
| Toolchain | upstream `rust-version` 1.75, builds with Clang (AOSP bionic uses C11 `_Atomic` in C++ headers) and needs GTK4 >= 4.12 and libadwaita >= 1.5 headers. This project pins Rust 1.94.1 in `rust-toolchain.toml` |

**Upstream's own position, which this project does not change.** `SECURITY.md`
says Cordial "does not support script execution, exploiting, botting or
multi-accounting". ADR-012 asks that several profiles be described as "profiles,
not multi-account", and `README.md` warns that Roblox bans accounts for using
third-party clients, in waves, including false positives. Nothing here is
endorsed by upstream and none of it should be sent to upstream as-is. The brief
for this project forbids injectors, script execution, synthetic input,
anti-AFK, CAPTCHA/ban/limit circumvention, account generation, automatic IP
rotation and automatic reconnects, and none is implemented.

## What upstream is, structurally

Five crates (`Cargo.toml`): `cordial-linker-sys` (ported AOSP bionic linker plus
libjnivm, built by CMake), `cordial-runtime` (the client, binary `cordial-run`),
`cordial-plugins`, `cordial-shell` (the GTK launcher, binary `cordial-shell`)
and `cordial-update` (APK fetch/verify/extract/store).

**One process is one instance is one window is one profile** (ADR-012).
`cordial-run` maps Roblox's unmodified `libroblox.so` with the bionic linker,
answers the engine's imports as *cordial*, *host* (glibc) or *stub*, stands up
`libjnivm` in place of ART, and implements the Android framework calls.

## What works in code (read)

| Area | Fact | Where |
|---|---|---|
| Profiles | `<root>/<name>`, name `[A-Za-z0-9_-]{1,64}`; root is `CORDIAL_PROFILE_ROOT`, else `$XDG_DATA_HOME/cordial/profiles`, else `$HOME/.local/share/cordial/profiles`, else `$TMPDIR/cordial/profiles` (a bare systemd unit with no `HOME` silently lands in `/tmp`) | `cordial-shell/src/profile.rs:85-111` |
| Profile lock | `flock(LOCK_EX\|LOCK_NB)` on `<profile>/.lock`; `cordial-run` claims it itself (exit **3** if refused, for any claim failure); a launcher can hand over its fd in `CORDIAL_PROFILE_LOCK_FD` | `profile.rs:200-352`, `load.rs:1517-1664` |
| Session storage | three stores (cookies, identity, local-storage secure values) in the Secret Service keyed by the **absolute profile path**, or as 0600 files. `CORDIAL_SECRET_STORE`: `auto` (default) **silently falls back to a plaintext 0600 file** when no service is usable, `keyring` refuses the fallback and saves nothing, `file` is plaintext, and *any other value is treated as `file`* | `cordial-shell/src/secrets.rs:192-260` |
| Secret Service client | hand-rolled over zbus, `plain` session transport, reads `Locked`, **never calls `Unlock` or `CreateCollection`**, needs a default-alias collection | `secrets/keyring.rs:173-298` |
| Login | the engine's own Lua login screen, including a device-code "Quick Sign-in"; Cordial has no function that drives it. Headless, the only way to see the code is devctl `screenshot` | `docs/design/sign-in.md`, `devctl.rs` |
| Join | `--join-url roblox://experiences/start?placeId=N[&linkCode=..]` is passed unchanged; a desktop `roblox-player:` link is translated. **The only channel is argv at start**; there is no way to hand a link to a running client | `deeplink.rs:307-629`, `load.rs:293-302` |
| Headless | `--headless` re-execs under `cage` with `WLR_BACKENDS=headless`. The pid you start becomes `cage`; `cordial-run` is its child. It falls back to nothing | `headless.rs` |
| Stop | SIGTERM/SIGINT is graceful only **after the pump starts**; a second signal during teardown exits 1; the teardown watchdog exits 124 after 10 s | `looper.rs:667-689, 1512-1571` |
| Exit codes | 0 orderly (also after several non-fatal failures), 1 generic/gate refused, 2 usage, 3 profile busy, 124 teardown watchdog; death by signal has none | `load.rs` |
| Status signals | stdout/stderr lines: `LOADED in`, `[roblox] app ready: <Screen>` (`Landing` = signed out, `Home`/`RootSwitchNavigator` = signed in), `DID_LOG_IN`/`DID_LOG_OUT`/`LUA_UNAUTHORIZED_LOG_OUT`, `[cordial] game: joining server / joined place / left`, `[cordial] health:` every 30 s | `init_params.cpp`, `android_classes.cpp`, `game_log.rs`, `looper.rs:1126` |
| APK verification | v2/v3 signing block parsed, chunked SHA-256, RSA/ECDSA via `ring`, downgrade protection, one pinned certificate fingerprint in `packaging/trust/roblox-signing-certificates.json` | `cordial-update/src/apk_signature.rs` |
| Safe extraction | `apk::inspect` refuses `..`, absolute paths, symlinks, devices, setuid; size and entry caps | `cordial-update/src/apk.rs` |
| Build store | `builds/<engine version>/`, `KEEP = 3`, a `.store.lock`, atomic `rename` publication inside `file_into_store` | `cordial-update/src/store.rs`, `install.rs` |
| Network gate | per-profile `network.json`, `"mode":"vpn-required"` plus a `check` argv that must exit 0, run at launch in both entry points | `cordial-shell/src/network.rs` |
| No injector | no hooking, patching, script environment or plugin API for one; ADR-001, ADR-003 | `AGENTS.md` |

## Findings that change the design

1. **`cordial-run` is a GTK process in every mode.** `cordial-runtime` depends
   directly on `gtk4`, `libadwaita` and `cordial-shell`
   (`Cargo.toml:47,54,62`). On Wayland, `adw::init()` runs and a full
   `AdwWindow` is built and iterated from the engine pump
   (`wayland.rs:1401`, `host_window.rs:158-330`). Removing the launcher does not
   remove GTK from the client. **A GTK-free manager is possible; a GTK-free
   client is not**, short of the X11 backend, which has no sign-in and no web
   views (ADR-024).
2. **`--headless` is a nested compositor, not a no-render mode.** GTK, the
   window, Vulkan/EGL and presents all stay (`headless.rs:19-22` measured the
   presents). There is no no-render mode anywhere in the open code.
3. **The asset cache never frees.** `Manager::read` decompresses each requested
   asset into a `Vec`, `Vec::leak`s it and keeps it in a process-lifetime
   `HashMap` (`asset.rs:273-279`); `AAsset_close` frees only a 16-byte handle;
   the pointer returned by `AAsset_getBuffer` stays valid after close, which the
   engine may rely on. **Evicting would be a use-after-free.** The bound is
   "what the APK contains" (~90 MB of assets), and its real size is unmeasured.
4. **Only six `AAsset*` functions exist and the engine imports exactly those**
   (`undefined-symbols.tsv:468-473`): no `AAsset_read`, no `AAssetDir_*`.
5. **The engine statically links mimalloc** (ADR-040). `MALLOC_ARENA_MAX` and
   glibc tunables do not touch the engine's heap; `MIMALLOC_*` environment
   variables are an unexplored lever.
6. **Engine text is shared.** `libroblox.so` has no TEXTREL and no `.rela.dyn`;
   its 546 relocations are in the data segment, so the ~106 MB of text stays
   clean, file-backed and shared through the page cache when every instance maps
   the same file (`patches/README.md` in upstream).
7. **The "~1.5 GB per instance" figure has no recorded method** (ADR-012:368).
   The only measurements in the repo are 500-802 MB RSS at the signed-out landing
   page, n=3, on the maintainer's desktop (`docs/analysis/startup-and-idle-cost.md`).
   **No signed-in, in-game or multi-instance figure exists.**
8. **The pinned signing certificate is not bound to the key that verified the
   signature.** `apk_signature::verify` checks the signature against the
   `public key` field of the signer record, and takes the fingerprint from the
   first certificate in the signed data, and never compares the two
   (`apk_signature.rs:500-610`; upstream's own spec,
   `docs/design/fetching-the-roblox-build.md:473-480`, requires the check).
   An archive carrying Roblox's public certificate and signed with any other key
   passes `verify_signed_by`. **Reproduced** (not only read): the test
   `binding::tests::a_pinned_certificate_on_a_block_signed_by_another_key_passes_upstream_and_fails_here`
   in `hrd-import` builds a small synthetic APK with a genuine v2 block, signed
   with an ephemeral key, whose embedded certificate wraps a *different*
   key; upstream's `verify_signed_by`, given that certificate's fingerprint as
   the pin, returns `Ok`. (A synthetic archive, not Roblox's; it proves the
   check is missing, not that any real build is forged.) `hrd-import` adds the
   missing comparison (certificate SPKI == record public key) for every signer
   and treats a mismatch as a refusal.
9. **Upstream's store is not safe to share as-is.** `keep_archives` hard-links
   under the source file's name, `.content-sha256` is never read, verify and
   extract re-open the path (TOCTOU for a same-user writer), the launcher
   verifies only `base.apk` and will extract the engine from an unverified
   `split_config*.apk`, and no versionCode/package/split consistency check
   exists. `hrd-import` stages private copies, verifies and extracts those same
   files, and uses its own store.
10. **One shared writable directory.** `cordial-run` extracts `assets/` into
    `$XDG_CACHE_HOME/cordial/assets`, stamp-gated (`size mtime canonical-path`
    of the APK), without a lock, and rewrites `clientsettings.json` /
    `enginesettings.json` non-atomically. Clients on different builds, or one
    build reached by different paths, would fight over it. This project gives
    each account its own `XDG_CACHE_HOME` and points `cordial/assets` at a
    read-only directory filled once at import.
11. **The network gate fails open.** An absent, malformed or unknown-mode
    `network.json` means "no requirement"; the `check` has no timeout; it is
    checked once at launch (`network.rs:201-213`). It is useful as a second
    line; the first line has to be the namespace itself (fail-closed by
    construction: the namespace has no interface but the tunnel).
12. **Nothing is proxied or intercepted.** The engine's network I/O is plain
    glibc (`socket`, `connect`, `getaddrinfo` via a thin wrapper), so a network
    namespace covers curl, the game's UDP transport, DNS and helper processes
    alike; `HTTP_PROXY` would cover none of the UDP. The same facts mean DNS is
    resolved from the **mount namespace's** `/etc/resolv.conf` /
    `nsswitch.conf`, and through `systemd-resolved` or `nscd` sockets if
    configured, which cross namespaces (a leak). The entry wrapper overlays both
    files and masks the nscd socket.
13. **Path limits.** The client binds `live/settings.sock` inside the profile
    (`sun_path` is 107 bytes); with the packaged layout that limits account names
    to 32 characters. devctl's socket path is overridable
    (`CORDIAL_DEV_CONTROL_SOCKET`), the live-settings one is not; a failed bind
    is non-fatal.
14. **Observability gaps.** There is no disconnect/kick parser (`game_log.rs`
    has tests that disconnect lines parse as nothing); `client.ready` is
    declared and never published; devctl has no game-state verb; exit status is
    not propagated through `cage`. Disconnect lines exist only in the engine's
    own log file (`[FLog::Network] Disconnection Notification. Reason: N`,
    `Connection lost`, `[DFLog::NetworkClient] Client:Disconnect`).
15. **Startup freeze.** Upstream documents an unresolved freeze at startup,
    mostly on signed-in profiles (16/20 on 2026-08-26, 0/16 in later rounds).
    `CORDIAL_STARTUP_RETRY` makes it worse and must stay off. A start that never
    reaches `app ready` is therefore an expected failure mode, not an anomaly.
16. **Unattended clients generate no synthetic input.** Upstream's
    `idle_keepalive` (the only thing `CORDIAL_THROTTLE` controls) acts *only
    while a key is held* (`input.rs:1717-1726`); with no keyboard, as under
    `cage`, it does nothing. The engine's own idle throttle applies (~1
    present/s after 13 s without input, `AGENTS.md`). Roblox's own idle-kick
    policy is outside this project and is not counteracted.
17. **Secrets on the command line.** `--join-url` values, including private
    server `linkCode`/`accessCode`, sit in argv and in `/proc/<pid>/cmdline`
    (world-readable). A patch (`patches/cordial/`) lets the manager pass the URL
    through the environment (same-uid only) instead.
18. **Stale upstream documentation found on the way.** `README.md:188-190` and
    `AGENTS.md:575-579` say `CORDIAL_PROFILE_ROOT` does not move the client; at
    this commit it does move the engine's storage (`load.rs:421,458-460`).
    `asset.rs:1298` calls its memfd "sealed" and `memfd_create(..., 0)` seals
    nothing. `accessibility.rs:40-42` says the runtime has no GTK dependency.

## Only described, or unverified

* Upstream's multi-account claim is two profiles side by side (ADR-012
  "Demonstrated, 2026-08-02"); nothing larger has been run.
* The `vpn-required` gate's effect under a real tunnel was not exercised
  (ADR-016: the author lacked `CAP_NET_ADMIN`).
* `cage` on a GPU-less host: not recorded anywhere. `docs/doctor.md` says only
  that a CPU Vulkan device (llvmpipe) "works and the GPU is not being used".
* `cage`'s signal and exit-status behaviour, its `XDG_RUNTIME_DIR` needs and the
  number of Wayland sockets it can pick (`wayland-0`..`wayland-32`) are not
  established. This project gives each instance a private `XDG_RUNTIME_DIR`.
* Whether `kick`/`leave` triggers `leaveUGCGameInternal` (`game: left`).
* Whether the engine sizes its worker pool from `sysconf(_SC_NPROCESSORS_ONLN)`
  (the `bionic_sysconf` shim forwards to glibc); whether restricting CPU
  affinity therefore shrinks the thread pool (63-73 threads per client,
  `RBX Worker A..P` one per core) is **inferred, not observed**.

## What this project implements (none of it exists upstream)

The CLI (`hrdctl`), the daemon (`hrdd`), the privileged network helper
(`hrd-netd`), the namespace-entry wrapper (`hrd-enter`), the runtime
importer (`hrd-import`), the optional web panel (`hrd-panel`), the
Debian packaging, and the patch queue. Their status is tracked in
[`docs/status.md`](docs/status.md) with the labels *implemented*, *compiled*,
*unverified at runtime*, *blocked by a named dependency*, *not implemented*.

## What was not done, and why

No Roblox client, account, game, engine or multi-instance session was run in the
environment this was written in: there is no APK, no account, no GPU, no
display and no systemd here, and the brief forbids running them. **Nothing that
depends on the real engine has been observed.** Compilation and unit tests of
this project's own logic were run where the environment allowed and are
reported as exactly that.
