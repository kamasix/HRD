# Memory

The goal is the smallest *real* memory per running client. This page says what
was done toward it, what was measured, and, as important, what is outside this
project's reach. No figure here is a promise about your machine.

## Three places memory goes

| | what | who controls it | what this project did |
|---|---|---|---|
| **A** | the manager (`cordiald`, `cordialctl`, the helpers) | this project | measured, see below |
| **B** | Cordial's open layer inside each `cordial-run`: GTK/libadwaita, the Android-framework emulation, the bionic linker, the asset cache, the nested compositor and the Vulkan/GL driver it talks to | upstream Cordial, patchable | a few real levers, below; **cost unmeasured** |
| **C** | the closed Roblox engine in the same process: its heap (statically linked mimalloc), its ~60-70 threads' stacks, textures and meshes it decodes, the replicated state of the game | Roblox, and the experience being played | **nothing can be done here from outside**; the client is the unmodified engine |

A client's resident memory is B + C. A and B+C must never be added into one
flattering number: a manager that holds 300 records in 4 MiB says nothing about
300 engines.

## A: the manager (measured)

Release build, this project's own code, on the machine it was written on (x86-64
Linux 6.18, 4 CPUs), `cordiald` with no live clients:

| state | VmRSS | PSS | threads |
|---|---|---|---|
| started, no accounts | 3.7 MiB | 2.0 MiB | 4 |
| 300 accounts registered, one sampling round done | 4.5 MiB | 2.9 MiB | 4 |
| after `status`, `stats` and `account list` | 4.7 MiB | 3.0 MiB | 4 |

Not measured: the daemon with 300 *live* clients (the sampler, log tails and the
admission code do per-client work, which has been written to be small and has
not been observed at that size). `cordialctl` is a short-lived process; its
binary is about 2.4 MB, which is **not** evidence of its memory use.

## B and C: what is known

Upstream's own numbers, which are the only ones anyone has: 500-802 MB resident
at the signed-out landing page, n=3, on the maintainer's desktop
(`docs/analysis/startup-and-idle-cost.md` upstream); the "~1.5 GB per instance"
in ADR-012 has no recorded method. **No signed-in, in-game or multi-client
figure exists**, here or upstream. `cordialctl stats` shows, on your machine,
RSS, PSS, USS, swap and `memory.current` separately for engine, compositor and
helper processes: that is how to learn the real number.

**About 1 MB per session** is not a target this architecture can meet and this
project does not claim it or approach it: a process that maps the 106 MB engine
text and runs ~60-70 threads costs more than that before the game sends a byte.
What sharing *can* do is make that text and the read-only assets count once
instead of once per client (PSS shows it); that is worth having and is
implemented (below). It is not 1 MB.

## Sharing, and what is deliberately not shared

* **Engine text.** `libroblox.so` has no text relocations; its 546 relocations
  are in the data segment, so its ~106 MB of code stays clean, file-backed page
  cache shared by every client that maps the same file. The runtime store holds
  one sealed (`0440`) copy per installed build, installed once and used by all
  processes, never unpacked per instance.
* **Assets.** Installed once, extracted once, sealed read-only. With the patched
  client (mode `minimal` or above) an asset is served from a mapping of the
  shared extracted file instead of a decompressed private copy.
* **Not shared between accounts:** profiles, cookies, databases, anything
  writable. One engine process per account; no attempt is made to run several
  accounts in one process, because the engine's global state is not known to
  allow it.

## The asset cache, in detail (and why it is not simply evicted)

Upstream's `Manager::read` (`android/asset.rs`) decompresses each requested asset
into a `Vec`, `Vec::leak`s it and keeps it in a process-lifetime map.
`AAsset_close` frees only a 16-byte handle and the pointer `AAsset_getBuffer`
returned stays valid afterwards, which the engine may rely on. **Evicting those
buffers would be a use-after-free**, so this project does not. The bound on the
cache is what the engine requests, at most what the APK contains (~90 MB
extracted); the real size is unmeasured.

Patch `0002` keeps the lifetime contract and changes whose memory it is: the
bytes come from a `MAP_PRIVATE` mapping of the extracted file, never unmapped.
Clean pages belong to the page cache (shared, reclaimable); a page the engine
writes is copied, as before. Checked by a test against a real mapping: content
served, size mismatch falls back to the APK, a symlink is not followed, a name
that leaves the tree is refused, a write does not reach the file. **What it saves
in a real client has not been measured.**

Only `AAsset_*` assets pass through this. Everything the engine downloads
(meshes, textures, sounds, the experience itself) arrives over the network and is
decoded inside the closed engine; it cannot be filtered without modifying the
engine, and intercepting TLS to do so is not done and will not be.

## Where each kind of data comes from, and what can be saved

Roblox's Android client has four kinds of data that matter for memory. For each:
where it comes from, who allocates and manages it, what this project does about it
and what stays out of reach.

| data | where from | who allocates / manages | what is done | outside Cordial's control |
|---|---|---|---|---|
| **1. starting resources in the APK** (`assets/`: fonts, shaders, the certificate bundle, Lua/content the app needs to start) | the APK; extracted once at import into a sealed read-only tree | `AAssetManager` emulation in `android/asset.rs` (open layer): today a decompressed `Vec`, leaked, per process | patch 0002 (shared file mapping), modes `minimal`+ | which assets the engine asks for; it may assume they exist (the certificate bundle and init content are required, nothing is stubbed or filtered) |
| **2. resources the engine downloads** (meshes, textures, sounds, the experience's content) | Roblox's servers over TLS, by the engine's own curl stack | the closed engine's heap (mimalloc) and its on-disk cache | nothing inside the engine; the per-account cache directory keeps one account's files apart | everything: what is fetched, decoded, cached and freed is decided inside `libroblox.so`. TLS is never intercepted to filter it |
| **3. replicated world state** | the game server, over the engine's UDP transport | the closed engine | nothing | entirely the experience and the engine |
| **4. data to start and keep a real session** (cookies, identity, client settings, flags, the ~106 MB engine text) | the keyring, the client-settings fetch, `libroblox.so` | open layer for the stores, engine for the rest | engine text shared through the page cache; sessions in one encrypted store, never in a plain file | flag and settings payloads, the engine's own initialisation |

Skipping an asset at the loader is only possible for names the open layer is asked
for, and nothing here does it: a missing asset the engine expects is a crash or a
silent wrong render, and no name was established as optional. The `minimal`
mode therefore removes cost that is demonstrably unneeded for a window nobody
looks at (surface size, present mode, desktop integration), not content.

## Modes

Each mode is a list of environment variables that a program actually reads
(`crates/cordiald/src/spawn.rs`, `mode_env`; tested). A variable the closed
engine's allocator may ignore is marked.

| variable | compatible | minimal | aggressive | reads it | expected effect |
|---|:-:|:-:|:-:|---|---|
| `CORDIAL_GAMEMODE=0` | yes | yes | yes | open layer | no D-Bus GameMode request and thread (a server has no gamemoded) |
| `CORDIAL_RESOLUTION` | upstream's 1280x720 | 640x360 | 320x240 | open layer | smaller swapchain and compositor surface; the engine's internal buffers may scale too: unmeasured. 320x240 is the smallest `cordial-run` accepts |
| `CORDIAL_ASSET_MMAP_DIR` | - | yes | yes | patch 0002 | shared file-backed assets instead of private copies; **needs the patched client**, ignored otherwise |
| `CORDIAL_PRESENT_MODE=fifo` | - | yes | yes | open layer | no extra presents from MAILBOX; matters when frames are drawn on the CPU |
| `MALLOC_ARENA_MAX=2` | - | - | yes | glibc | fewer malloc arenas in the GTK/host side; the engine's own heap is mimalloc and is unaffected |
| `MIMALLOC_PURGE_DELAY=0` | - | - | yes | the engine's mimalloc, **if it honours the variable** | freed pages returned to the OS at once (CPU cost); unverified that the statically linked allocator reads it |
| `CORDIAL_NPROC=N` | - | - | yes | patch 0003 | lowers the CPU count the engine is told; **inferred, not observed**, that the worker pool follows it |

A configured `engine.resolution` beats the mode. Sign-in clients always get the
full size, because a person reads them.

What is *not* in any mode, because it would only hide cost: swapping clients out
to lower RSS (`resources.swap_max_mib` stays unset), a `memory.max` that merely
kills, a fake "no assets" switch, pausing the engine loop to cut frame rate.

## Other switches, off by default

* `resources.ksm = true` asks the kernel to merge identical anonymous pages
  between clients (Linux 6.4+). Its CPU is charged to `ksmd`, not to any client,
  and whether the engine has enough identical pages to pay for it is unmeasured;
  `cordialctl stats` shows the merge counters so you can tell.
* `resources.memory_high_mib` throttles and reclaims above a line. With no swap,
  anonymous memory cannot be reclaimed, so a client over the line is slowed
  rather than made smaller.
* `engine.cpus_per_instance` pins clients to CPUs round-robin to limit
  contention. Affinity does not change how many CPUs the engine sees.

## Starts cost more than steady state

A start decompresses, relocates and loads; the scheduler therefore paces them
(`scheduler.max_concurrent_starts`, free-memory and pressure checks, and an
estimate that replaces its initial guess with the observed peak of the last
starts). The estimate is a peak estimate and says nothing about steady-state
cost.
