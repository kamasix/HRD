# A server without a graphics card

Most VPSes and many home servers have no GPU. Cordial needs something to draw
with, so on such a machine the CPU does it. This is supported by the manager and
**unverified with the real engine**; the page says what the settings are and
what to expect.

## What is configured

`engine.graphics`:

* `auto` (default): if the service user can open a DRM render node
  (`/dev/dri/renderD*`) the client uses it; otherwise it draws on the CPU.
  `hrdctl doctor` says which.
* `software`: never touches `/dev/dri`.
* `gpu`: refuses to start a client without a render node instead of falling back.

For CPU drawing the manager sets, per client: `WLR_RENDERER=pixman` (the nested
compositor draws with pixman, no EGL needed), `LIBGL_ALWAYS_SOFTWARE=1` and
`GALLIUM_DRIVER=llvmpipe` (Mesa GL), `VK_DRIVER_FILES`/`VK_ICD_FILENAMES` set to
the lavapipe ICD (Mesa's CPU Vulkan driver), `GSK_RENDERER=cairo` (GTK), and
`LP_NUM_THREADS` from `engine.software_threads` when set.

Install the driver: `apt install mesa-vulkan-drivers` (lavapipe), `cage`. Without
a Vulkan device the engine cannot draw; `doctor` fails that check instead of
letting you find out at the first start.

## What it costs

CPU drawing is not free. Every frame of every client is rasterised by the CPU;
at the idle throttle of about one present per second the cost is small per client
but not zero, and a client in a game draws more. Two things make it worse than
it looks:

* llvmpipe and lavapipe default to one rasteriser thread per core **per
  client**. With several clients on few cores that oversubscribes the machine.
  Set `engine.software_threads = 1` on a small machine.
* Starts are CPU-heavy for about a minute. The default concurrency
  (`max_concurrent_starts = 0`) is 1 when frames are drawn on the CPU on a
  machine with fewer than 8 cores, and the scheduler also waits for CPU pressure
  (`max_cpu_pressure_avg10`) to fall.

## Expectations on a small box

For a machine like an older quad-core desktop CPU (4 cores, no hyper-threading,
no GPU, 8-16 GB) the honest statement is:

* The limit will be memory before it is CPU. Upstream's only figures are
  500-802 MB resident at the signed-out landing page; if in-game clients were
  similar, 16 GB would hold on the order of a dozen or two, before CPU. **Nobody
  has measured an in-game client**, here or upstream, and this project has run no
  client at all.
* 300 clients on such a machine is not a realistic goal. 300 is the *manager's*
  design target (registry, queue, sampling, stop-all), not a statement about
  engines.
* Find your number: start one, then two, then four, watching `hrdctl stats`
  (RSS/PSS per class, memory pressure, CPU) and `hrdctl status`; set
  `scheduler.max_instances` to what the machine sustains and leave headroom.

## Other Debian servers

The manager builds for amd64 and arm64. The Roblox Android build and upstream's
client are the constraint: upstream supports x86-64 and lists aarch64 as new and
untested on real hardware. Older kernels work: without cgroup v2 delegation the
manager falls back to process groups (weaker; `doctor` warns), without
`cgroup.kill` it uses a kill loop, without PSI it admits starts on free memory
alone, without a render node it draws on the CPU. The minimum for the privileged
helper is a kernel with network namespaces and WireGuard (5.6+, or the DKMS
module on older ones).
