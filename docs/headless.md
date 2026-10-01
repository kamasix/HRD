# Headless operation and what the client still needs

The manager (`hrdd`, `hrdctl`, the helpers) needs no graphics library at
all: they link the C library and `libgcc_s` and nothing else (checked with `ldd`; the
binaries are plain Rust). The client is a different matter.

## What `cordial-run` actually links (checked)

The patched client was built in release mode for this project and its dynamic
dependencies listed with `readelf -d` and `ldd` (Ubuntu 24.04 toolchain with GTK
4.14 and libadwaita 1.5 headers; a Debian 13 build will show the same kinds of
entries with different versions):

* direct: `libgtk-4`, `libadwaita-1`, `libcairo`, `libpango-1.0`, `libgraphene`,
  `libgio-2.0`, `libglib-2.0`, `libgobject-2.0`, `libstdc++`, `libgcc_s`, `libm`,
  `libc`;
* transitively 106 shared objects, including the X11 client libraries
  (`libX11`, `libXrandr`, ...), `libwayland-client`, `libwayland-egl`, `libvulkan`,
  `libepoxy`, `libxkbcommon`, `libcurl-gnutls` (and with it Kerberos, LDAP and
  GnuTLS), `libsystemd`, `libxml2`, `libfontconfig`, `libharfbuzz`, image codecs.

Stripped, the client is about 14 MB (242 MB with debug information, which is not
shipped).

**Consequences.** Removing the GTK *launcher* does not remove GTK from the
client: upstream's `cordial-runtime` depends on `gtk4` and `libadwaita`
directly, and initialises libadwaita and builds a window even on the Wayland
backend. A GTK-free manager is delivered; **a GTK-free client is not possible
without changing upstream**, short of its X11 backend, which has no sign-in and no
web views and was not attempted. No desktop environment is needed or installed,
but the GTK libraries must be.

## `--headless` is a nested compositor, not "no rendering"

Upstream's `--headless` re-executes the client under `cage` with
`WLR_BACKENDS=headless`. The pid that was started becomes `cage`; `cordial-run` is
its child. It draws: the window, the swapchain, the presents and the compositor
surface all exist, just not on any display. **This project does not claim zero
rendering.** Upstream measured it working (about one present per second when idle,
which is the engine's own idle throttle, not a frame rate) and records that Xvfb
and `mutter --headless` do not work; there is no fallback to either here.

Each client gets its own `cage`, its own `XDG_RUNTIME_DIR` (so its own Wayland
socket and control sockets) and its own environment. A compositor shared by
several clients was considered and rejected: `cage` serves one client (it is a
kiosk compositor), a shared one would make every client's window and lifecycle
depend on one process, and a crash would take the group with it.

## What the manager adds

* `cordial-run --headless` is the only arrangement started (`engine.compositor =
  "cage"`); `"external"` uses a display the environment already provides and
  starts nothing.
* `DISPLAY`/`WAYLAND_DISPLAY` are not inherited; the environment is built from
  nothing for every client.
* Software drawing for machines without a GPU: [gpu-less.md](gpu-less.md).

## Not verified

`cage` on a machine without a GPU is recorded nowhere upstream (only that a CPU
Vulkan device "works and the GPU is not being used"). That combination, the exact
process exit behaviour of `cage` and how many Wayland sockets it can pick are
**unverified**; the manager gives each instance its own runtime directory so the
last one does not matter.
