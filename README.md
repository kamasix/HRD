# HRD

HRD runs many independent [Cordial](https://github.com/luohoa97/cordial) clients
on a Debian server, from the terminal or a small web panel, each with its own
profile, process set and network exit, for your own accounts in your own
experiences. Cordial runs Roblox's official Android build natively on Linux; HRD
does not touch the engine, it manages the processes around it.

**Read [docs/status.md](docs/status.md) first.** It says what is implemented, what
was only compiled, and what could not be verified because no Roblox client,
account, GPU, WireGuard-capable kernel or systemd was available while this was
written. Nothing has been run against the real engine. There is no measurement of
a client's memory here, no claim of ~1 MB per session and no claim that 300
clients run anywhere; 300 is the manager's design target.

## What it is

| | |
|---|---|
| `hrdd` | the one daemon: registry, start queue with memory- and pressure-aware admission, per-instance state machine, process sets in cgroups, stats, the secret store |
| `hrdctl` | the command line (`--json` everywhere) and `hrdctl tui` |
| `hrd-panel` | optional HTTPS web panel on a random port, login token |
| `hrd-netd` | the only root component: per-group network namespaces + WireGuard + fail-closed firewall |
| `hrd-enter` | static launcher with one file capability; enters a group's namespace, drops everything, runs the client |
| `hrd-import` | verifies and installs the Roblox Android build you provide |
| `patches/cordial/` | three small patches to a build copy of the pinned upstream client |

## What it does not do

No injector or script execution, no synthetic input or anti-AFK for playing
clients, no bypassing of protections, CAPTCHA, bans or limits, no account
creation, no IP rotation, and **no automatic reconnect or restart**: a
disconnected, failed or signed-out client keeps its state and reason and waits for
your command. The daemon starts with no clients and starts one only when told to.

## Quick start (Debian 13)

```
sudo apt install ./hrd_*.deb ./hrd-client_*.deb cage mesa-vulkan-drivers
sudo hrdctl init && sudo systemctl enable --now hrd-netd hrdd
hrdctl doctor
hrdctl secrets unlock --create
hrdctl runtime import --apk ~/roblox/
hrdctl account add alt-01 && hrdctl account login alt-01
sudo hrdctl network add de-1 --wireguard-config de-1.conf --exit-ip 203.0.113.11
hrdctl group create g01 --network de-1 --capacity 20
hrdctl group assign g01 --accounts g01.txt
hrdctl network apply
hrdctl group start g01 --place-id 1234567890 && hrdctl status
```

## Documents

[install](docs/install.md) · [operations](docs/operations.md) · [architecture](docs/architecture.md) ·
[memory](docs/memory.md) · [headless](docs/headless.md) · [server without a GPU](docs/gpu-less.md) ·
[networking](docs/networking.md) · [gateway](docs/gateway.md) · [accounts](docs/accounts.md) ·
[stats](docs/stats.md) · [panel](docs/panel.md) · [security](docs/security.md) ·
[build](docs/build.md) · [testing](docs/testing.md) · [status](docs/status.md) ·
[BASELINE](BASELINE.md) · [NOTICE](NOTICE.md)

Licence: GPL-3.0-or-later ([LICENSE](LICENSE)); upstream Cordial is GPL-3.0 too.

## Po polsku (skrót)

HRD to menedżer wielu klientów Cordial (terminal przez SSH i opcjonalny panel WWW) dla Debiana, dla własnych kont i
własnych experiences: jeden daemon `hrdd`, CLI `hrdctl` (+ TUI), opcjonalny
panel WWW (losowy port, HTTPS, token — `docs/panel.md`), grupy sieciowe z
przestrzenią nazw i WireGuard (fail-closed), bezpieczny magazyn sesji (keyring
odblokowywany hasłem po każdym restarcie), kolejka startów z kontrolą pamięci, tryby
`compatible/minimal/aggressive`. Działa na serwerze **bez karty graficznej**
(rysowanie na CPU: `docs/gpu-less.md`; uczciwie: na 4 rdzeniach zmieści się
niewiele klientów, a 300 to cel skalowania managera, nie obietnica). Niczego nie
uruchamiano z prawdziwym silnikiem Roblox — `docs/status.md` rozróżnia
zaimplementowane / skompilowane / niezweryfikowane. Nie ma automatycznego
reconnectu, rotacji IP, anti-AFK ani wstrzykiwania kodu: po rozłączeniu zostaje stan i
powód, a ponowny start wymaga Twojej komendy.
