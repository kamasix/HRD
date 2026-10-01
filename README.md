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

## How it is organised

A **group** is one game: a name and its Place ID. A group holds **proxy groups**,
and each proxy group is one **proxy** (a WireGuard tunnel to an exit address) with
the Roblox **accounts** that leave through it. The panel's main screen is exactly
that, and `hrdctl tree` prints it:

```
adopt-me  place 920587237  mode -  (14 account(s), 11 live)
  de-1  proxy de-1  ready  12/20 account(s)
    alt-01  connected
    alt-02  stopped
    ...
  nl-1  proxy nl-1  ready  2/5 account(s)
    nl-01  stopped
    nl-02  stopped
```

Start and Stop work at every level: a group, a proxy group, or one account. A
start joins the place of the account's group.

## What it is

| | |
|---|---|
| `hrdd` | the one daemon: registry, start queue with memory- and pressure-aware admission, per-instance state machine, process sets in cgroups, stats, the secret store |
| `hrdctl` | the command line (`--json` everywhere) and `hrdctl tui` |
| `hrd-panel` | optional HTTPS web panel on a random port, login token |
| `hrd-netd` | the only root component: per-proxy-group network namespaces + WireGuard + fail-closed firewall |
| `hrd-enter` | static launcher with one file capability; enters a proxy group's namespace, drops everything, runs the client |
| `hrd-import` | verifies and installs the Roblox Android build you provide |
| `patches/cordial/` | three small patches to a build copy of the pinned upstream client |

## What it does not do

No injector or script execution, no synthetic input or anti-AFK for playing
clients, no bypassing of protections, CAPTCHA, bans or limits, no account
creation, no IP rotation, and **no automatic reconnect or restart**: a
disconnected, failed or signed-out client keeps its state and reason and waits for
your command. The daemon starts with no clients and starts one only when told to.
A proxy is a WireGuard tunnel; HTTP and SOCKS proxies are not supported (the game's
UDP cannot go through a TCP-only proxy).

## Quick start (Debian 13)

```
sudo apt install ./hrd_*.deb ./hrd-client_*.deb cage mesa-vulkan-drivers
sudo hrdctl init && sudo systemctl enable --now hrd-netd hrdd
hrdctl doctor
hrdctl secrets unlock --create
hrdctl runtime fetch                              # or: runtime import --apk ~/roblox/
hrdctl group create adopt-me --place-id 1234567890
sudo hrdctl proxy add de-1 --wireguard-config de-1.conf --exit-ip 203.0.113.11
hrdctl proxy-group create de-1 --group adopt-me --proxy de-1 --capacity 20
hrdctl proxy-group assign de-1 --accounts alt.txt --create-missing
hrdctl proxy apply
hrdctl account login alt-01                       # you type the password
hrdctl group start adopt-me && hrdctl tree
```

The same, in a browser: `sudo -u cordial hrd-panel init --listen 127.0.0.1`, then
`sudo systemctl enable --now hrd-panel` ([docs/panel.md](docs/panel.md)).

## Documents

[install](docs/install.md) · [operations](docs/operations.md) · [architecture](docs/architecture.md) ·
[memory](docs/memory.md) · [headless](docs/headless.md) · [server without a GPU](docs/gpu-less.md) ·
[networking](docs/networking.md) · [gateway](docs/gateway.md) · [accounts](docs/accounts.md) ·
[stats](docs/stats.md) · [panel](docs/panel.md) · [security](docs/security.md) ·
[build](docs/build.md) · [testing](docs/testing.md) · [status](docs/status.md) ·
[BASELINE](BASELINE.md) · [NOTICE](NOTICE.md)

Licence: GPL-3.0-or-later ([LICENSE](LICENSE)); upstream Cordial is GPL-3.0 too.

## Po polsku (skrót)

HRD to menedżer wielu klientów Cordial (terminal przez SSH i opcjonalny panel WWW)
dla Debiana, dla własnych kont i własnych experiences. Układ jest trzypoziomowy:
**grupa** (jedna gra: nazwa i Place ID) → **grupy proxy** (każda to jeden proxy,
czyli tunel WireGuard, i konta, które przez niego wychodzą) → **konta Roblox**.
Start i stop działają na każdym poziomie, a start bierze Place ID z grupy konta.
Jeden daemon `hrdd`, CLI `hrdctl` (+ TUI), panel WWW (losowy port, HTTPS, token —
`docs/panel.md`; główny ekran to właśnie ta hierarchia, a proxy dodaje się w nim
plikiem WireGuard, jeśli root to dopuścił w `netd.toml`), przestrzeń nazw i
WireGuard na każdą grupę proxy (fail-closed), bezpieczny magazyn sesji (keyring
odblokowywany hasłem po każdym restarcie), kolejka startów z kontrolą pamięci,
tryby `compatible/minimal/aggressive`. Proxy to tylko WireGuard: proxy HTTP/SOCKS
nie są obsługiwane (UDP gry nie przejdzie przez proxy TCP). Działa na serwerze
**bez karty graficznej** (rysowanie na CPU: `docs/gpu-less.md`; uczciwie: na 4
rdzeniach zmieści się niewiele klientów, a 300 to cel skalowania managera, nie
obietnica). Niczego nie uruchamiano z prawdziwym silnikiem Roblox —
`docs/status.md` rozróżnia zaimplementowane / skompilowane / niezweryfikowane. Nie
ma automatycznego reconnectu, rotacji IP, anti-AFK ani wstrzykiwania kodu: po
rozłączeniu zostaje stan i powód, a ponowny start wymaga Twojej komendy.
Katalogi na serwerze (`/var/lib/cordial-hrd` itd.) i użytkownik `cordial` zostały
pod starymi nazwami celowo — klient zapisuje sesje logowania pod pełną ścieżką
profilu, więc zmiana katalogu wylogowałaby wszystkie konta (`docs/install.md`).
