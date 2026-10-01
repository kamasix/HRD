# The web panel (optional)

Two pages. The page is in Polish; everything it does is also an `hrdctl` command
(see [operations.md](operations.md)).

**Grupy** is the main screen and is the hierarchy HRD keeps:

```
adopt-me   Place [ 920587237 ]                       12/25 połączonych   Start Stop ⋯
  de-1   ● proxy gotowe  203.0.113.11   12/20 połączonych · limit 20     Start Stop ⋯
     alt-01   ● połączony   10 min · 280 MB · 3%                          Stop ⋯
     alt-02   ● zatrzymany                                               Start ⋯
     + Dodaj konta
  nl-1   ● proxy gotowe  ...
  + Dodaj proxy
```

* a **group** is one game: its name and its **Place ID**, typed in its header (saved
  when you leave the field or press Enter), and Start and Stop for everything in it.
  Its menu (⋯) holds the resource mode and a note, and removal;
* inside it, one **proxy group** per proxy: whether the proxy is ready, unverified,
  not applied or broken, the exit address, how many of its accounts are connected
  and its limit, and Start and Stop for that proxy group. Its menu: settings (limit,
  move to another group, expected exit address, STUN server), check the exit, apply,
  remove. A proxy group with many accounts starts collapsed; the page remembers
  what you opened;
* inside that, the **accounts**: state, how long it has run, memory and CPU, one main
  button (Start, Stop or Zaloguj) and a menu: details, log, sign in again, sign out,
  move to another proxy group, take out of its group, remove;
* **Bez grupy** lists accounts that are in no proxy group, each with an assign button.

A start without anything else joins the place of the account's group. Start on a
group queues every account in all its proxy groups; the scheduler paces them
([operations.md](operations.md)). A group with no Place ID yet cannot be started:
the page puts the cursor in the field.

"+ Nowa grupa" creates a group (type "Adopt Me" and the name becomes `adopt-me`),
"+ Dodaj proxy" adds a proxy group to a group, "+ Dodaj konta" adds accounts to a
proxy group (one name per line, or separated by commas; a name that already exists is moved in).

**Ustawienia** has four sections: Roblox (installed versions, automatic updates,
check now, install from APK files), the secret store, Proxy (every defined proxy,
which proxy group uses it, plan and apply the network changes) and an advanced one
with the doctor and every daemon setting.

## Adding a proxy

A **proxy** is a WireGuard tunnel: the `.conf` file your VPN or gateway provider
gives you ([networking.md](networking.md)). In a group, "+ Dodaj proxy" asks for the
name, the file (or its pasted text), the exit address you expect and the limit of
accounts. HRD hands the file to the network helper, which keeps its private key in
a root-only directory, creates a proxy group of the same name in that group and
applies it. Or pick a proxy defined earlier that no proxy group uses. A name that is already a proxy is refused, by the page and by the panel itself, because adding over it would replace its key.

**Whether the panel may do this is decided in `netd.toml`, by root.** A proxy decides
where the traffic of every account behind it goes, and the file carries a private
key, so the helper accepts a new proxy only from root unless you set

```
allow_service_define = true     # /etc/cordial-hrd/netd.toml, then: sudo systemctl restart hrd-netd
```

Left off (the default) the panel says so, instead of showing a form that cannot work,
and names the terminal command: `sudo hrdctl proxy add NAME --wireguard-config
FILE.conf`. A proxy added that way appears under "Zdefiniowane wcześniej". With the
setting on, anyone who can sign in to the panel can define proxies: see
[security.md](security.md).

HTTP and SOCKS proxies are not supported. The game talks UDP and a TCP-only proxy
cannot carry it ([networking.md](networking.md)).

## Set it up

```
sudo -u cordial hrd-panel init --listen 10.66.0.2 --san 203.0.113.5
```

* `--listen` is where it listens. `127.0.0.1` = this machine only (reach it with
  `ssh -L 24817:127.0.0.1:24817 server`). An address on your management tunnel
  is how a browser reaches it through the VPS. Listening on all addresses
  (`0.0.0.0`) works and prints a warning: it puts a login page on the Internet.
* The **port is random** (20000-59999, checked free) unless you pass `--port`.
* `--san` adds names or addresses to the certificate (the VPS's public address if
  you will open it there).
* It prints, once: the URL, a **login token** (256 random bits; only its SHA-256
  is stored) and the certificate's SHA-256 fingerprint. `hrd-panel show`
  prints the URL and fingerprint again; `hrd-panel reset-token` makes a new
  token; the running panel adopts it at the next login attempt and ends every
  session opened with the old one.

```
sudo systemctl enable --now hrd-panel
```

Open the URL. The certificate is self-signed, so the browser warns; compare its
fingerprint with the one `init` printed before accepting. Enter the token.

It is **off until you set it up**, is a separate program (`hrd-panel`) and a
separate service, and has no authority beyond what the control socket gives any
member of the service group: it is a client of that socket, as the same
unprivileged user. It cannot change the protected settings (see security.md) and
needs the file-based token to log in. The one thing it asks the network helper
for that `hrdctl` does as root is defining a proxy, and only when
`allow_service_define` is on.

## Reaching it by typing the VPS address

The home server cannot take inbound connections, so a browser at
`https://<VPS address>:<port>/` reaches it through the VPS: the gateway forwards
that port over a management WireGuard tunnel to the address the panel listens on.
`hrdctl gateway plan ... --panel-target <home address on the tunnel>
--panel-port <port> --panel-allow <your network> --panel-mgmt-key <key>` writes
those rules ([gateway.md](gateway.md)); the allow-list is mandatory, and nothing
is applied for you.

## Protection

* TLS only (rustls). No plain-HTTP listener.
* One secret token; sessions are random server-side values in an `HttpOnly;
  Secure; SameSite=Strict` cookie (12 hours, 2 hours idle, at most 16).
* Five wrong tokens from one address lock that address out for ten minutes
  (even for the right token), every wrong answer is delayed a second.
* Every state-changing request must carry a CSRF header the page received at
  login and an `Origin` equal to the page's own; a request with neither is
  refused.
* The page loads only its own script and stylesheet (Content-Security-Policy
  `default-src 'none'`), builds all text with `textContent`, cannot be framed.
* The daemon's own controls are all available except the ones that cannot be
  done safely from a page: stopping the daemon, streams, and sending files
  through the JSON route (uploads have their own route, limited to 4 files of
  1 GiB, stored in a private directory and deleted after the import). A
  WireGuard file typed or chosen in the page is sent once over HTTPS to the
  panel, handed to the helper and not kept: the panel writes it nowhere and the
  page clears it.
* Logs contain the method, path and status, never a body, a query or a cookie.
  Passwords typed into the sign-in screen and passphrases are sent once and are
  not kept.
* The service is hardened (no new privileges, no capabilities, read-only system).

## What to be careful about

Whoever has the token can do everything the manager can, including starting
clients and typing into a sign-in client, and, with `allow_service_define` on,
defining a proxy. Treat it like the SSH key to the machine. A login page reachable
from the whole Internet will be found and attacked; use the allow-list and, better,
a tunnel. The page was exercised in headless Chromium against a real `hrdd` and
`hrd-panel` (with a stand-in for the network helper, which cannot run in the
sandbox it was written in) and over TLS with `curl`. Separate automated review
passes read it and their findings were fixed; no person has security-reviewed it.
