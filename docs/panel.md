# The web panel (optional)

Two pages. **Konta** (accounts): one card per account with its state, memory and CPU
and one main button (Start, Stop or Zaloguj depending on the state), a Place ID
field that is remembered in your browser, and "Zatrzymaj wszystko". **Ustawienia**
(settings): Roblox (installed versions, automatic updates, check now, install from
APK files), the secret store, groups and networks, and an advanced section with
the doctor and every daemon setting. The page is in Polish. Everything it does is
also a `cordialctl` command (see operations.md).

The panel lets you do from a browser what `cordialctl` does: fleet status and
statistics, accounts and the sign-in screen, groups, networks (listing, applying; defining a WireGuard
network needs root and is done with `sudo cordialctl network add`), the Roblox runtime (including uploading an APK),
settings, the secret store, and the doctor. It is **off until you set it up**, is
a separate program (`cordial-panel`) and a separate service, and has no authority
beyond what the control socket gives any member of the service group: it is a
client of that socket, as the same unprivileged user. It cannot define a WireGuard
network (that needs root: `sudo cordialctl network add`), cannot change the
protected settings (see security.md) and needs the file-based token to log in.

## Set it up

```
sudo -u cordial cordial-panel init --listen 10.66.0.2 --san 203.0.113.5
```

* `--listen` is where it listens. `127.0.0.1` = this machine only (reach it with
  `ssh -L 24817:127.0.0.1:24817 server`). An address on your management tunnel
  is how a browser reaches it through the VPS. Listening on all addresses
  (`0.0.0.0`) works and prints a warning: it puts a login page on the Internet.
* The **port is random** (20000-59999, checked free) unless you pass `--port`.
* `--san` adds names or addresses to the certificate (the VPS's public address if
  you will open it there).
* It prints, once: the URL, a **login token** (256 random bits; only its SHA-256
  is stored) and the certificate's SHA-256 fingerprint. `cordial-panel show`
  prints the URL and fingerprint again; `cordial-panel reset-token` makes a new
  token; the running panel adopts it at the next login attempt and ends every
  session opened with the old one.

```
sudo systemctl enable --now cordial-panel
```

Open the URL. The certificate is self-signed, so the browser warns; compare its
fingerprint with the one `init` printed before accepting. Enter the token.

## Reaching it by typing the VPS address

The home server cannot take inbound connections, so a browser at
`https://<VPS address>:<port>/` reaches it through the VPS: the gateway forwards
that port over a management WireGuard tunnel to the address the panel listens on.
`cordialctl gateway plan ... --panel-target <home address on the tunnel>
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
  1 GiB, stored in a private directory and deleted after the import).
* Logs contain the method, path and status, never a body, a query or a cookie.
  Passwords typed into the sign-in screen and passphrases are sent once and are
  not kept.
* The service is hardened (no new privileges, no capabilities, read-only system).

## What to be careful about

Whoever has the token can do everything the manager can, including starting
clients, importing a network and typing into a sign-in client. Treat it like the
SSH key to the machine. A login page reachable from the whole Internet will be
found and attacked; use the allow-list and, better, a tunnel. The panel has been
exercised over real TLS with `curl` against a scratch daemon (login, lockout, CSRF,
headers, forwarding) and its page was loaded in a headless browser; it has not
been security-reviewed by anyone else.
