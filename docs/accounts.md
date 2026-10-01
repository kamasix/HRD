# Accounts, sign-in and sessions

An **account** here is a profile for one of your own Roblox accounts: a name
(`[a-z0-9-]`, up to 32 characters, because a socket path inside the profile has
to fit 107 bytes), labels, a note, an optional group, an optional resource mode.
Nothing is created at Roblox. There is no account generation.

```
hrdctl account add alt-01 --label batch1 --group g01
hrdctl account login alt-01          # you type the password
hrdctl account list
hrdctl account logout alt-01         # erase the stored session
hrdctl account remove alt-01         # asks you to type the name
hrdctl account export --file accounts.json     # names, labels, groups: no secrets
hrdctl account import accounts.json
```

## Where a session lives

Upstream Cordial keeps a profile's cookie jar and identity in the **Secret
Service**, keyed by the profile's absolute path, or, in its other modes, in a
plain 0600 file; with its default setting it silently falls back to that plain
file when no service is usable. The engine itself never writes the session to
disk (upstream measured this). So the manager:

* starts a **private session bus and a headless `gnome-keyring-daemon`** on it
  (no desktop, no login session);
* points every client at that bus and sets `CORDIAL_SECRET_STORE=keyring`, which
  refuses the plain-file fallback and saves nothing rather than fall back;
* has you unlock it with a passphrase after every reboot
  (`hrdctl secrets unlock`, `--create` the first time). The passphrase goes to
  the keyring on its standard input, is not in any argument, is not written
  anywhere, and the keyring file is encrypted with it. **Nothing on disk holds the
  key.** Forget it and the stored sessions are unreadable; accounts sign in again;
* never reads a secret: it asks the service whether an item exists and asks it to
  delete one, through `busctl`, which prints object paths and no values;
* looks for plain `cookies`/`identity` files in profiles (`doctor`) and reports
  them as a failure if they ever appear.

`secrets.backend = none` is not usable: upstream has no mode that means "store
nothing" other than the failing keyring mode, and its only other store is
plaintext, so the manager refuses to start clients in it rather than approximate.

Same-user caveat: every client runs as the same Unix user and can reach the same
bus, so a compromised client could ask for another profile's item. Per-profile
keying separates honest clients, not hostile ones ([security.md](security.md)).

## Session states (`account list`)

| state | meaning |
|---|---|
| `none` | nothing is stored |
| `stored` | an item exists in the keyring; **not** proof that Roblox still accepts it |
| `verified` | a client of this account was seen signed in (`app ready: Home`) |
| `required` | a client reached the sign-in screen, or reported a sign-out |
| `unknown` | not determined (the keyring was locked when asked) |

`instance start` refuses an account that is `none` or `required` and sets it to
the instance state `auth_required` with the reason. A client that reaches the
sign-in screen while playing is stopped and set to `auth_required`; it is never
signed in again automatically.

## Signing in

Sign-in is upstream's own Lua screen inside the client; Cordial has no function
that drives it. Passwords, codes, and any puzzle or confirmation are yours to
provide. `hrdctl account login NAME`:

1. queues a special **sign-in client** for the account through the account's
   group network (a login from another address than the client will play from is
   avoided), at full resolution;
2. when it reaches its first screen, opens the **console**: the client's current
   frame drawn in the terminal (half-block characters with rulers in frame pixels)
   and a prompt. You type `click X Y`, `type TEXT`, `password` (read without echo,
   sent once, never stored or logged), `key enter|tab|...`, `shot`, `detach`,
   `quit`. Each line you enter is one action; nothing repeats, nothing is scripted,
   no timer sends anything;
3. when the client reports a signed-in screen the session ends and the stored
   session is checked.

The console is a thin relay to a development control surface Cordial already has
(a Unix socket inside the instance's private runtime directory, created **only**
for sign-in runs; clients that play never have one). It is the only place in this
project that sends input to a client, it needs you at the keyboard, and it can be
switched off (`login.console = false`; then sign in on a machine with a display).
The full-resolution PNG is saved for `scp` while the console is open.

**Unverified:** that Quick Sign-in or a password screen can be completed this way
on a headless client, that CAPTCHA or another web-view step renders in the frame
that is captured, and that the session then persists in the keyring. All of it
depends on the real engine and was not run.
