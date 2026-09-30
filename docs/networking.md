# Network groups

A **group** is a set of accounts (your organisational unit, for example 20 per
exit address; the number is yours, not a Roblox limit) and at most one
**network**: a WireGuard tunnel the group's clients leave through. A network
belongs to one group, because two interfaces with one key would fight over the
gateway's endpoint for that key.

## What "through the tunnel" means here

Each group gets its own Linux **network namespace**. The namespace contains the
loopback interface and one WireGuard interface, `wg0`, nothing else. A client
starts inside it (`cordial-enter`). Everything the client or any process it
starts does (initialisation, sign-in, HTTPS, the game's UDP, DNS, helpers) goes
out through `wg0` or goes nowhere, because there is no other interface. This is
a property of the namespace, not of a proxy setting.

Fail-closed, concretely:

* the namespace's firewall (`nft`, installed **before** any address or route) has
  a default-drop policy on input, output and forward and accepts only `lo` and
  `wg0`; if the tunnel is down, packets are dropped and the client has no
  connectivity. Nothing falls back to the server's own link;
* a group with no tunnel is refused at start (`network.allow_unrouted = false`);
* `cordial-enter` will not run a client if the namespace handle is missing or not
  root-owned, and `cordial-enter check` (also wired to upstream's per-profile
  `network.json` gate) verifies from inside the client that the only interfaces
  are `lo` and `wg0`;
* DNS: the namespace's `resolv.conf` and `nsswitch.conf` are generated and
  overlaid in the client's private mount namespace (`hosts: files dns`), and the
  `nscd` and `systemd-resolved` sockets are masked, so name lookups cannot leave
  through the host's resolver (which would reach the host's network across
  namespaces). The group's DNS server must be reachable *through* the tunnel;
  an imported network without one is refused;
* IPv6: if the WireGuard file carries an IPv6 address and a `::/0` route it goes
  through the tunnel under the same rules; otherwise, or with `--block-ipv6`,
  it is dropped in the namespace. Nothing IPv6 leaves by another path;
* nothing changes the exit after a kick or an auth error. There is no rotation.

`HTTP_PROXY`-style settings are not isolation and are not used. A TCP-only proxy
cannot carry the game's UDP and is not a backend. SOCKS5 with real UDP
ASSOCIATE is not implemented.

## The privileged helper

`cordial-netd` is root with `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and `CAP_CHOWN` and
`no_new_privs`. It holds the WireGuard private keys in `/var/lib/cordial-hrd-netd`
(root, `0700`/`0600`); the keys never pass through the daemon or appear in any
registry file, argument or log. The manager can ask it only to store a network
under a name, to plan or apply a *list of (group, network) pairs*, to tear a
group down, to report status and to probe the exit. It cannot give the helper an
address, a path, a route or a command; all of those are derived from the stored
file. External programs (`ip`, `wg`, `nft`) are found in system directories,
required to be root-owned, and run with argument vectors and a cleared
environment. `PostUp`, `PreDown` and every other unknown field of an imported file
are **rejected** (the file is not run or partly used); only `PrivateKey`,
`Address`, `DNS`, `MTU`, `ListenPort` and, for the single peer, `PublicKey`,
`PresharedKey`, `AllowedIPs`, `Endpoint`, `PersistentKeepalive` are read.

The helper only touches its own objects: namespaces under
`/run/cordial-hrd-netns`, the interfaces and nft table inside them, and its own
files. It does not edit the host's firewall, routes or SSH path. Applying is
idempotent (a desired-state hash per group; an unchanged group is left alone) and
removal is idempotent.

## Commands

```
sudo cordialctl network add de-1 --wireguard-config de-1.conf --exit-ip 203.0.113.11 [--stun-server HOST:PORT]
cordialctl group create g01 --network de-1 --capacity 20
cordialctl group assign g01 --accounts g01.txt
cordialctl network plan        # what apply would do; changes nothing
cordialctl network apply       # does it, for groups with no live client
cordialctl network check de-1  # observed exit, see below
cordialctl network list
```

`network apply` never rebuilds a group that has live clients (a rebuild would cut
them off); stop them first. `apply` with `--no-prune` leaves namespaces of
removed groups alone.

## Configured exit and observed exit

The address you tell the manager a group leaves from (`--exit-ip`) is what you
**configured**; nothing verifies it. `network check` sends a STUN binding request
from inside the group's namespace, to a server **you** named with
`--stun-server` (the manager never contacts a third party you did not name), and
records the address the far end saw as the **observed** exit, with the time and
the server. Both are shown, side by side. A STUN reply proves that UDP works out
of that namespace and from which address; it does not prove that a game server
will accept that address, and an HTTPS check would not prove UDP at all.

## Limits

* The VPS cannot create public addresses; every exit address must already be
  routed to it by the provider. [gateway.md](gateway.md).
* One WireGuard peer per imported file.
* The namespace/firewall/DNS logic was exercised in a sandbox on real namespaces
  using a veth pair as a stand-in for `wg0`, because the sandbox kernel has no
  WireGuard. **Creating a real WireGuard device and completing a handshake has
  not been run.** See [status.md](status.md).
