# The gateway (your VPS)

The home server has no fixed address and cannot take inbound connections. The
VPS does both jobs a gateway needs: it is the far end of every group's tunnel and
it is where the traffic appears to come from. **Nothing here is applied for you.**
`hrdctl gateway plan` writes files; you read them and apply them on the VPS.

## What you need from the provider

* One public address per group you want a distinct exit for (20 accounts per
  address and 15 groups is *your* layout, not a platform rule). The VPS cannot
  create addresses: the provider must assign them and route them to the VPS, and
  they must be configured on the public interface.
* Packet forwarding allowed on the VPS and the provider not filtering
  source-translated traffic.

## Plan

```
hrdctl network set de-1 --exit-ip 203.0.113.11      # per network, the address you expect
hrdctl gateway plan --out ./gw --interface wg-clients --listen-port 51820 \
        --address 10.66.0.1/16 --uplink eth0
```

Every group needs its own tunnel address in the imported file (for example
`10.66.1.2/32` for g01, `10.66.2.2/32` for g02): the plan maps *tunnel address ->
public address* explicitly, in one nftables table, and **drops** traffic from any
tunnel address that is not in the map instead of translating it to a default.
The output:

* `<interface>.conf` (for the example, `wg-clients.conf`) - the gateway's WireGuard interface with one `[Peer]` per
  group (their client public keys are derived by the helper from the imported
  private keys). No `PostUp`/`PostDown` lines: nothing is run from a config file.
* `hrd-gateway.nft` - forward/SNAT rules, default-drop, per group.
* `99-hrd-gateway.conf` - a sysctl drop-in: `net.ipv4.ip_forward = 1` and nothing else.
* `README-gateway.txt` - the exact commands to apply and to undo, and warnings: a preshared
  key in an imported file must be put on the gateway's peer by hand.

Read them before use. The VPS is also your only way in; apply nothing to it over
the same connection you cannot afford to lose without a console.

## Reaching the panel through the VPS

The optional panel ([panel.md](panel.md)) runs on the home server. To open it
from a browser at `https://<VPS address>:<port>` the VPS forwards that port
through a management tunnel to the home server:

```
hrdctl gateway plan ... --panel-target 10.66.0.2 --panel-port 24817 \
        --panel-allow 198.51.100.7/32 --panel-mgmt-key <management peer public key>
```

`--panel-allow` is required: an admin interface is not forwarded to the whole
Internet. The panel is still protected by TLS and a login token; the allow-list
is an extra layer, not a substitute.

## Verifying

After applying on the gateway and on the home server (`hrdctl network apply`):
`hrdctl network list` shows the latest handshake age, `hrdctl network
check NAME` shows the observed exit next to the configured one. Neither has been
run against a real gateway by this project.
