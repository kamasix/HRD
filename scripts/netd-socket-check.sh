#!/bin/bash
# The real hrd-netd binary, started as root, and a client that has dropped to the service
# user: the socket must be reachable by that user and by root, and defining a proxy must be
# refused to the service user (allow_service_define is off) and not to root.
#
#   scripts/netd-socket-check.sh [DIR_WITH_THE_BINARIES]     (root; needs unshare and python3)
#
# `ip`, `wg` and `nft` are replaced by empty stand-ins, visible only inside a private mount
# namespace, so that the helper starts on a machine that has none of them. The helper then does
# nothing to the network: this checks the socket and the permission rule, not WireGuard.
set -u
BIN=${1:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 2; }
[ -x "$BIN/hrd-netd" ] || { echo "no $BIN/hrd-netd: build it first (cargo build -p hrd-netd)"; exit 2; }
T=$(mktemp -d /dev/shm/hrd-netd-check.XXXXXX)
trap 'rm -rf "$T"' EXIT
chmod 755 "$T"
mkdir -p "$T/stub" "$T/root"
chmod 755 "$T/root"
for t in ip wg nft; do printf '#!/bin/sh\nexit 0\n' > "$T/stub/$t"; chmod 755 "$T/stub/$t"; done
printf 'service_user = "nobody"\nservice_group = "nogroup"\n' > "$T/netd.toml"
printf 'service_user = "nobody"\nservice_group = "no-such-group-here"\n' > "$T/bad-group.toml"
chmod 644 "$T/netd.toml" "$T/bad-group.toml"

cat > "$T/client.py" <<'PY'
import json, os, socket, sys
path, who = sys.argv[1], sys.argv[2]
if who == "service":
    os.setgid(65534); os.setuid(65534)
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
try:
    s.connect(path)
except OSError as e:
    print(f"{who}: cannot connect: {e}"); sys.exit(1)
f = s.makefile("rw")
def ask(i, cmd, args=None):
    req = {"id": i, "cmd": cmd}
    if args is not None: req["args"] = args
    f.write(json.dumps(req) + "\n"); f.flush()
    return json.loads(f.readline())
ping = ask(1, "ping")
define = ask(2, "put_network", {"name": "x1", "config": "[Interface]\nPrivateKey = x\n", "dns": []})
print(json.dumps({"ping_ok": ping.get("ok"), "service_define": (ping.get("data") or {}).get("service_define"),
                  "define_error": (define.get("error") or {}).get("code")}))
PY

out=$(unshare -m bash -c '
  mount --bind "'"$T"'/stub" /usr/sbin || { echo "cannot mount the stand-in tools"; exit 2; }
  "'"$BIN"'/hrd-netd" --root "'"$T"'/root" --config "'"$T"'/netd.toml" > "'"$T"'/netd.log" 2>&1 &
  pid=$!
  S="'"$T"'/root/run-netns/netd.sock"
  for i in $(seq 1 20); do [ -S "$S" ] && break; sleep 0.2; done
  echo "socket $(stat -c "%a %U:%G" "$S")"
  echo "service $(python3 "'"$T"'/client.py" "$S" service)"
  echo "root $(python3 "'"$T"'/client.py" "$S" root)"
  kill $pid; wait $pid 2>/dev/null
  "'"$BIN"'/hrd-netd" --root "'"$T"'/root2" --config "'"$T"'/bad-group.toml" > "'"$T"'/bad.log" 2>&1
  echo "missing-group exit $? $(head -c 160 "'"$T"'/bad.log" | tr "\n" " ")"
')
echo "$out"
fail=0
check() { if echo "$out" | grep -q "$1"; then echo "  ok: $2"; else echo "  FAILED: $2"; fail=1; fi; }
check '^socket 660 root:nogroup' "the socket is 0660, root, and the service group's"
check '^service {"ping_ok": true, "service_define": false, "define_error": "denied"}' "the service user connects, and may not define a proxy"
check '^root {"ping_ok": true, "service_define": false, "define_error": "invalid"}' "root connects, and gets past the permission rule to the file check"
check '^missing-group exit [1-9][0-9]* .*does not exist' "a service group that does not exist stops the helper with a message, instead of a socket nobody can reach"
[ $fail -eq 0 ] && echo "netd socket check: ok" || { echo "netd socket check: FAILED"; exit 1; }
