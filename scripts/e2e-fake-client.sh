#!/bin/bash
# Exercises cordiald and cordialctl against a FAKE client: a shell script that
# prints the log lines the real client prints. It is not Roblox, contacts
# nothing, and needs no account. What it checks is this project's own logic:
# the queue, the state machine, stop, adoption after a restart, the secret
# store. What it cannot check is anything the real engine does.
#
#   scripts/e2e-fake-client.sh [path-to-target/debug]
#
# Needs: busctl, dbus-daemon, gnome-keyring-daemon, secret-tool. Runs the daemon
# as the current user with --allow-root under a scratch root; touches nothing
# outside it.
set -u
B=${1:-$(dirname "$0")/../target/debug}
B=$(cd "$B" && pwd)
T=$(mktemp -d /tmp/hrd-e2e.XXXXXX)
export CORDIAL_HRD_ROOT=$T/root R=$T/root
mkdir -p "$R/etc" "$R/run"
fail=0
ok() { printf 'PASS  %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; fail=1; }
expect() { # description, command output must contain pattern
  if grep -q -- "$3" <<<"$2"; then ok "$1"; else bad "$1 (wanted: $3)"; echo "$2" | sed 's/^/      /'; fi
}
cleanup() {
  "$B/cordialctl" daemon stop --stop-clients >/dev/null 2>&1; sleep 1
  "$B/cordialctl" secrets lock >/dev/null 2>&1
  for p in $(pgrep -f "$T/root" 2>/dev/null); do [ "$p" != "$$" ] && kill "$p" 2>/dev/null; done
  rm -rf "$T"
}
trap cleanup EXIT

cat > "$R/etc/cordiald.toml" <<CFG
[service]
user = "nobody"
group = "nogroup"
[engine]
compositor = "external"
graphics = "software"
cordial_run = "$T/fake-run"
enter = "$T/fake-enter"
importer = "$T/fake-import"
[network]
allow_unrouted = true
[scheduler]
max_concurrent_starts = 2
min_start_interval_ms = 200
disconnect_grace_s = 3
min_available_mem_mib = 64
assumed_start_peak_mib = 64
max_cpu_pressure_avg10 = 0
max_memory_pressure_avg10 = 0
[stats]
interval_s = 1
pss_interval_s = 2
CFG
cat > "$T/fake-run" <<'FAKE'
#!/bin/sh
name=$(basename "$HOME")
echo "LOADED in 25ms"; sleep 1
case "$name" in
  *-signedout) echo "[roblox] app ready: Landing"; sleep 600 ;;
  *) echo "[roblox] app ready: Home" ;;
esac
sleep 1
echo "[cordial] game: joined place 920587237 (universe 1) as 42"
case "$name" in
  *-kicked) sleep 2
    d="$XDG_DATA_HOME/cordial/profiles/default/data/files/appData/logs"; mkdir -p "$d"
    echo "2026-08-31T03:16:55.333Z,316.3,5b43f6c0,7 [FLog::Network] Disconnection Notification. Reason: 267" >> "$d/client.log"
    sleep 600 ;;
  *-crash) sleep 2; exit 7 ;;
  *) sleep 600 ;;
esac
FAKE
chmod +x "$T/fake-run"
mkdir -p "$R/var/lib/runtime/builds/fake-1"/{engine,apk,assets}
echo x > "$R/var/lib/runtime/builds/fake-1/engine/libroblox.so"; echo x > "$R/var/lib/runtime/builds/fake-1/apk/base.apk"
ln -s builds/fake-1 "$R/var/lib/runtime/current"

"$B/cordiald" --root "$R" --allow-root > "$T/daemon.log" 2>&1 &
sleep 1.5
printf 'correct horse battery' > "$T/pass"; chmod 600 "$T/pass"
out=$("$B/cordialctl" secrets unlock --create --passphrase-file "$T/pass"); expect "keyring is created and unlocked" "$out" "ready"
export DBUS_SESSION_BUS_ADDRESS=unix:path=$R/run/secrets/bus
grep -rl "correct horse" "$R" >/dev/null 2>&1 && bad "the passphrase is on disk" || ok "the passphrase is nowhere on disk"

for a in a1 a2-kicked a3-crash a4-signedout; do
  "$B/cordialctl" account add $a >/dev/null
  printf fake | secret-tool store --label="fake $a" application cordial profile "$R/var/lib/acct/$a/data/cordial/profiles/default" store cookies
done
"$B/cordialctl" account add nosession >/dev/null
"$B/cordialctl" secrets unlock --passphrase-file "$T/pass" >/dev/null; sleep 3
out=$("$B/cordialctl" account list); expect "stored sessions are detected" "$out" "a1 .*stored"
out=$("$B/cordialctl" instance start nosession --place-id 1 2>&1); expect "an account without a session is refused" "$out" "account login nosession"
out=$("$B/cordialctl" status --account nosession); expect "...and becomes auth_required" "$out" "auth_required"

for a in a1 a2-kicked a3-crash a4-signedout; do "$B/cordialctl" instance start $a --place-id 920587237 >/dev/null; done
sleep 12
out=$("$B/cordialctl" status)
expect "a healthy client is connected only after the joined line" "$out" "a1 .*connected"
expect "a disconnect notice with no new join becomes disconnected, with its code" "$out" "a2-kicked .*disconnected.*267"
expect "a client that ends after connecting is disconnected, not restarted" "$out" "a3-crash .*disconnected.*exit code 7"
expect "the sign-in screen makes auth_required" "$out" "a4-signedout .*auth_required"
n=$(pgrep -f "slee[p] 600" | wc -l); [ "$n" -le 1 ] && ok "processes of ended instances are gone" || bad "leftover processes: $n"
sleep 6; out=$("$B/cordialctl" status); expect "nothing was started again" "$out" "a3-crash .*disconnected"

pkill -TERM -x cordiald; sleep 2
"$B/cordiald" --root "$R" --allow-root >> "$T/daemon.log" 2>&1 &
sleep 2
out=$("$B/cordialctl" status --account a1); expect "a running client is adopted after a daemon restart" "$out" "a1 .*connected"
expect "the queue is not restored" "$(cat "$T/daemon.log")" "starting with an empty queue"

for i in 1 2 3 4 5; do "$B/cordialctl" account add q$i >/dev/null; printf x | secret-tool store --label=f application cordial profile "$R/var/lib/acct/q$i/data/cordial/profiles/default" store cookies; done
"$B/cordialctl" secrets unlock --passphrase-file "$T/pass" >/dev/null; sleep 2
for i in 1 2 3 4 5; do "$B/cordialctl" instance start q$i --place-id 1 >/dev/null; done
sleep 0.4; out=$("$B/cordialctl" status --live); expect "starts are paced by the concurrency limit" "$out" "queued"
"$B/cordialctl" instance stop q1 >/dev/null; sleep 3
out=$("$B/cordialctl" status --account q1); expect "an operator stop ends in stopped" "$out" "q1 .*stopped"
"$B/cordialctl" stop-all >/dev/null; sleep 4
out=$("$B/cordialctl" status --live); expect "stop-all leaves nothing live" "$out" "0 instance"
pgrep -af "slee[p] 600" | sed "s/^/      leftover: /" ; n=$(pgrep -f "slee[p] 600" | wc -l); [ "$n" -eq 0 ] && ok "no client process is left" || bad "leftover processes: $n"
[ $fail -eq 0 ] && echo "ALL PASSED" || echo "SOME FAILED"
exit $fail
