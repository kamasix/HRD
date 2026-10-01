# Running it

Everything is `hrdctl` over SSH. `--json` on any command prints JSON for
scripts; exit codes: 0 ok, 1 error, 2 bad usage or invalid input, 3 not found,
4 conflict, 5 unavailable (daemon, helper, runtime, secret store, network not
ready), 6 authentication required, 7 permission denied.

## A session, start to end

```
hrdctl secrets status                # ready? after a reboot: secrets unlock
hrdctl doctor                        # anything FAIL?
hrdctl tree                          # groups, their proxy groups, the accounts in them
hrdctl group start adopt-me          # every account of the group, at the group's Place ID
hrdctl proxy-group start de-1        # or the accounts of one proxy group
hrdctl instance start alt-07         # or one account
hrdctl status --live                 # queued -> starting -> joining -> connected
hrdctl stats
hrdctl instance stop alt-07          # polite stop, then the whole process set is ended
hrdctl group stop adopt-me           # everything running in the group (also proxy-group stop)
hrdctl stop-all
```

The place comes from the group (`hrdctl group set adopt-me --place-id N`); a
`--place-id` on a start overrides it for that start. A group without a place
refuses to start and says so; a running client keeps the place it joined when the
group's place is changed. The resource mode is the request's, else the account's,
else the group's, else `resources.default_mode`.

A start only **queues**. The scheduler admits one start when: fewer than
`max_concurrent_starts` are in flight (0 = chosen from the machine), the minimum
interval has passed, free memory minus what the starts in flight are still
expected to add stays above `min_available_mem_mib`, and memory and CPU pressure
are below their limits. The queue position and the reason a start is waiting are
shown by `queue list`. `queue cancel --all` empties it. Stopping the daemon does
not restore a queue; it is an instruction to a daemon that is gone.

## What each state means and what to do

| state | meaning | you |
|---|---|---|
| `configured` | registered, never started | `instance start` (or start its group) |
| `auth_required` | no usable session, or a client reached the sign-in screen; the reason says which | `account login` |
| `queued` | waiting for a start slot | wait, or `queue cancel` |
| `starting` | process set exists, engine not yet at its first screen | wait; after `start_timeout_s` it becomes `failed` |
| `joining` | signed in, the join was requested, the client has not said it is in the game | wait; `join_timeout_s` |
| `connected` | the client printed that it joined a place. Only this line moves an instance here | - |
| `disconnected` | the engine reported a disconnection that was not followed by a new join, or the client left, or its process ended after being connected. The reason and the engine's reason code are recorded; **the process set is already released and nothing restarts it** | `instance show`, then `instance start` if you want it again |
| `stopped` | you stopped it (or cancelled it while queued) | - |
| `failed` | could not start, crashed before joining, was killed by the kernel for memory, or timed out; the reason says which (exit 3 is "profile locked by another process") | `logs`, `instance show` |
| `unknown` | a process exists but nothing it said settles the question, or the run could not be re-derived after a manager restart | `instance show`; stop and start it |

`connected` does **not** mean the game is healthy; it means the client reported
joining. A reason code on a disconnect (`Disconnection Notification. Reason: N`)
is Roblox's; the manager records it and does not interpret it.

## A restart of the daemon

`systemctl restart hrdd` leaves clients running. The new daemon finds each live
process set, re-reads the client's log from the run's banner, and continues. Queued
starts are dropped. A run whose processes are gone is closed as ended with an
unobserved exit status. The keyring keeps running across a daemon restart.

## Sizing

Start small and look: `hrdctl stats` (PSS and pressure), then raise
`scheduler.max_instances` and start more proxy groups. 300 is the manager's ceiling,
not a prediction for the machine ([memory.md](memory.md), [gpu-less.md](gpu-less.md)).
Stop before the machine swaps or the OOM killer chooses for you: clients have
`oom_score_adj = 300`, the daemon -500, so a squeeze kills a client first.

## Automation

```
hrdctl --json status --state connected | jq -r '.[].id'
hrdctl --json status | jq '[.[] | .state] | group_by(.) | map({(.[0]): length}) | add'
```

Errors in JSON mode are `{"ok":false,"error":{"code":...,"message":...}}` on
standard output with a non-zero exit status.

## Troubleshooting

| symptom | look at |
|---|---|
| `cannot connect to control.sock` | `systemctl status hrdd`; are you in the `cordial` group? |
| start refused: secret store | `hrdctl secrets status`, then `secrets unlock` |
| start refused: proxy not usable | `proxy list` (state and reason), `proxy plan`, `proxy apply` |
| `failed` right after start | `instance show ID`, `logs ID`; `doctor` for a missing `cage` / Vulkan / client binary |
| many `failed` at once under load | `stats`: memory pressure; raise `min_available_mem_mib`, lower `max_instances` |
| a proxy group's clients all `disconnected` | `proxy list`: handshake age; `proxy check`; the gateway (docs/gateway.md) |
| `doctor` says processes are tracked by process group | the service is not running with `Delegate=yes`, or cgroup v2 is missing |
