# What the numbers mean

`hrdctl stats` and `status` show measurements from `/proc` and cgroup v2.
A value that could not be read is shown as `-` or `not measured`, never as 0.

| figure | source | notes |
|---|---|---|
| RSS | `/proc/<pid>/status` VmRSS, summed over the process set | counts a shared page in every process that maps it; a total of RSS overstates |
| PSS | `/proc/<pid>/smaps_rollup` Pss | shared pages divided among the processes sharing them: the honest sum |
| USS | Private_Clean + Private_Dirty | what killing the process would free, ignoring sharing |
| swap | smaps_rollup Swap, or cgroup `memory.swap.current` | |
| cgroup `memory.current` | the instance's cgroup | includes page cache and kernel memory; **a different quantity** from RSS/PSS and shown separately |
| CPU% | the instance cgroup's `usage_usec` delta over wall time; without a cgroup, the delta of summed `utime+stime` | 100 = one core fully busy; first sample after a process appears is `-`; CPU of processes that exited between samples is included only in the cgroup figure |
| processes, threads | members of the process set | |
| uptime | since the run started | |
| memory pressure | `/proc/pressure/memory` "some" 10-second average | |
| disk | allocated bytes of the accounts' tree plus the runtime store, hard links counted once | a walk capped at 500,000 entries, says so when it stops early |
| proxy group traffic | rx/tx bytes of each proxy group's `wg0`, from the helper | |
| KSM | `/sys/kernel/mm/ksm/*` when KSM is on | |

Classes: **engine** = `cordial-run`; **compositor** = `cage`; **manager** =
`hrdd`; **helpers** = everything else in an instance's process set (plugin
runtime, web process, sandbox, anything the client started).
`cordial-run` contains the open layer and the closed engine in one process, and
they cannot be told apart from outside.

Sampling is cheap by design: cheap counters every `stats.interval_s` (5 s);
`smaps_rollup` walks a process's memory map, so it is read for at most 20
instances per round and each instance at most every `stats.pss_interval_s` (30 s);
the PSS/USS shown can be up to that old, and the age is in the JSON output. Set
`pss_interval_s = 0` to turn it off.

The manager's own memory is in `stats` (class `manager`) and in
[memory.md](memory.md).
