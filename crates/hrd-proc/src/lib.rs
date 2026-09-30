//! Reading process and cgroup accounting, and saying what each number is.
//!
//! The brief asks for RSS, PSS, private memory, swap, CPU and cgroup figures
//! "without summing shared memory mechanically" and without treating
//! `memory.current` as RSS. The types here keep those quantities apart:
//!
//! | quantity | source | counts shared pages | counts page cache | notes |
//! |---|---|---|---|---|
//! | RSS | `/proc/<pid>/status` `VmRSS` | fully, in every process | no (mapped file pages yes) | summing it over processes counts a shared page once per mapper |
//! | PSS | `/proc/<pid>/smaps_rollup` `Pss` | divided among mappers | mapped file pages | the figure that does sum: the total over all processes is the real total for the pages they map |
//! | USS | `Private_Clean + Private_Dirty` | not at all | mapped private file pages | what exits with the process |
//! | swap | `smaps_rollup` `Swap` / `SwapPss` | | | `SwapPss` divides like `Pss` |
//! | `memory.current` | cgroup v2 | charged to whichever cgroup touched them first | **yes** | a cgroup-level figure; not comparable with the above |
//!
//! Everything that can be absent is `Option`: a process that exits between
//! listing and reading, a kernel without `smaps_rollup`, a cgroup without the
//! memory controller. `None` is "not measured", never zero.

#![forbid(unsafe_code)]

pub mod cgroup;
pub mod disk;
pub mod procfs;
pub mod stats;
