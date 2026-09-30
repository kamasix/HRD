//! Types and small utilities shared by every binary in the fleet manager.
//!
//! Nothing in this crate talks to Roblox, to the network or to a display. It
//! holds what the CLI, the daemon and the privileged helper must agree on:
//! what a valid name is, where things live, what the control protocol says and
//! how a file is written so that a crash cannot leave half of it behind.
//!
//! The crate is `forbid(unsafe_code)`: every syscall it needs is reachable
//! through `rustix`'s safe wrappers.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod fsutil;
pub mod ids;
pub mod layout;
pub mod model;
pub mod proto;
pub mod redact;
pub mod time;
pub mod wire;

pub use error::{Error, Result};
