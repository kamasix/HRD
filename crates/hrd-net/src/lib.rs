//! Network groups: what a WireGuard file may contain, what applying it means,
//! and what the gateway on the other end must be told.
//!
//! This crate executes nothing. It turns text into validated values and values
//! into lists of steps, so that every decision about what the privileged helper
//! will do can be reviewed, printed and tested without root.

#![forbid(unsafe_code)]

pub mod base64;
pub mod gateway;
pub mod ipnet;
pub mod plan;
pub mod proto;
pub mod stun;
pub mod wg;
