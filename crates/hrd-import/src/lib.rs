//! Importing a Roblox Android build into the shared runtime store.
//!
//! One build is imported once and then used, read-only, by every client. The
//! pipeline (`import`) is: stage private copies of the inputs, inspect them,
//! verify signature *and key binding*, classify by content, check the set is
//! consistent, extract the engine and the assets from the staged copies, write
//! a provenance record, then publish by one atomic rename. Nothing the
//! operator's files do after staging can affect what gets published.

pub mod axml;
pub mod binding;
pub mod der;
pub mod import;
pub mod stage;
pub mod store;
