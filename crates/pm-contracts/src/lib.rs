//! Shared command and response contracts, secret ownership, and wire encryption.
//! This crate has no vault storage, HTTP, clipboard, or GUI implementation.
#[cfg(feature = "cli")]
mod cli_values;
pub mod cloud;
pub mod protocol;
pub mod secret;
pub mod types;
pub mod vault;
