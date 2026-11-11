//! Authenticated clients and terminal rendering without vault storage or HTTP.
pub use pm_contracts::{protocol, secret, types, vault};
pub use pm_platform::file;
mod client;
mod terminal;
pub use client::*;
