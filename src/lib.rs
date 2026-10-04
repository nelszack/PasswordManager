//! Shared production implementation used by the CLI and security fuzz targets.
pub mod cli;
pub mod client;
pub mod clipboard;
pub mod config;
pub mod docs;
pub mod encryption;
pub mod file;
pub mod native_messaging;
pub mod password;
pub mod protocol;
pub mod server;
mod terminal;
pub mod types;
pub mod vault;

#[cfg(feature = "fuzzing")]
pub mod fuzz_support {
    /// Parse a framed native request and validate its command without contacting
    /// the server, touching files, or printing any synthetic secrets.
    pub fn native_message(data: &[u8]) {
        crate::native_messaging::fuzz_message(data);
        let _ = crate::protocol::decode_responses(data);
        if let Ok(mut command) = rmp_serde::from_slice::<crate::types::ServerCommand>(data) {
            zeroize::Zeroize::zeroize(&mut command);
        }
    }

    pub fn imports(data: &[u8]) {
        if let Ok(text) = std::str::from_utf8(data) {
            crate::vault::fuzz_imports(text);
        }
    }
}
