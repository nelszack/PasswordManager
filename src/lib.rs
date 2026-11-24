//! Shared production implementation used by the CLI and security fuzz targets.
pub mod cli;
pub use pm_client as client;
pub mod clipboard;
mod clock;
pub mod cloud;
pub mod config;
pub mod docs;
mod duo;
pub mod encryption;
pub use pm_contracts::item_profile;
pub use pm_platform::file;
/// In-process mobile API used by the Android JNI adapter.
pub mod mobile {
    pub use crate::vault::mobile::{Cancellation, MobileVault, wipe_response};
}
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod native_messaging;
mod operations;
pub mod passkey;
pub mod password;
pub mod prompt;
pub use pm_contracts::{protocol, secret, types};
pub mod server;
pub mod vault;
pub mod vault_names;

#[cfg(feature = "fuzzing")]
pub mod fuzz_support {
    /// Parse a framed native request and validate its command without contacting
    /// the server, touching files, or printing any synthetic secrets.
    pub fn native_message(data: &[u8]) {
        crate::native_messaging::fuzz_message(data);
        let _ = crate::protocol::decode_responses(data);
        if let Ok(mut request) = rmp_serde::from_slice::<crate::protocol::RequestEnvelope>(data) {
            let _ = request.validate();
            zeroize::Zeroize::zeroize(&mut request);
        }
    }

    pub fn imports(data: &[u8]) {
        if let Ok(text) = std::str::from_utf8(data) {
            crate::vault::fuzz_imports(text);
        }
    }
}

#[cfg(test)]
mod benchmarks;
