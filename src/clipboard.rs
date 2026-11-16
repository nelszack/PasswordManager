//! Compatibility exports for platform integration.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use pm_platform::clipboard::*;

// Mobile clipboards are managed by the platform UI, not a background process.
#[cfg(any(target_os = "android", target_os = "ios"))]
mod mobile {
    pub fn copy_with_timeout(_: &str, _: u8) -> Result<(), String> {
        Err("Use the mobile application's clipboard action".into())
    }
    pub fn try_copy_in_background(_: String, _: u8) -> Result<(), String> {
        Err("Use the mobile application's clipboard action".into())
    }
    pub fn copy_in_background(_: String, _: u8) {}
    pub fn clear_owned() -> Result<(), String> {
        Ok(())
    }
    pub fn run_helper(_: u8) -> Result<(), String> {
        Err("Clipboard helpers are unavailable on mobile".into())
    }
}
#[cfg(any(target_os = "android", target_os = "ios"))]
pub use mobile::*;
