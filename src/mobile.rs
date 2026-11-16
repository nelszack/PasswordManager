//! In-process mobile API. Paths are supplied explicitly; no desktop daemon or
//! process-global environment changes are needed. Android calls this via JNI.
pub use crate::vault::mobile::MobileVault;
pub use crate::vault::mobile::wipe_response;
