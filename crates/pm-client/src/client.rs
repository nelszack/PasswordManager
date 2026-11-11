#[doc(hidden)]
pub mod presentation;
#[cfg(target_os = "windows")]
mod shutdown;
mod transport;
pub use transport::{AuthenticatedClient, RequestFailure};
pub fn render_response(payload: &crate::protocol::ResponsePayload) -> String {
    presentation::render(payload)
}
pub fn terminal_output(text: &str) -> String {
    crate::terminal::output(text).to_string()
}

/// Escape untrusted metadata without allowing it to change terminal layout.
pub fn terminal_metadata(text: &str) -> zeroize::Zeroizing<String> {
    crate::terminal::metadata(text)
}
