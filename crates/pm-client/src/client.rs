#[doc(hidden)]
pub mod presentation;
#[cfg(target_os = "windows")]
mod shutdown;
mod transport;
pub use presentation::Style;
pub use transport::{AuthenticatedClient, RequestFailure, StatusEvents, StatusEventsShutdown};
pub fn render_response(style: Style, payload: &crate::protocol::ResponsePayload) -> String {
    presentation::render(style, payload)
}
pub fn terminal_output(text: &str) -> String {
    crate::terminal::output(text).to_string()
}

/// Escape untrusted metadata without allowing it to change terminal layout.
pub fn terminal_metadata(text: &str) -> zeroize::Zeroizing<String> {
    crate::terminal::metadata(text)
}
