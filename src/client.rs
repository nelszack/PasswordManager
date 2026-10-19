pub(crate) mod presentation;
mod transport;
pub use transport::{AuthenticatedClient, RequestFailure};
pub fn render_response(payload: &crate::protocol::ResponsePayload) -> String {
    presentation::render(payload)
}
pub fn terminal_output(text: &str) -> String {
    crate::terminal::output(text).to_string()
}
