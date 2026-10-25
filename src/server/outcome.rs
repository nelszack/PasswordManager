use super::*;
use crate::protocol::{ResponsePayload, RpcResponse};
#[derive(Default)]
pub(super) struct CommandOutcome {
    pub responses: Vec<RpcResponse>,
    pub effect: CommandEffect,
    // Captured by the vault owner before an asynchronous effect releases it.
    // Late replies must carry this session, never an unrelated later unlock.
    pub session_id: Option<String>,
}
pub(super) fn respond_payload(
    code: ResponseCode,
    payload: ResponsePayload,
    responses: &mut Vec<RpcResponse>,
) {
    responses.push(RpcResponse::new(code, payload));
}
pub(super) fn respond_with_code(
    code: ResponseCode,
    message: &str,
    responses: &mut Vec<RpcResponse>,
) {
    responses.push(RpcResponse::message(code, message));
}
pub(super) fn respond_data(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_payload(
        ResponseCode::Success,
        ResponsePayload::Secret(message.into()),
        responses,
    );
}
pub(super) fn respond(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_with_code(ResponseCode::Success, message, responses);
}
pub(super) fn respond_failure(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_with_code(ResponseCode::Failure, message, responses);
}
pub(super) fn respond_not_found(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_with_code(ResponseCode::NotFound, message, responses);
}
pub(super) fn respond_conflict(message: &str, responses: &mut Vec<RpcResponse>) {
    respond_with_code(ResponseCode::Conflict, message, responses);
}
fn domain_code(error: &crate::vault::VaultError) -> ResponseCode {
    use crate::vault::VaultError;
    match error {
        VaultError::NotFound(_) => ResponseCode::NotFound,
        VaultError::InvalidInput(_) | VaultError::Validation(_) => ResponseCode::InvalidInput,
        VaultError::Conflict(_) => ResponseCode::Conflict,
        VaultError::Locked | VaultError::Persistence(_) => ResponseCode::Failure,
        VaultError::Durability(_) => ResponseCode::Durability,
    }
}
pub(super) fn respond_domain_error(
    error: &crate::vault::VaultError,
    responses: &mut Vec<RpcResponse>,
) {
    respond_domain_error_with_context(error, &error.to_string(), responses);
}
pub(super) fn respond_domain_error_with_context(
    error: &crate::vault::VaultError,
    message: &str,
    responses: &mut Vec<RpcResponse>,
) {
    respond_with_code(domain_code(error), message, responses);
}
pub(super) fn respond_domain_result(
    result: Result<String, crate::vault::VaultError>,
    responses: &mut Vec<RpcResponse>,
) {
    match result {
        Ok(output) => {
            let output = zeroize::Zeroizing::new(output);
            respond(&output, responses)
        }
        Err(error) => respond_domain_error(&error, responses),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgements_remain_messages_even_when_they_look_like_json() {
        let mut responses = Vec::new();
        respond_domain_result(Ok(r#"{"history":[]}"#.into()), &mut responses);
        assert!(matches!(
            &responses[0].payload,
            ResponsePayload::Message(message) if message == r#"{"history":[]}"#
        ));
    }
}
