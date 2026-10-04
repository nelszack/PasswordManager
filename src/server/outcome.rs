use super::*;

#[derive(Default)]
pub(super) struct CommandOutcome {
    pub responses: Vec<BufferedResponse>,
    pub effect: CommandEffect,
}

pub(super) fn respond_with_code(
    code: ResponseCode,
    message: &str,
    responses: &mut Vec<BufferedResponse>,
) {
    responses.push(BufferedResponse {
        code,
        message: message.to_owned(),
    });
}
pub(super) fn respond(message: &str, responses: &mut Vec<BufferedResponse>) {
    respond_with_code(ResponseCode::Success, message, responses);
}
pub(super) fn respond_failure(message: &str, responses: &mut Vec<BufferedResponse>) {
    respond_with_code(ResponseCode::Failure, message, responses);
}
pub(super) fn respond_not_found(message: &str, responses: &mut Vec<BufferedResponse>) {
    respond_with_code(ResponseCode::NotFound, message, responses);
}
pub(super) fn respond_conflict(message: &str, responses: &mut Vec<BufferedResponse>) {
    respond_with_code(ResponseCode::Conflict, message, responses);
}

fn domain_code(error: &crate::vault::VaultError) -> ResponseCode {
    use crate::vault::VaultError;
    match error {
        VaultError::NotFound(_) => ResponseCode::NotFound,
        VaultError::InvalidInput(_) | VaultError::Validation(_) => ResponseCode::InvalidInput,
        VaultError::Conflict(_) => ResponseCode::Conflict,
        VaultError::Locked | VaultError::Persistence(_) | VaultError::Durability(_) => {
            ResponseCode::Failure
        }
    }
}

pub(super) fn respond_domain_error(
    error: &crate::vault::VaultError,
    responses: &mut Vec<BufferedResponse>,
) {
    respond_domain_error_with_context(error, &error.to_string(), responses);
}

pub(super) fn respond_domain_error_with_context(
    error: &crate::vault::VaultError,
    message: &str,
    responses: &mut Vec<BufferedResponse>,
) {
    respond_with_code(domain_code(error), message, responses);
}

pub(super) fn respond_domain_result(
    result: Result<String, crate::vault::VaultError>,
    responses: &mut Vec<BufferedResponse>,
) {
    match result {
        Ok(output) => {
            let output = zeroize::Zeroizing::new(output);
            respond(&output, responses);
        }
        Err(error) => respond_domain_error(&error, responses),
    }
}
