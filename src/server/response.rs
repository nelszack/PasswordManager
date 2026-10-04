use super::*;

pub async fn respond(message: &str, stream: &mut TcpStream) {
    respond_with_code(ResponseCode::Success, message, stream).await;
}

pub(super) async fn respond_failure(message: &str, stream: &mut TcpStream) {
    respond_with_code(ResponseCode::Failure, message, stream).await;
}

pub(super) async fn respond_not_found(message: &str, stream: &mut TcpStream) {
    respond_with_code(ResponseCode::NotFound, message, stream).await;
}

pub(super) async fn respond_conflict(message: &str, stream: &mut TcpStream) {
    respond_with_code(ResponseCode::Conflict, message, stream).await;
}

pub async fn respond_with_code(code: ResponseCode, message: &str, stream: &mut TcpStream) {
    if RESPONSE_BUFFER
        .try_with(|buffer| {
            buffer.borrow_mut().push(BufferedResponse {
                code,
                message: message.to_owned(),
            });
        })
        .is_ok()
    {
        return;
    }
    write_response(code, message, stream).await;
}

pub(super) async fn flush_buffered_responses(stream: &mut TcpStream) {
    let responses = RESPONSE_BUFFER.with(|buffer| std::mem::take(&mut *buffer.borrow_mut()));
    for mut response in responses {
        write_response(response.code, &response.message, stream).await;
        response.message.zeroize();
    }
}

async fn write_response(code: ResponseCode, message: &str, stream: &mut TcpStream) {
    let frame = Zeroizing::new(encode_response(code, message));
    let transport = TRANSPORT_RESPONSE_KEY.try_with(|key| {
        key.borrow()
            .as_deref()
            .and_then(|key| encrypt_record(key, &frame))
    });
    let direct_test_write = transport.is_err();
    let mut encrypted = transport.ok().flatten();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        if let Some(record) = encrypted.as_deref() {
            stream.write_all(record).await
        } else if direct_test_write {
            stream.write_all(&frame).await
        } else {
            Ok(())
        }
    })
    .await;
    if let Some(record) = encrypted.as_mut() {
        record.zeroize();
    }
    let _ = stream.flush().await;
}

fn domain_code(error: &crate::vault::VaultError) -> ResponseCode {
    use crate::vault::VaultError;
    match error {
        VaultError::NotFound(_) => ResponseCode::NotFound,
        VaultError::InvalidInput(_) | VaultError::Validation(_) => ResponseCode::InvalidInput,
        VaultError::Conflict(_) => ResponseCode::Conflict,
        VaultError::Locked | VaultError::Persistence(_) => ResponseCode::Failure,
    }
}

pub(super) async fn respond_domain_error(error: &crate::vault::VaultError, stream: &mut TcpStream) {
    respond_domain_error_with_context(error, &error.to_string(), stream).await;
}

pub(super) async fn respond_domain_error_with_context(
    error: &crate::vault::VaultError,
    message: &str,
    stream: &mut TcpStream,
) {
    respond_with_code(domain_code(error), message, stream).await;
}

pub(super) async fn respond_domain_result(
    result: Result<String, crate::vault::VaultError>,
    stream: &mut TcpStream,
) {
    match result {
        Ok(output) => {
            let output = zeroize::Zeroizing::new(output);
            respond(&output, stream).await;
        }
        Err(error) => respond_domain_error(&error, stream).await,
    }
}

pub(super) async fn deliver_entry(
    result: Result<crate::vault::EntryOutput<'_>, crate::vault::VaultError>,
    timeout: u8,
    stream: &mut TcpStream,
) {
    match result {
        Ok(crate::vault::EntryOutput::Details(view)) => {
            respond(&presentation::entry_details(&view), stream).await;
            if !view.entry.password.is_empty() {
                copy_in_background(view.entry.password.clone(), timeout);
            }
        }
        Ok(crate::vault::EntryOutput::SiteLogins(output)) => respond(&output, stream).await,
        Err(error) => respond_domain_error(&error, stream).await,
    }
}
