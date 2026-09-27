use super::*;

pub async fn respond(message: &str, stream: &mut TcpStream, http: bool) {
    respond_with_code(ResponseCode::Success, message, stream, http).await;
}

pub(super) async fn respond_failure(message: &str, stream: &mut TcpStream, http: bool) {
    respond_with_code(ResponseCode::Failure, message, stream, http).await;
}

pub(super) async fn respond_not_found(message: &str, stream: &mut TcpStream, http: bool) {
    respond_with_code(ResponseCode::NotFound, message, stream, http).await;
}

pub(super) async fn respond_conflict(message: &str, stream: &mut TcpStream, http: bool) {
    respond_with_code(ResponseCode::Conflict, message, stream, http).await;
}

pub async fn respond_with_code(
    code: ResponseCode,
    message: &str,
    stream: &mut TcpStream,
    http: bool,
) {
    if RESPONSE_BUFFER
        .try_with(|buffer| {
            buffer.borrow_mut().push(BufferedResponse {
                code,
                message: message.to_owned(),
                http,
            });
        })
        .is_ok()
    {
        return;
    }
    write_response(code, message, stream, http).await;
}

pub(super) async fn flush_buffered_responses(stream: &mut TcpStream) {
    let responses = RESPONSE_BUFFER.with(|buffer| std::mem::take(&mut *buffer.borrow_mut()));
    for mut response in responses {
        write_response(response.code, &response.message, stream, response.http).await;
        response.message.zeroize();
    }
}

async fn write_response(code: ResponseCode, message: &str, stream: &mut TcpStream, http: bool) {
    if http {
        let body = json!({
            "ok": code == ResponseCode::Success,
            "code": code as u8,
            "message": message,
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        );
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            stream.write_all(response.as_bytes()),
        )
        .await;
    } else {
        let frame = encode_response(code, message);
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            stream.write_all(&frame).await
        })
        .await;
    }
    let _ = stream.flush().await;
}
