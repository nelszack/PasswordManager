use super::*;

pub async fn respond(message: &str, stream: &mut TcpStream) {
    respond_with_code(ResponseCode::Success, message, stream).await;
}

pub async fn respond_with_code(code: ResponseCode, message: &str, stream: &mut TcpStream) {
    write_response(code, message, false, stream).await;
}

pub(super) async fn deliver_responses(responses: Vec<BufferedResponse>, stream: &mut TcpStream) {
    for response in responses {
        write_response(response.code, &response.message, response.data, stream).await;
    }
}

async fn write_response(code: ResponseCode, message: &str, data: bool, stream: &mut TcpStream) {
    let frame = Zeroizing::new(if data {
        encode_data_response(message)
    } else {
        encode_response(code, message)
    });
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
