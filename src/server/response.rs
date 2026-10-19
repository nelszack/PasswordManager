use super::*;
use crate::protocol::{ResponsePayload, RpcResponse, encode_rpc_response};

/// A connection's authenticated key is an explicit capability. There is no
/// plaintext response path, including in tests or error handling.
pub(super) async fn deliver_responses(
    responses: Vec<RpcResponse>,
    stream: &mut TcpStream,
    response_key: &[u8; 32],
) -> std::io::Result<()> {
    let mut iter = responses.into_iter();
    let Some(mut response) = iter.next() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "command produced no response",
        ));
    };
    for next in iter {
        response.code = response.code.max(next.code);
        if let (ResponsePayload::Message(previous), ResponsePayload::Message(message)) =
            (&mut response.payload, &next.payload)
        {
            if !previous.ends_with('\n') {
                previous.push('\n');
            }
            previous.push_str(message);
        } else {
            response.payload = next.payload;
        }
        if next.operation.is_some() {
            response.operation = next.operation;
        }
        if next.request_id.is_some() {
            response.request_id = next.request_id;
        }
    }
    let frame = Zeroizing::new(encode_rpc_response(&response).map_err(std::io::Error::other)?);
    let encrypted = Zeroizing::new(
        encrypt_record(response_key, &frame)
            .ok_or_else(|| std::io::Error::other("could not encrypt server response"))?,
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        stream.write_all(&encrypted).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "server response write timed out",
        )
    })?
}
