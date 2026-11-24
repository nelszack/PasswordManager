use super::*;
use crate::protocol::{RpcResponse, encode_rpc_response};

/// A connection's authenticated key is an explicit capability. There is no
/// plaintext response path, including in tests or error handling.
pub(super) async fn deliver_responses(
    reply: Option<RpcResponse>,
    stream: &mut TcpStream,
    response_key: &[u8; 32],
) -> std::io::Result<()> {
    let Some(response) = reply else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "command produced no response",
        ));
    };
    let frame = encode_rpc_response(&response).map_err(std::io::Error::other)?;
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
