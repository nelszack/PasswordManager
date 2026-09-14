const RESPONSE_MAGIC: &[u8; 4] = b"PMR1";
const RESPONSE_HEADER_LEN: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
    Success = 0,
    Failure = 1,
    InvalidInput = 2,
    NotFound = 3,
    Conflict = 4,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProtocolResponse {
    pub code: i32,
    pub message: String,
}

pub fn encode_response(code: ResponseCode, message: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(RESPONSE_HEADER_LEN + message.len());
    frame.extend_from_slice(RESPONSE_MAGIC);
    frame.push(code as u8);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(message.as_bytes());
    frame
}

pub fn decode_responses(mut bytes: &[u8]) -> Result<ProtocolResponse, String> {
    let mut message = String::new();
    let mut code = ResponseCode::Success as i32;
    while !bytes.is_empty() {
        if bytes.len() < RESPONSE_HEADER_LEN || &bytes[..4] != RESPONSE_MAGIC {
            return Err("server returned an invalid response frame".to_string());
        }
        let frame_code = bytes[4] as i32;
        if frame_code > ResponseCode::Conflict as i32 {
            return Err("server returned an unknown response code".to_string());
        }
        let length = u32::from_be_bytes(
            bytes[5..9]
                .try_into()
                .map_err(|_| "server returned an invalid response length".to_string())?,
        ) as usize;
        bytes = &bytes[RESPONSE_HEADER_LEN..];
        if bytes.len() < length {
            return Err("server returned a truncated response".to_string());
        }
        let text = std::str::from_utf8(&bytes[..length])
            .map_err(|_| "server returned invalid UTF-8".to_string())?;
        message.push_str(text);
        if !text.ends_with('\n') {
            message.push('\n');
        }
        code = code.max(frame_code);
        bytes = &bytes[length..];
    }
    if message.is_empty() {
        return Err("server returned an empty response".to_string());
    }
    Ok(ProtocolResponse { code, message })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_frames_round_trip_and_preserve_the_highest_error_code() {
        let mut frames = encode_response(ResponseCode::Success, "first");
        frames.extend(encode_response(ResponseCode::NotFound, "missing"));
        let response = decode_responses(&frames).unwrap();
        assert_eq!(response.code, ResponseCode::NotFound as i32);
        assert_eq!(response.message, "first\nmissing\n");
    }

    #[test]
    fn malformed_and_unknown_frames_are_rejected() {
        assert!(decode_responses(b"not-a-frame").is_err());
        let mut frame = encode_response(ResponseCode::Success, "ok");
        frame[4] = 99;
        assert!(decode_responses(&frame).is_err());
        frame[4] = 0;
        frame.pop();
        assert!(decode_responses(&frame).is_err());
    }

    #[test]
    fn response_codes_are_not_derived_from_human_readable_messages() {
        let frame = encode_response(ResponseCode::Conflict, "wording may change freely");
        let response = decode_responses(&frame).unwrap();
        assert_eq!(response.code, ResponseCode::Conflict as i32);
        assert_eq!(response.message, "wording may change freely\n");
    }
}
