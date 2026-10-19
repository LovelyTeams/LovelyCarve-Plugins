//! LPP frames between LovelyCarve and `lc-plugin-host`: a four-byte
//! big-endian payload length followed by a MessagePack map.
//!
//! Plugins never see frames — the C ABI carries bare method payloads — but
//! the host and the out-of-process loader share these definitions.

use std::io::{self, Read, Write};

use rmpv::Value;
use serde::{Deserialize, Serialize};

/// LPP version: 2 (typed record streams). Version 1 plugins are refused.
pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_SIZE: usize = 8 * 1024 * 1024;

fn nil() -> Value {
    Value::Nil
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LppMessage {
    Request {
        v: u16,
        id: u64,
        method: String,
        #[serde(default = "nil")]
        params: Value,
    },
    Response {
        v: u16,
        id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<RpcError>,
    },
    Event {
        v: u16,
        method: String,
        #[serde(default = "nil")]
        params: Value,
    },
    Cancel {
        v: u16,
        request_id: u64,
    },
}

impl LppMessage {
    pub fn request(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self::Request {
            v: PROTOCOL_VERSION,
            id,
            method: method.into(),
            params,
        }
    }

    pub fn success(id: u64, result: Value) -> Self {
        Self::Response {
            v: PROTOCOL_VERSION,
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(id: u64, error: RpcError) -> Self {
        Self::Response {
            v: PROTOCOL_VERSION,
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

impl RpcError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Reads one frame; `Ok(None)` when the stream ends cleanly between frames.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<LppMessage>> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_SIZE {
        return Err(invalid_data(format!(
            "payload length {length} is outside 1..={MAX_FRAME_SIZE}"
        )));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    rmp_serde::from_slice(&payload)
        .map(Some)
        .map_err(|error| invalid_data(error.to_string()))
}

/// Encodes one frame, rejecting payloads above [`MAX_FRAME_SIZE`].
pub fn encode_frame(message: &LppMessage) -> io::Result<Vec<u8>> {
    let payload =
        rmp_serde::to_vec_named(message).map_err(|error| invalid_data(error.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_FRAME_SIZE {
        return Err(invalid_data(format!(
            "encoded payload length {} is outside 1..={MAX_FRAME_SIZE}",
            payload.len()
        )));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| invalid_data("encoded payload is too large".to_owned()))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn write_frame(writer: &mut impl Write, message: &LppMessage) -> io::Result<()> {
    writer.write_all(&encode_frame(message)?)?;
    writer.flush()
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_preserves_binary_values() {
        let expected = LppMessage::success(2, Value::Binary(vec![0, 1, 0xff]));
        let frame = encode_frame(&expected).expect("encode");
        let decoded = read_frame(&mut frame.as_slice()).expect("read");
        assert_eq!(decoded, Some(expected));
    }

    #[test]
    fn clean_end_of_stream_is_not_an_error() {
        assert_eq!(read_frame(&mut [].as_slice()).expect("eof"), None);
        assert!(read_frame(&mut [0_u8, 0].as_slice()).is_err());
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let header = ((MAX_FRAME_SIZE + 1) as u32).to_be_bytes();
        let error = read_frame(&mut header.as_slice()).expect_err("reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
