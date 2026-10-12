//! MessagePack helpers for LPP payloads.

use rmpv::Value;

use crate::{Error, Result};

pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|error| Error::plugin(format!("MessagePack encoding failed: {error}")))?;
    Ok(bytes)
}

/// Decodes one payload; an empty payload is `nil`.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() {
        return Ok(Value::Nil);
    }
    rmpv::decode::read_value(&mut &bytes[..])
        .map_err(|error| Error::invalid_params(format!("invalid MessagePack payload: {error}")))
}

pub fn map<'a>(entries: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

/// The value of `key` in a map, `None` for missing keys or non-maps.
pub fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_map()?.iter().find_map(|(entry_key, entry_value)| {
        (entry_key.as_str() == Some(key)).then_some(entry_value)
    })
}

pub fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    get(value, key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid_params(format!("{key} must be a string")))
}

pub fn required_u64(value: &Value, key: &str) -> Result<u64> {
    get(value, key)
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::invalid_params(format!("{key} must be an unsigned integer")))
}

/// A string field that may be missing or `nil`.
pub fn optional_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    get(value, key).and_then(Value::as_str)
}

pub fn optional_string(value: Option<&str>) -> Value {
    value.map(Value::from).unwrap_or(Value::Nil)
}

pub fn optional_u64(value: Option<u64>) -> Value {
    value.map(Value::from).unwrap_or(Value::Nil)
}

/// Binary or byte-array results become a byte vector.
pub fn into_bytes(value: Value, method: &str) -> Result<Vec<u8>> {
    match value {
        Value::Binary(bytes) => Ok(bytes),
        _ => Err(Error::new(
            "PROTOCOL_ERROR",
            format!("{method} result must be MessagePack binary"),
        )),
    }
}

pub fn into_byte_list(value: Value, method: &str) -> Result<Vec<Vec<u8>>> {
    match value {
        Value::Array(items) => items
            .into_iter()
            .map(|item| into_bytes(item, method))
            .collect(),
        _ => Err(Error::new(
            "PROTOCOL_ERROR",
            format!("{method} result must be an array of binaries"),
        )),
    }
}

pub(crate) fn ranges(ranges: &[(u64, usize)]) -> Value {
    Value::Array(
        ranges
            .iter()
            .map(|(offset, length)| {
                Value::Array(vec![Value::from(*offset), Value::from(*length as u64)])
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trip_and_lookup() {
        let original = map([
            ("name", Value::from("文件")),
            ("size", Value::from(5_u64)),
            ("data", Value::Binary(vec![1, 2])),
        ]);
        let decoded = decode(&encode(&original).expect("encode")).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(required_str(&decoded, "name").expect("name"), "文件");
        assert_eq!(required_u64(&decoded, "size").expect("size"), 5);
        assert!(required_u64(&decoded, "name").is_err());
        assert_eq!(decode(&[]).expect("empty"), Value::Nil);
    }
}
