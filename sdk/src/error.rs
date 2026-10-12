use std::fmt;

use rmpv::Value;

use crate::value;

/// An LPP error: a stable, machine-readable `code` and a human-readable
/// `message`. Errors returned by plugin code reach the host unchanged; host
/// call failures carry the host's code (for example
/// `EVIDENCE_PATH_NOT_FOUND` or `RESOURCE_LIMIT`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: String,
    pub message: String,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// A generic plugin failure (`PLUGIN_ERROR`).
    pub fn plugin(message: impl Into<String>) -> Self {
        Self::new("PLUGIN_ERROR", message)
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new("INVALID_PARAMS", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("NOT_FOUND", message)
    }

    pub fn cancelled() -> Self {
        Self::new("CANCELLED", "request cancelled")
    }

    pub fn is_cancelled(&self) -> bool {
        self.code == "CANCELLED"
    }

    /// The `{code, message}` map carried by a `STATUS_ERROR` reply.
    pub fn to_value(&self) -> Value {
        value::map([
            ("code", Value::from(self.code.as_str())),
            ("message", Value::from(self.message.as_str())),
        ])
    }

    /// Reads a `{code, message}` map; anything else becomes `PROTOCOL_ERROR`.
    pub fn from_value(error: &Value) -> Self {
        match (
            value::get(error, "code").and_then(Value::as_str),
            value::get(error, "message").and_then(Value::as_str),
        ) {
            (Some(code), Some(message)) => Self::new(code, message),
            _ => Self::new("PROTOCOL_ERROR", "error reply is not a {code, message} map"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::plugin(error.to_string())
    }
}
