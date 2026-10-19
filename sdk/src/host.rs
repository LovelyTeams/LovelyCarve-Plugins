//! The host as seen from plugin code: synchronous LPP calls, per-request
//! cancellation and diagnostics.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use rmpv::Value;

use crate::{
    abi::{self, Buffer, Bytes, HostApiV1},
    value, Error, Result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    fn abi(self) -> u32 {
        match self {
            Self::Error => abi::LOG_ERROR,
            Self::Warn => abi::LOG_WARN,
            Self::Info => abi::LOG_INFO,
            Self::Debug => abi::LOG_DEBUG,
        }
    }
}

/// The host function table of one plugin instance.
#[derive(Clone, Copy)]
pub(crate) struct HostConnection {
    api: HostApiV1,
}

// SAFETY: the C ABI requires the host table, including `context`, to be
// callable from any thread for as long as the plugin instance exists.
unsafe impl Send for HostConnection {}
unsafe impl Sync for HostConnection {}

impl HostConnection {
    pub(crate) fn new(api: HostApiV1) -> Self {
        Self { api }
    }

    pub(crate) fn call(&self, method: &str, params: &Value) -> Result<Value> {
        let params = value::encode(params)?;
        self.call_bytes(method, &params)
            .and_then(|reply| value::decode(&reply))
    }

    /// A typed host call: `params` and the reply are named MessagePack maps.
    pub(crate) fn call_typed<P: serde::Serialize, R: for<'de> serde::Deserialize<'de>>(
        &self,
        method: &str,
        params: &P,
    ) -> Result<R> {
        let params = crate::protocol::encode(params)?;
        let reply = self.call_bytes(method, &params)?;
        if reply.is_empty() {
            return crate::protocol::decode(&[0xc0]);
        }
        crate::protocol::decode(&reply)
    }

    /// Sends encoded params and returns the encoded reply, or the decoded
    /// `{code, message}` error.
    pub(crate) fn call_bytes(&self, method: &str, params: &[u8]) -> Result<Vec<u8>> {
        let mut reply = Buffer::empty();
        // SAFETY: the host table is valid for the instance's lifetime, the
        // method and params slices outlive the call, and `reply` is released
        // through the host's own `free_buffer`.
        let status = unsafe {
            (self.api.call)(
                self.api.context,
                Bytes::from_slice(method.as_bytes()),
                Bytes::from_slice(params),
                &mut reply,
            )
        };
        let bytes = unsafe { reply.as_slice() }.to_vec();
        unsafe { (self.api.free_buffer)(self.api.context, &mut reply) };
        match status {
            abi::STATUS_OK => Ok(bytes),
            abi::STATUS_ERROR => Err(match value::decode(&bytes) {
                Ok(error) => Error::from_value(&error),
                Err(error) => error,
            }),
            status => Err(Error::new(
                "HOST_ERROR",
                format!("host call {method} failed with ABI status {status}"),
            )),
        }
    }

    pub(crate) fn log(&self, level: LogLevel, message: &str) {
        // SAFETY: see `call`; the message slice outlives the call.
        unsafe {
            (self.api.log)(
                self.api.context,
                level.abi(),
                Bytes::from_slice(message.as_bytes()),
            )
        };
    }
}

/// The host request a piece of plugin code is serving: its cancellation
/// flag plus the host connection for progress and log output.
///
/// Every host call made through a handle bound to a context fails with
/// `CANCELLED` once the host cancels the request, so analyzers that read
/// evidence stop promptly; long CPU-only loops should also poll
/// [`Context::check_cancelled`].
#[derive(Clone)]
pub struct Context {
    host: HostConnection,
    cancelled: Arc<AtomicBool>,
}

impl Context {
    pub(crate) fn new(host: HostConnection, cancelled: Arc<AtomicBool>) -> Self {
        Self { host, cancelled }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn check_cancelled(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::cancelled())
        } else {
            Ok(())
        }
    }

    /// Writes one line to the LovelyCarve log (target `plugin`) and the
    /// plugin's own log file.
    pub fn log(&self, level: LogLevel, message: &str) {
        self.host.log(level, message);
    }

    pub(crate) fn call_host(&self, method: &str, params: &Value) -> Result<Value> {
        self.check_cancelled()?;
        self.host.call(method, params)
    }

    /// A typed host call that fails with `CANCELLED` once the request is.
    pub(crate) fn call_typed<P: serde::Serialize, R: for<'de> serde::Deserialize<'de>>(
        &self,
        method: &str,
        params: &P,
    ) -> Result<R> {
        self.check_cancelled()?;
        self.host.call_typed(method, params)
    }

    pub(crate) fn host(&self) -> HostConnection {
        self.host
    }
}
