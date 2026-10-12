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
        let mut reply = Buffer::empty();
        // SAFETY: the host table is valid for the instance's lifetime, the
        // method and params slices outlive the call, and `reply` is released
        // through the host's own `free_buffer`.
        let status = unsafe {
            (self.api.call)(
                self.api.context,
                Bytes::from_slice(method.as_bytes()),
                Bytes::from_slice(&params),
                &mut reply,
            )
        };
        let decoded = value::decode(unsafe { reply.as_slice() });
        unsafe { (self.api.free_buffer)(self.api.context, &mut reply) };
        match status {
            abi::STATUS_OK => decoded,
            abi::STATUS_ERROR => Err(match decoded {
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

    /// Reports progress to the LovelyCarve task center (`host.progress`).
    pub fn progress(&self, current: u64, total: Option<u64>, message: Option<&str>) -> Result<()> {
        self.call_host(
            "host.progress",
            &value::map([
                ("current", Value::from(current)),
                ("total", value::optional_u64(total)),
                ("message", value::optional_string(message)),
            ]),
        )
        .map(drop)
    }

    /// Writes one line to the LovelyCarve log (target `plugin`).
    pub fn log(&self, level: LogLevel, message: &str) {
        self.host.log(level, message);
    }

    pub(crate) fn call_host(&self, method: &str, params: &Value) -> Result<Value> {
        self.check_cancelled()?;
        self.host.call(method, params)
    }

    pub(crate) fn host(&self) -> HostConnection {
        self.host
    }
}
