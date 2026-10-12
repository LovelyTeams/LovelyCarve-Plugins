//! C ABI v1 between LovelyCarve and a plugin library.
//!
//! A plugin library exports [`ENTRY_SYMBOL`] with the [`EntryFn`] signature.
//! The host passes its [`HostApiV1`] table and receives the plugin's
//! [`PluginApiV1`] table. `include/lovelycarve_plugin.h` declares the same
//! layout for C and C++ plugins.
//!
//! Every payload is MessagePack. A call names an LPP v1 method and carries
//! that method's `params`; a [`STATUS_OK`] reply carries the method's
//! `result`, a [`STATUS_ERROR`] reply an `{code, message}` map. The method
//! set, DTOs and limits are the ones in `docs/PLUGIN_PROTOCOL.md`.
//!
//! Ownership: a [`Buffer`] is filled by the callee and released by the
//! caller through the callee's `free_buffer`, so each side frees memory with
//! its own allocator. Threading: both tables may be called concurrently from
//! any thread. A plugin call blocks its calling thread until it returns;
//! cancellation is cooperative through [`PluginApiV1::cancel`].

use std::ffi::c_void;

/// Version of this table layout; bumped on any incompatible change.
pub const ABI_VERSION: u32 = 1;

/// Exported entry point, NUL-terminated for `GetProcAddress` / `dlsym`.
pub const ENTRY_SYMBOL: &[u8] = b"lovelycarve_plugin_v1\0";

/// The call succeeded; the reply buffer holds the MessagePack result.
pub const STATUS_OK: i32 = 0;
/// The call failed; the reply buffer holds a MessagePack `{code, message}`.
pub const STATUS_ERROR: i32 = 1;
/// A pointer argument was null or a payload was not valid MessagePack.
pub const STATUS_INVALID_ARGUMENT: i32 = 2;
/// The caller's table version or size is not supported.
pub const STATUS_ABI_MISMATCH: i32 = 3;
/// A panic reached the boundary; the reply buffer may be empty.
pub const STATUS_PANIC: i32 = 4;

pub const LOG_ERROR: u32 = 1;
pub const LOG_WARN: u32 = 2;
pub const LOG_INFO: u32 = 3;
pub const LOG_DEBUG: u32 = 4;

/// Borrowed bytes; valid only for the duration of the call that receives it.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Bytes {
    pub data: *const u8,
    pub len: usize,
}

impl Bytes {
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: slice.as_ptr(),
            len: slice.len(),
        }
    }

    /// # Safety
    ///
    /// `data` must point to `len` readable bytes that stay valid for `'a`,
    /// or `len` must be zero.
    pub unsafe fn as_slice<'a>(self) -> &'a [u8] {
        if self.len == 0 || self.data.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.data, self.len) }
        }
    }
}

/// Reply bytes owned by the side that filled them.
#[repr(C)]
#[derive(Debug)]
pub struct Buffer {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl Buffer {
    pub const fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }

    /// Hands a vector across the boundary. Only [`Buffer::free_vec`] in the
    /// same library may release it.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        let mut bytes = std::mem::ManuallyDrop::new(bytes);
        Self {
            data: bytes.as_mut_ptr(),
            len: bytes.len(),
            capacity: bytes.capacity(),
        }
    }

    /// # Safety
    ///
    /// `data` must point to `len` readable bytes, or be null.
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.data, self.len) }
        }
    }

    /// Releases a buffer produced by [`Buffer::from_vec`] and leaves it empty.
    ///
    /// # Safety
    ///
    /// The buffer must be empty or come from [`Buffer::from_vec`] in this same
    /// library, and must not have been released already.
    pub unsafe fn free_vec(&mut self) {
        if !self.data.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.data, self.len, self.capacity) });
        }
        *self = Self::empty();
    }
}

/// Plugin → host LPP call (`source.read`, `evidence.stat`, `host.progress`, …).
pub type HostCallFn = unsafe extern "C" fn(
    context: *mut c_void,
    method: Bytes,
    params: Bytes,
    out: *mut Buffer,
) -> i32;
/// Releases a reply buffer filled by [`HostApiV1::call`].
pub type HostFreeBufferFn = unsafe extern "C" fn(context: *mut c_void, buffer: *mut Buffer);
/// Writes one diagnostic line (`LOG_*` level, UTF-8 text) to the host log.
pub type HostLogFn = unsafe extern "C" fn(context: *mut c_void, level: u32, message: Bytes);

/// Functions the host offers to a plugin instance. `context` stays valid
/// for as long as the instance exists.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HostApiV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub context: *mut c_void,
    pub call: HostCallFn,
    pub free_buffer: HostFreeBufferFn,
    pub log: HostLogFn,
}

/// Fills `out` with the MessagePack `plugin.hello` params: protocol range,
/// `{id, name, version}` identity and advertised capabilities.
pub type PluginDescribeFn = unsafe extern "C" fn(instance: *mut c_void, out: *mut Buffer) -> i32;
/// Host → plugin LPP call (`fs.*`, `analyzer.*`, `plugin.shutdown`). Blocks
/// until the method finishes; `call_id` is unique among in-flight calls.
pub type PluginCallFn = unsafe extern "C" fn(
    instance: *mut c_void,
    call_id: u64,
    method: Bytes,
    params: Bytes,
    out: *mut Buffer,
) -> i32;
/// Asks an in-flight call to stop; it should return `CANCELLED` promptly.
pub type PluginCancelFn = unsafe extern "C" fn(instance: *mut c_void, call_id: u64);
/// Releases a reply buffer filled by `describe` or `call`.
pub type PluginFreeBufferFn = unsafe extern "C" fn(instance: *mut c_void, buffer: *mut Buffer);
/// Releases the instance. The host calls it only when no call is in flight.
pub type PluginDestroyFn = unsafe extern "C" fn(instance: *mut c_void);

/// Functions of one plugin instance, filled in by the entry point.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PluginApiV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub instance: *mut c_void,
    pub describe: PluginDescribeFn,
    pub call: PluginCallFn,
    pub cancel: PluginCancelFn,
    pub free_buffer: PluginFreeBufferFn,
    pub destroy: PluginDestroyFn,
}

/// Creates a plugin instance bound to `host` and writes its table to
/// `plugin`. Returns [`STATUS_OK`] or an error status; `plugin` is only
/// written on success. May be called more than once to create independent
/// instances (the host does so after a restart).
pub type EntryFn = unsafe extern "C" fn(host: *const HostApiV1, plugin: *mut PluginApiV1) -> i32;

/// `struct_size` of a v1 [`HostApiV1`].
pub const HOST_API_SIZE: u32 = std::mem::size_of::<HostApiV1>() as u32;
/// `struct_size` of a v1 [`PluginApiV1`].
pub const PLUGIN_API_SIZE: u32 = std::mem::size_of::<PluginApiV1>() as u32;
