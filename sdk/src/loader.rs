//! Host-side loading of plugin libraries (feature `loader`), shared by
//! LovelyCarve's in-process mode and `lc-plugin-host`.

use std::{mem::MaybeUninit, path::Path};

use rmpv::Value;

use crate::{
    abi::{self, Buffer, Bytes, EntryFn, HostApiV1, PluginApiV1},
    value, Error, Result,
};

/// Loads the plugin library at `path` and returns its entry point.
///
/// The library stays loaded for the rest of the process: plugin threads can
/// outlive an abandoned instance, so unloading is never safe. On Windows the
/// library's own directory is searched first for its dependent DLLs.
pub fn load_library(path: &Path) -> Result<EntryFn> {
    let path = std::path::absolute(path).map_err(|error| {
        Error::new("PLUGIN_LOAD_FAILED", format!("{}: {error}", path.display()))
    })?;
    // SAFETY: loading runs the library's initialisers; plugins are trusted on
    // discovery (docs/PLUGIN_PROTOCOL.md).
    let library = unsafe { open(&path) }.map_err(|error| {
        Error::new("PLUGIN_LOAD_FAILED", format!("{}: {error}", path.display()))
    })?;
    // SAFETY: the ABI fixes the entry point's signature.
    let entry = unsafe { library.get::<EntryFn>(abi::ENTRY_SYMBOL) }
        .map(|symbol| *symbol)
        .map_err(|error| {
            Error::new(
                "PLUGIN_LOAD_FAILED",
                format!(
                    "{} does not export lovelycarve_plugin_v1: {error}",
                    path.display()
                ),
            )
        })?;
    std::mem::forget(library);
    Ok(entry)
}

#[cfg(windows)]
unsafe fn open(path: &Path) -> std::result::Result<libloading::Library, libloading::Error> {
    use libloading::os::windows::{
        Library, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    };
    unsafe {
        Library::load_with_flags(
            path,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    }
    .map(Into::into)
}

#[cfg(not(windows))]
unsafe fn open(path: &Path) -> std::result::Result<libloading::Library, libloading::Error> {
    unsafe { libloading::Library::new(path) }
}

/// One plugin instance created through an entry point. Every method may be
/// called from any thread.
pub struct PluginInstance {
    api: PluginApiV1,
}

// SAFETY: the C ABI requires every plugin function to be callable
// concurrently from any thread.
unsafe impl Send for PluginInstance {}
unsafe impl Sync for PluginInstance {}

impl PluginInstance {
    /// Creates an instance bound to `host`.
    ///
    /// # Safety
    ///
    /// `host` and its context must stay valid, and keep serving calls from
    /// any thread, until the instance is destroyed (or forever when it is
    /// abandoned).
    pub unsafe fn create(entry: EntryFn, host: &HostApiV1) -> Result<Self> {
        let mut api = MaybeUninit::<PluginApiV1>::uninit();
        let status = unsafe { entry(host, api.as_mut_ptr()) };
        if status != abi::STATUS_OK {
            return Err(Error::new(
                "PLUGIN_INIT_FAILED",
                format!("plugin entry point failed with ABI status {status}"),
            ));
        }
        let api = unsafe { api.assume_init() };
        if api.abi_version != abi::ABI_VERSION || api.struct_size < abi::PLUGIN_API_SIZE {
            // An unknown table layout cannot be destroyed safely; leak it.
            return Err(Error::new(
                "PLUGIN_ABI_MISMATCH",
                format!(
                    "plugin implements C ABI v{} ({} bytes); host requires v{}",
                    api.abi_version,
                    api.struct_size,
                    abi::ABI_VERSION
                ),
            ));
        }
        Ok(Self { api })
    }

    /// The `plugin.hello` params: protocol range, identity, capabilities.
    pub fn describe(&self) -> Result<Value> {
        let mut out = Buffer::empty();
        let status = unsafe { (self.api.describe)(self.api.instance, &mut out) };
        self.take_reply(status, out, "describe", usize::MAX)
    }

    /// Runs one LPP method on the calling thread. A reply larger than
    /// `reply_limit` bytes fails with `RESOURCE_LIMIT`.
    pub fn call(
        &self,
        call_id: u64,
        method: &str,
        params: &Value,
        reply_limit: usize,
    ) -> Result<Value> {
        let params = value::encode(params)?;
        let mut out = Buffer::empty();
        let status = unsafe {
            (self.api.call)(
                self.api.instance,
                call_id,
                Bytes::from_slice(method.as_bytes()),
                Bytes::from_slice(&params),
                &mut out,
            )
        };
        self.take_reply(status, out, method, reply_limit)
    }

    /// Asks the in-flight call `call_id` to stop.
    pub fn cancel(&self, call_id: u64) {
        unsafe { (self.api.cancel)(self.api.instance, call_id) };
    }

    /// Releases the instance.
    ///
    /// # Safety
    ///
    /// No call may be in flight and the instance must not be used again.
    pub unsafe fn destroy(&self) {
        unsafe { (self.api.destroy)(self.api.instance) };
    }

    fn take_reply(
        &self,
        status: i32,
        mut out: Buffer,
        method: &str,
        reply_limit: usize,
    ) -> Result<Value> {
        let bytes = unsafe { out.as_slice() };
        let decoded = if bytes.len() > reply_limit {
            Err(Error::new(
                "RESOURCE_LIMIT",
                format!(
                    "{method} reply of {} bytes exceeds {reply_limit} bytes",
                    bytes.len()
                ),
            ))
        } else {
            value::decode(bytes)
        };
        unsafe { (self.api.free_buffer)(self.api.instance, &mut out) };
        match status {
            abi::STATUS_OK => decoded,
            abi::STATUS_ERROR => Err(match decoded {
                Ok(error) => Error::from_value(&error),
                Err(error) => error,
            }),
            abi::STATUS_PANIC => Err(Error::new(
                "PLUGIN_PANIC",
                format!("{method} panicked inside the plugin"),
            )),
            status => Err(Error::new(
                "PLUGIN_ABI_ERROR",
                format!("{method} failed with ABI status {status}"),
            )),
        }
    }
}
