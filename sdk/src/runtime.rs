//! The plugin side of the C ABI: one [`Instance`] per entry-point call turns
//! host calls into trait calls. Plugin crates reach it through
//! [`crate::export_plugin!`].

use std::{
    any::Any,
    collections::HashMap,
    ffi::c_void,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
};

use rmpv::Value;

use crate::{
    abi::{self, Buffer, Bytes, HostApiV1, PluginApiV1},
    filesystem::{FsNode, Probe},
    host::{Context, HostConnection, LogLevel},
    protocol::{self, method, RunStart},
    run::Run,
    schema::RecordSchema,
    value, Error, Plugin, Result, Source, Volume,
};

/// Probed sources kept for the following `fs.open`.
const MAX_CACHED_SOURCES: usize = 16;

/// Exports `$constructor: fn() -> Plugin` as the plugin entry point
/// [`crate::abi::ENTRY_SYMBOL`]. Use it once per plugin library.
#[macro_export]
macro_rules! export_plugin {
    ($constructor:path) => {
        /// LovelyCarve plugin entry point (C ABI v1, LPP v2).
        ///
        /// # Safety
        ///
        /// Called by the LovelyCarve host with a valid host table that
        /// outlives the instance and writable memory for the plugin table.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn lovelycarve_plugin_v1(
            host: *const $crate::abi::HostApiV1,
            plugin: *mut $crate::abi::PluginApiV1,
        ) -> i32 {
            unsafe { $crate::runtime::entry(host, plugin, $constructor) }
        }
    };
}

/// Creates an instance of the plugin built by `constructor`.
///
/// # Safety
///
/// `host` must point to a valid [`HostApiV1`] whose functions and context
/// outlive the instance, and `plugin` to writable memory for a
/// [`PluginApiV1`].
pub unsafe fn entry(
    host: *const HostApiV1,
    plugin: *mut PluginApiV1,
    constructor: fn() -> Plugin,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if host.is_null() || plugin.is_null() {
            return abi::STATUS_INVALID_ARGUMENT;
        }
        let (version, size) = unsafe { ((*host).abi_version, (*host).struct_size) };
        if version != abi::ABI_VERSION || size < abi::HOST_API_SIZE {
            return abi::STATUS_ABI_MISMATCH;
        }
        let host = HostConnection::new(unsafe { *host });
        let instance = Box::new(Instance::new(constructor(), host));
        unsafe {
            plugin.write(PluginApiV1 {
                abi_version: abi::ABI_VERSION,
                struct_size: abi::PLUGIN_API_SIZE,
                instance: Box::into_raw(instance).cast(),
                describe,
                call,
                cancel,
                free_buffer,
                destroy,
            });
        }
        abi::STATUS_OK
    }))
    .unwrap_or(abi::STATUS_PANIC)
}

#[derive(Clone, Copy)]
enum Method {
    Shutdown,
    RunStart,
    Probe,
    Open,
    Close,
    Children,
    ChildrenPage,
    Stat,
    ReadRange,
}

impl Method {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            method::SHUTDOWN => Self::Shutdown,
            method::RUN_START => Self::RunStart,
            "fs.probe" => Self::Probe,
            "fs.open" => Self::Open,
            "fs.close" => Self::Close,
            "fs.children" => Self::Children,
            "fs.children_page" => Self::ChildrenPage,
            "fs.stat" => Self::Stat,
            "fs.read_range" => Self::ReadRange,
            _ => return None,
        })
    }
}

struct Instance {
    plugin: Plugin,
    schemas: Arc<HashMap<String, RecordSchema>>,
    host: HostConnection,
    sources: Mutex<HashMap<String, Source>>,
    selected_parsers: Mutex<HashMap<String, usize>>,
    sessions: Mutex<HashMap<String, Arc<Box<dyn Volume>>>>,
    next_session: AtomicU64,
    calls: Mutex<HashMap<u64, Arc<AtomicBool>>>,
}

impl Instance {
    fn new(plugin: Plugin, host: HostConnection) -> Self {
        Self {
            schemas: plugin.schema_map(),
            plugin,
            host,
            sources: Mutex::default(),
            selected_parsers: Mutex::default(),
            sessions: Mutex::default(),
            next_session: AtomicU64::new(1),
            calls: Mutex::default(),
        }
    }

    fn handle(&self, call_id: u64, method: &str, params: &[u8]) -> Result<Value> {
        let Some(method) = Method::parse(method) else {
            return Err(Error::new(
                "METHOD_NOT_FOUND",
                format!("plugin method {method} is not available"),
            ));
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        lock(&self.calls).insert(call_id, Arc::clone(&cancelled));
        let _registration = CallRegistration {
            calls: &self.calls,
            call_id,
        };
        let context = Context::new(self.host, cancelled);
        match method {
            Method::RunStart => self.run(&context, protocol::decode(params)?),
            method => self.dispatch_value(method, &value::decode(params)?),
        }
    }

    fn run(&self, context: &Context, start: RunStart) -> Result<Value> {
        let analyzer = self
            .plugin
            .analyzers
            .iter()
            .find(|(id, _)| *id == start.analyzer)
            .map(|(_, analyzer)| analyzer)
            .ok_or_else(|| {
                Error::new(
                    "INVALID_ANALYZER",
                    format!("analyzer {} is not registered", start.analyzer),
                )
            })?;
        let run = Run::new(context.clone(), start, Arc::clone(&self.schemas));
        analyzer.run(&run)?;
        protocol::to_value(&run.finish()?)
    }

    fn dispatch_value(&self, method: Method, params: &Value) -> Result<Value> {
        match method {
            Method::Shutdown => {
                self.close_sessions();
                Ok(Value::Nil)
            }
            Method::Probe => self.probe(value::required_str(params, "source_id")?),
            Method::Open => self.open(
                value::required_str(params, "source_id")?,
                value::get(params, "options").unwrap_or(&Value::Nil),
            ),
            Method::Close => {
                let volume =
                    lock(&self.sessions).remove(value::required_str(params, "session_id")?);
                if let Some(volume) = volume {
                    volume.close();
                }
                Ok(Value::Nil)
            }
            Method::Children | Method::ChildrenPage | Method::Stat | Method::ReadRange => {
                self.browse(method, params)
            }
            Method::RunStart => Err(Error::new(
                "METHOD_NOT_FOUND",
                "run.start is dispatched separately",
            )),
        }
    }

    fn probe(&self, source_id: &str) -> Result<Value> {
        let Some(first) = self.plugin.parsers.first() else {
            return Err(no_parser());
        };
        let source = self.source(source_id)?;
        let mut best: Option<(usize, Probe)> = None;
        for (index, parser) in self.plugin.parsers.iter().enumerate() {
            let probe = parser.probe(&source)?;
            let best_confidence = best.as_ref().map_or(0.0, |(_, best)| best.confidence);
            if probe.confidence > best_confidence {
                best = Some((index, probe));
            }
        }
        // A probe without a match still names a declared filesystem, so the
        // host can tell "no match" from "undeclared filesystem".
        let (filesystem, probe) = match best {
            Some((index, probe)) => {
                lock(&self.selected_parsers).insert(source_id.to_owned(), index);
                (self.plugin.parsers[index].filesystem(), probe)
            }
            None => (first.filesystem(), Probe::no_match()),
        };
        Ok(value::map([
            ("filesystem", Value::from(filesystem)),
            ("confidence", Value::from(probe.confidence)),
            ("label", value::optional_string(probe.label.as_deref())),
        ]))
    }

    fn open(&self, source_id: &str, options: &Value) -> Result<Value> {
        if self.plugin.parsers.is_empty() {
            return Err(no_parser());
        }
        let cached = lock(&self.sources).remove(source_id);
        let source = match cached {
            Some(source) => source,
            None => Source::open(self.host, source_id)?,
        };
        let parser_index = lock(&self.selected_parsers)
            .get(source_id)
            .copied()
            .filter(|index| *index < self.plugin.parsers.len())
            .unwrap_or(0);
        let volume = self.plugin.parsers[parser_index].open(source, options)?;
        let root_node = volume.root_node().to_owned();
        let session_id = format!(
            "session-{}",
            self.next_session.fetch_add(1, Ordering::Relaxed)
        );
        lock(&self.sessions).insert(session_id.clone(), Arc::new(volume));
        Ok(value::map([
            ("session_id", Value::from(session_id)),
            ("root_node", Value::from(root_node)),
        ]))
    }

    fn browse(&self, method: Method, params: &Value) -> Result<Value> {
        let session_id = value::required_str(params, "session_id")?;
        let volume = lock(&self.sessions)
            .get(session_id)
            .cloned()
            .ok_or_else(|| Error::new("INVALID_SESSION", "filesystem session does not exist"))?;
        let node_id = value::required_str(params, "node_id")?;
        match method {
            Method::Children => Ok(Value::Array(
                volume
                    .children(node_id)?
                    .iter()
                    .map(FsNode::to_value)
                    .collect(),
            )),
            Method::ChildrenPage => {
                let limit =
                    usize::try_from(value::required_u64(params, "limit")?).unwrap_or(usize::MAX);
                let cursor = value::optional_str(params, "cursor");
                Ok(volume.children_page(node_id, limit, cursor)?.to_value())
            }
            Method::Stat => Ok(volume.stat(node_id)?.to_value()),
            Method::ReadRange => {
                let offset = value::required_u64(params, "offset")?;
                let length = usize::try_from(value::required_u64(params, "length")?)
                    .map_err(|_| Error::invalid_params("length does not fit this host"))?;
                Ok(Value::Binary(volume.read(node_id, offset, length)?))
            }
            Method::Shutdown | Method::RunStart | Method::Probe | Method::Open | Method::Close => {
                Err(Error::new(
                    "METHOD_NOT_FOUND",
                    "not a filesystem session method",
                ))
            }
        }
    }

    fn source(&self, source_id: &str) -> Result<Source> {
        if let Some(source) = lock(&self.sources).get(source_id) {
            return Ok(source.clone());
        }
        let source = Source::open(self.host, source_id)?;
        let mut sources = lock(&self.sources);
        if sources.len() >= MAX_CACHED_SOURCES {
            sources.clear();
        }
        sources.insert(source_id.to_owned(), source.clone());
        Ok(source)
    }

    fn cancel(&self, call_id: u64) {
        if let Some(cancelled) = lock(&self.calls).get(&call_id) {
            cancelled.store(true, Ordering::Release);
        }
    }

    fn close_sessions(&self) {
        let sessions = std::mem::take(&mut *lock(&self.sessions));
        for volume in sessions.into_values() {
            volume.close();
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.close_sessions();
    }
}

/// Removes a call's cancellation flag when the call ends, even by panic.
struct CallRegistration<'a> {
    calls: &'a Mutex<HashMap<u64, Arc<AtomicBool>>>,
    call_id: u64,
}

impl Drop for CallRegistration<'_> {
    fn drop(&mut self) {
        lock(self.calls).remove(&self.call_id);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn no_parser() -> Error {
    Error::new("NO_PARSER", "no filesystem parser registered")
}

/// # Safety
///
/// `instance` must be null or a pointer produced by [`entry`] that has not
/// been destroyed.
unsafe fn instance_ref<'a>(instance: *mut c_void) -> Result<&'a Instance> {
    if instance.is_null() {
        Err(Error::invalid_params("null plugin instance"))
    } else {
        Ok(unsafe { &*instance.cast::<Instance>() })
    }
}

unsafe extern "C" fn describe(instance: *mut c_void, out: *mut Buffer) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let instance = unsafe { instance_ref(instance) }?;
        instance
            .plugin
            .validate()
            .map_err(|message| Error::new("PLUGIN_INVALID", message))?;
        protocol::to_value(&instance.plugin.hello())
    }));
    unsafe { reply(out, outcome) }
}

unsafe extern "C" fn call(
    instance: *mut c_void,
    call_id: u64,
    method: Bytes,
    params: Bytes,
    out: *mut Buffer,
) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let instance = unsafe { instance_ref(instance) }?;
        let method = std::str::from_utf8(unsafe { method.as_slice() })
            .map_err(|_| Error::invalid_params("method name is not UTF-8"))?;
        instance.handle(call_id, method, unsafe { params.as_slice() })
    }));
    unsafe { reply(out, outcome) }
}

unsafe extern "C" fn cancel(instance: *mut c_void, call_id: u64) {
    if let Ok(instance) = unsafe { instance_ref(instance) } {
        instance.cancel(call_id);
    }
}

unsafe extern "C" fn free_buffer(_instance: *mut c_void, buffer: *mut Buffer) {
    if !buffer.is_null() {
        unsafe { (*buffer).free_vec() };
    }
}

unsafe extern "C" fn destroy(instance: *mut c_void) {
    if instance.is_null() {
        return;
    }
    let instance = unsafe { Box::from_raw(instance.cast::<Instance>()) };
    let host = instance.host;
    if let Err(panic) = catch_unwind(AssertUnwindSafe(move || drop(instance))) {
        host.log(
            LogLevel::Error,
            &format!(
                "plugin instance teardown panicked: {}",
                panic_message(panic.as_ref())
            ),
        );
    }
}

/// Writes a reply buffer and returns its status.
///
/// # Safety
///
/// `out` must be null or point to a writable [`Buffer`].
pub(crate) unsafe fn reply(out: *mut Buffer, outcome: std::thread::Result<Result<Value>>) -> i32 {
    if out.is_null() {
        return abi::STATUS_INVALID_ARGUMENT;
    }
    let (status, payload) = match outcome {
        Ok(Ok(result)) => (abi::STATUS_OK, result),
        Ok(Err(error)) => (abi::STATUS_ERROR, error.to_value()),
        Err(panic) => (
            abi::STATUS_ERROR,
            Error::new("PLUGIN_PANIC", panic_message(panic.as_ref())).to_value(),
        ),
    };
    let (status, bytes) = match value::encode(&payload) {
        Ok(bytes) => (status, bytes),
        Err(error) => (
            abi::STATUS_ERROR,
            value::encode(&error.to_value()).unwrap_or_default(),
        ),
    };
    unsafe { out.write(Buffer::from_vec(bytes)) };
    status
}

pub(crate) fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "plugin panicked".to_owned()
    }
}
