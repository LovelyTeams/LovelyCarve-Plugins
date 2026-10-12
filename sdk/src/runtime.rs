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
    value, Error, Evidence, File, Plugin, Result, Source, Volume,
};

/// Probed sources kept for the following `fs.open`.
const MAX_CACHED_SOURCES: usize = 16;

/// Exports `$constructor: fn() -> Plugin` as the plugin entry point
/// [`crate::abi::ENTRY_SYMBOL`]. Use it once per plugin library.
#[macro_export]
macro_rules! export_plugin {
    ($constructor:path) => {
        /// LovelyCarve plugin entry point (C ABI v1).
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
    Probe,
    Open,
    Close,
    Children,
    ChildrenPage,
    Stat,
    ReadRange,
    AnalyzeFile,
    AnalyzeEvidence,
}

impl Method {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "plugin.shutdown" => Self::Shutdown,
            "fs.probe" => Self::Probe,
            "fs.open" => Self::Open,
            "fs.close" => Self::Close,
            "fs.children" => Self::Children,
            "fs.children_page" => Self::ChildrenPage,
            "fs.stat" => Self::Stat,
            "fs.read_range" => Self::ReadRange,
            "analyzer.analyze" => Self::AnalyzeFile,
            "analyzer.analyze_evidence" => Self::AnalyzeEvidence,
            _ => return None,
        })
    }
}

struct Instance {
    plugin: Plugin,
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
            plugin,
            host,
            sources: Mutex::default(),
            selected_parsers: Mutex::default(),
            sessions: Mutex::default(),
            next_session: AtomicU64::new(1),
            calls: Mutex::default(),
        }
    }

    fn handle(&self, call_id: u64, method: &str, params: &Value) -> Result<Value> {
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
        self.dispatch(&context, method, params)
    }

    fn dispatch(&self, context: &Context, method: Method, params: &Value) -> Result<Value> {
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
            Method::AnalyzeFile => {
                let analyzer_id = value::required_str(params, "analyzer")?;
                let analyzer = self
                    .plugin
                    .file_analyzers
                    .iter()
                    .find(|analyzer| analyzer.analyzer() == analyzer_id)
                    .ok_or_else(|| {
                        Error::new(
                            "INVALID_ANALYZER",
                            format!("unknown analyzer {analyzer_id}"),
                        )
                    })?;
                let handle = value::get(params, "file")
                    .ok_or_else(|| Error::invalid_params("missing file handle"))?;
                let file = File::from_params(context.clone(), handle)?;
                Ok(analyzer.analyze(&file)?.to_value())
            }
            Method::AnalyzeEvidence => {
                let analyzer_id = value::required_str(params, "analyzer")?;
                let analyzer = self
                    .plugin
                    .evidence_analyzers
                    .iter()
                    .find(|analyzer| analyzer.analyzer() == analyzer_id)
                    .ok_or_else(|| {
                        Error::new(
                            "INVALID_ANALYZER",
                            format!("unknown evidence analyzer {analyzer_id}"),
                        )
                    })?;
                let handle = value::get(params, "evidence")
                    .ok_or_else(|| Error::invalid_params("missing evidence handle"))?;
                let evidence = Evidence::from_params(context.clone(), handle)?;
                Ok(analyzer.analyze_evidence(&evidence)?.to_value())
            }
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
            Method::Shutdown
            | Method::Probe
            | Method::Open
            | Method::Close
            | Method::AnalyzeFile
            | Method::AnalyzeEvidence => Err(Error::new(
                "METHOD_NOT_FOUND",
                "not a filesystem session method",
            )),
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
        Ok(instance.plugin.describe())
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
        let params = value::decode(unsafe { params.as_slice() })?;
        instance.handle(call_id, method, &params)
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
unsafe fn reply(out: *mut Buffer, outcome: std::thread::Result<Result<Value>>) -> i32 {
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

fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "plugin panicked".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::{mem::MaybeUninit, thread, time::Duration};

    use super::*;
    use crate::{
        AnalysisResult, Artifact, Attributes, EvidenceAnalyzer, FileAnalyzer, FileSystemParser,
        FsStat, NodeKind,
    };

    /// In-memory host: one source, one logical file and one evidence root.
    struct MockHost {
        data: Vec<u8>,
        progress: Mutex<Vec<u64>>,
    }

    impl MockHost {
        fn answer(&self, method: &str, params: &Value) -> Result<Value> {
            let slice = |offset: u64, length: u64| {
                let start = (offset as usize).min(self.data.len());
                let end = start.saturating_add(length as usize).min(self.data.len());
                Value::Binary(self.data[start..end].to_vec())
            };
            match method {
                "source.info" => Ok(value::map([
                    ("size", Value::from(self.data.len() as u64)),
                    ("sector_size", Value::from(512_u64)),
                ])),
                "source.read" | "file.read" | "evidence.read" => Ok(slice(
                    value::required_u64(params, "offset")?,
                    value::required_u64(params, "length")?,
                )),
                "host.progress" => {
                    lock(&self.progress).push(value::required_u64(params, "current")?);
                    Ok(Value::Nil)
                }
                "evidence.roots" => Ok(Value::Array(vec![value::map([(
                    "root_id",
                    Value::from("part:0"),
                )])])),
                "evidence.stat" => match value::required_str(params, "path")? {
                    "etc/hostname" => Ok(value::map([
                        ("name", Value::from("hostname")),
                        ("kind", Value::from("file")),
                        ("size", Value::from(self.data.len() as u64)),
                    ])),
                    _ => Ok(Value::Nil),
                },
                _ => Err(Error::new("METHOD_NOT_FOUND", method)),
            }
        }
    }

    unsafe extern "C" fn host_call(
        context: *mut c_void,
        method: Bytes,
        params: Bytes,
        out: *mut Buffer,
    ) -> i32 {
        let host = unsafe { &*context.cast::<MockHost>() };
        let method = std::str::from_utf8(unsafe { method.as_slice() }).expect("method");
        let params = value::decode(unsafe { params.as_slice() }).expect("params");
        unsafe { reply(out, Ok(host.answer(method, &params))) }
    }

    unsafe extern "C" fn host_free(_context: *mut c_void, buffer: *mut Buffer) {
        unsafe { (*buffer).free_vec() };
    }

    unsafe extern "C" fn host_log(_context: *mut c_void, _level: u32, _message: Bytes) {}

    struct Magic;

    impl FileAnalyzer for Magic {
        fn analyzer(&self) -> &str {
            "test.magic"
        }

        fn analyze(&self, file: &crate::File) -> Result<AnalysisResult> {
            let head = file.read(0, 4)?;
            if head == b"boom" {
                panic!("boom requested");
            }
            Ok(AnalysisResult {
                summary: Some(String::from_utf8_lossy(&head).into_owned()),
                artifacts: vec![Artifact {
                    artifact_type: "test.magic".to_owned(),
                    title: file.name().to_owned(),
                    value: None,
                    attributes: Attributes::from_iter([("test.size", file.size())]),
                }],
                ..AnalysisResult::default()
            })
        }
    }

    struct Hostname;

    impl EvidenceAnalyzer for Hostname {
        fn analyzer(&self) -> &str {
            "test.hostname"
        }

        fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
            let volume = evidence
                .find_root(&["etc/hostname"], &[])?
                .ok_or_else(|| Error::not_found("no root"))?;
            evidence.progress(1, Some(2), Some("reading"))?;
            if value::get(evidence.params(), "wait").is_some() {
                while !evidence.context().is_cancelled() {
                    thread::sleep(Duration::from_millis(5));
                }
                return Err(Error::cancelled());
            }
            Ok(AnalysisResult {
                summary: volume.read_text("etc/hostname", 1024)?,
                ..AnalysisResult::default()
            })
        }
    }

    struct Raw;

    impl FileSystemParser for Raw {
        fn filesystem(&self) -> &str {
            "raw-test"
        }

        fn probe(&self, source: &Source) -> Result<Probe> {
            Ok(if source.read(0, 2)? == b"ka" {
                Probe::matched(0.5, Some("raw"))
            } else {
                Probe::no_match()
            })
        }

        fn open(&self, source: Source, _options: &Value) -> Result<Box<dyn Volume>> {
            Ok(Box::new(RawVolume(source)))
        }
    }

    struct RawVolume(Source);

    impl Volume for RawVolume {
        fn root_node(&self) -> &str {
            "root"
        }

        fn children(&self, _node_id: &str) -> Result<Vec<FsNode>> {
            let mut node = FsNode::new("data", "data.bin", NodeKind::File);
            node.size = self.0.size();
            Ok(vec![node])
        }

        fn stat(&self, _node_id: &str) -> Result<FsStat> {
            Ok(FsStat::new(self.0.size()))
        }

        fn read(&self, _node_id: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
            self.0.read(offset, length)
        }
    }

    fn test_plugin() -> Plugin {
        Plugin::new("org.test.sdk", "SDK test", "1")
            .filesystem(Raw)
            .file_analyzer(Magic)
            .evidence_analyzer(Hostname)
    }

    struct Harness {
        api: PluginApiV1,
        host: Box<MockHost>,
        _table: Box<HostApiV1>,
    }

    // SAFETY: the C ABI makes both tables callable from any thread.
    unsafe impl Send for Harness {}
    unsafe impl Sync for Harness {}

    impl Harness {
        fn new(data: &[u8]) -> Self {
            let host = Box::new(MockHost {
                data: data.to_vec(),
                progress: Mutex::default(),
            });
            let table = Box::new(HostApiV1 {
                abi_version: abi::ABI_VERSION,
                struct_size: abi::HOST_API_SIZE,
                context: (&*host as *const MockHost).cast_mut().cast(),
                call: host_call,
                free_buffer: host_free,
                log: host_log,
            });
            let mut api = MaybeUninit::<PluginApiV1>::uninit();
            let status = unsafe { entry(&*table, api.as_mut_ptr(), test_plugin) };
            assert_eq!(status, abi::STATUS_OK);
            Self {
                api: unsafe { api.assume_init() },
                host,
                _table: table,
            }
        }

        fn call(&self, call_id: u64, method: &str, params: Value) -> (i32, Value) {
            let params = value::encode(&params).expect("params");
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
            let reply = value::decode(unsafe { out.as_slice() }).expect("reply");
            unsafe { (self.api.free_buffer)(self.api.instance, &mut out) };
            (status, reply)
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            unsafe { (self.api.destroy)(self.api.instance) };
        }
    }

    #[test]
    fn describe_advertises_registered_capabilities() {
        let harness = Harness::new(b"");
        let mut out = Buffer::empty();
        let status = unsafe { (harness.api.describe)(harness.api.instance, &mut out) };
        assert_eq!(status, abi::STATUS_OK);
        let hello = value::decode(unsafe { out.as_slice() }).expect("hello");
        unsafe { (harness.api.free_buffer)(harness.api.instance, &mut out) };
        assert_eq!(
            value::get(&hello, "capabilities"),
            Some(&Value::Array(vec![
                Value::from("filesystem"),
                Value::from("file_analyzer"),
                Value::from("evidence_analyzer"),
            ]))
        );
        let identity = value::get(&hello, "plugin").expect("identity");
        assert_eq!(
            value::required_str(identity, "id").expect("id"),
            "org.test.sdk"
        );
    }

    #[test]
    fn file_analysis_reads_through_the_host() {
        let harness = Harness::new(b"kali-linux");
        let (status, result) = harness.call(
            2,
            "analyzer.analyze",
            value::map([
                ("analyzer", Value::from("test.magic")),
                (
                    "file",
                    value::map([
                        ("file_id", Value::from("file_1")),
                        ("name", Value::from("a.bin")),
                        ("size", Value::from(10_u64)),
                    ]),
                ),
            ]),
        );
        assert_eq!(status, abi::STATUS_OK);
        assert_eq!(value::optional_str(&result, "summary"), Some("kali"));
    }

    #[test]
    fn panics_become_plugin_panic_errors() {
        let harness = Harness::new(b"boom");
        let (status, error) = harness.call(
            2,
            "analyzer.analyze",
            value::map([
                ("analyzer", Value::from("test.magic")),
                (
                    "file",
                    value::map([
                        ("file_id", Value::from("file_1")),
                        ("size", Value::from(4_u64)),
                    ]),
                ),
            ]),
        );
        assert_eq!(status, abi::STATUS_ERROR);
        assert_eq!(
            Error::from_value(&error),
            Error::new("PLUGIN_PANIC", "boom requested")
        );
    }

    #[test]
    fn evidence_analysis_reports_progress_and_reads_text() {
        let harness = Harness::new(b"kali\n");
        let (status, result) = harness.call(
            2,
            "analyzer.analyze_evidence",
            value::map([
                ("analyzer", Value::from("test.hostname")),
                (
                    "evidence",
                    value::map([("evidence_id", Value::from("evidence_1"))]),
                ),
            ]),
        );
        assert_eq!(status, abi::STATUS_OK);
        assert_eq!(value::optional_str(&result, "summary"), Some("kali\n"));
        assert_eq!(*lock(&harness.host.progress), vec![1]);
    }

    #[test]
    fn cancel_reaches_the_running_call() {
        let harness = Harness::new(b"kali");
        let api = harness.api;
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                harness.call(
                    8,
                    "analyzer.analyze_evidence",
                    value::map([
                        ("analyzer", Value::from("test.hostname")),
                        (
                            "evidence",
                            value::map([
                                ("evidence_id", Value::from("evidence_1")),
                                ("params", value::map([("wait", Value::Boolean(true))])),
                            ]),
                        ),
                    ]),
                )
            });
            while lock(&harness.host.progress).is_empty() {
                thread::sleep(Duration::from_millis(1));
            }
            unsafe { (api.cancel)(api.instance, 8) };
            let (status, error) = running.join().expect("call thread");
            assert_eq!(status, abi::STATUS_ERROR);
            assert!(Error::from_value(&error).is_cancelled());
        });
    }

    #[test]
    fn filesystem_session_probes_opens_and_reads() {
        let harness = Harness::new(b"kali-linux");
        let (_, probe) = harness.call(
            2,
            "fs.probe",
            value::map([("source_id", Value::from("source_1"))]),
        );
        assert_eq!(value::optional_str(&probe, "filesystem"), Some("raw-test"));
        let (_, opened) = harness.call(
            4,
            "fs.open",
            value::map([("source_id", Value::from("source_1"))]),
        );
        let session = value::required_str(&opened, "session_id").expect("session");
        let (status, bytes) = harness.call(
            6,
            "fs.read_range",
            value::map([
                ("session_id", Value::from(session)),
                ("node_id", Value::from("data")),
                ("offset", Value::from(5_u64)),
                ("length", Value::from(100_u64)),
            ]),
        );
        assert_eq!(status, abi::STATUS_OK);
        assert_eq!(bytes, Value::Binary(b"linux".to_vec()));
        let (status, page) = harness.call(
            8,
            "fs.children_page",
            value::map([
                ("session_id", Value::from(session)),
                ("node_id", Value::from("root")),
                ("limit", Value::from(10_u64)),
            ]),
        );
        assert_eq!(status, abi::STATUS_OK);
        assert_eq!(value::get(&page, "total"), Some(&Value::from(1_u64)));
    }

    #[test]
    fn unknown_methods_report_method_not_found() {
        let harness = Harness::new(b"");
        let (status, error) = harness.call(2, "fs.unknown", Value::Nil);
        assert_eq!(status, abi::STATUS_ERROR);
        assert_eq!(Error::from_value(&error).code, "METHOD_NOT_FOUND");
    }
}
