//! LPP frames on one side, a plugin's C ABI on the other (feature
//! `loader`).
//!
//! `lc-plugin-host` serves a plugin library this way over its stdin and
//! stdout; LovelyCarve's tests serve an entry point over in-memory pipes
//! (a loopback transport), so they exercise the same protocol path as a
//! plugin process without starting one.

use std::{
    collections::HashMap,
    ffi::c_void,
    io::{self, Read, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex, MutexGuard, PoisonError,
    },
    thread,
};

use rmpv::Value;

use crate::{
    abi::{self, Buffer, Bytes, EntryFn, HostApiV1},
    loader::PluginInstance,
    protocol, value,
    wire::{self, LppMessage, RpcError, MAX_FRAME_SIZE},
    Error,
};

/// Plugin calls may recurse deeply in parsers of hostile data.
const WORKER_STACK_SIZE: usize = 8 * 1024 * 1024;

type Reply = Result<Value, RpcError>;

/// Serves the plugin behind `entry` until the host sends `plugin.shutdown`
/// or closes `input`.
pub fn serve(
    entry: EntryFn,
    mut input: impl Read,
    output: Box<dyn Write + Send>,
) -> io::Result<()> {
    let bridge = Arc::new(Bridge {
        output: Mutex::new(output),
        pending: Mutex::default(),
        next_request_id: AtomicU64::new(3),
        closed: AtomicBool::new(false),
    });
    // The plugin may call the host from its own threads until the process
    // exits, so the table and its context live for the rest of the process.
    let host: &'static HostApiV1 = Box::leak(Box::new(HostApiV1 {
        abi_version: abi::ABI_VERSION,
        struct_size: abi::HOST_API_SIZE,
        context: Arc::into_raw(Arc::clone(&bridge)).cast_mut().cast(),
        call: host_call,
        free_buffer: host_free_buffer,
        log: host_log,
    }));
    let plugin = Arc::new(unsafe { PluginInstance::create(entry, host) }.map_err(plugin_error)?);
    let hello = plugin.describe().map_err(plugin_error)?;
    bridge.handshake(&mut input, hello)?;
    let outcome = bridge.serve_requests(&mut input, &plugin);
    bridge.close();
    outcome
}

/// The library's `plugin.hello`. The library runs with a host table that
/// refuses every call, so describing reads no evidence.
pub fn describe(entry: EntryFn) -> crate::Result<protocol::Hello> {
    let host: &'static HostApiV1 = Box::leak(Box::new(HostApiV1 {
        abi_version: abi::ABI_VERSION,
        struct_size: abi::HOST_API_SIZE,
        context: std::ptr::null_mut(),
        call: refusing_host_call,
        free_buffer: host_free_buffer,
        log: host_log,
    }));
    let plugin = unsafe { PluginInstance::create(entry, host) }?;
    protocol::from_value(plugin.describe()?)
}

unsafe extern "C" fn refusing_host_call(
    _context: *mut c_void,
    _method: Bytes,
    _params: Bytes,
    out: *mut Buffer,
) -> i32 {
    if out.is_null() {
        return abi::STATUS_INVALID_ARGUMENT;
    }
    let error = Error::new("HOST_UNAVAILABLE", "describe mode serves no host calls");
    match value::encode(&error.to_value()) {
        Ok(bytes) => {
            unsafe { out.write(Buffer::from_vec(bytes)) };
            abi::STATUS_ERROR
        }
        Err(_) => abi::STATUS_INVALID_ARGUMENT,
    }
}

struct Bridge {
    output: Mutex<Box<dyn Write + Send>>,
    /// Plugin → host requests waiting for their response.
    pending: Mutex<HashMap<u64, mpsc::SyncSender<Reply>>>,
    next_request_id: AtomicU64,
    closed: AtomicBool,
}

impl Bridge {
    fn handshake(&self, input: &mut impl Read, hello: Value) -> io::Result<()> {
        self.send(&LppMessage::request(1, protocol::method::HELLO, hello))?;
        match wire::read_frame(input)? {
            Some(LppMessage::Response {
                id: 1, error: None, ..
            }) => Ok(()),
            Some(LppMessage::Response {
                id: 1,
                error: Some(error),
                ..
            }) => Err(io::Error::other(format!(
                "host rejected plugin.hello: {}: {}",
                error.code, error.message
            ))),
            Some(message) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected the plugin.hello response, received {message:?}"),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "host closed the connection during the handshake",
            )),
        }
    }

    fn serve_requests(
        self: &Arc<Self>,
        input: &mut impl Read,
        plugin: &Arc<PluginInstance>,
    ) -> io::Result<()> {
        while let Some(message) = wire::read_frame(input)? {
            match message {
                LppMessage::Request {
                    id, method, params, ..
                } if id % 2 == 0 => {
                    if method == protocol::method::SHUTDOWN {
                        // Close sessions, answer, then let the process exit.
                        return self.send_reply(id, respond(plugin, id, &method, &params));
                    }
                    self.spawn_request(plugin, id, method, params);
                }
                LppMessage::Response {
                    id, result, error, ..
                } if id % 2 == 1 => self.complete(id, result, error),
                LppMessage::Cancel { request_id, .. } => plugin.cancel(request_id),
                LppMessage::Event { .. } => {}
                LppMessage::Request { .. } | LppMessage::Response { .. } => {
                    log_line("WARN ignored an LPP message with the wrong request-id parity");
                }
            }
        }
        Ok(())
    }

    fn spawn_request(
        self: &Arc<Self>,
        plugin: &Arc<PluginInstance>,
        id: u64,
        method: String,
        params: Value,
    ) {
        let bridge = Arc::clone(self);
        let plugin = Arc::clone(plugin);
        let spawned = thread::Builder::new()
            .name(format!("lpp-request-{id}"))
            .stack_size(WORKER_STACK_SIZE)
            .spawn(move || {
                let reply = respond(&plugin, id, &method, &params);
                if let Err(error) = bridge.send_reply(id, reply) {
                    log_line(&format!("WARN could not answer request {id}: {error}"));
                }
            });
        if let Err(error) = spawned {
            let reply = LppMessage::failure(
                id,
                RpcError::new(
                    "PLUGIN_BUSY",
                    format!("could not start a worker thread: {error}"),
                ),
            );
            if let Err(error) = self.send(&reply) {
                log_line(&format!("WARN could not answer request {id}: {error}"));
            }
        }
    }

    /// Sends a reply, replacing one that exceeds the frame limit with a
    /// `RESOURCE_LIMIT` failure.
    fn send_reply(&self, id: u64, reply: LppMessage) -> io::Result<()> {
        match wire::encode_frame(&reply) {
            Ok(frame) => self.write(&frame),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                self.send(&LppMessage::failure(
                    id,
                    RpcError::new(
                        "RESOURCE_LIMIT",
                        format!("plugin reply exceeds the {MAX_FRAME_SIZE}-byte LPP frame limit"),
                    ),
                ))
            }
            Err(error) => Err(error),
        }
    }

    fn send(&self, message: &LppMessage) -> io::Result<()> {
        self.write(&wire::encode_frame(message)?)
    }

    fn write(&self, frame: &[u8]) -> io::Result<()> {
        let mut output = lock(&self.output);
        output.write_all(frame)?;
        output.flush()
    }

    /// Plugin → host call; blocks until the host answers or disconnects.
    fn call_host(&self, method: &str, params: Value) -> Reply {
        let id = self.next_request_id.fetch_add(2, Ordering::Relaxed);
        let (sender, receiver) = mpsc::sync_channel(1);
        lock(&self.pending).insert(id, sender);
        // `close` sets the flag before sweeping `pending`, so either the sweep
        // sees this request or this check sees the flag.
        if self.closed.load(Ordering::SeqCst) {
            lock(&self.pending).remove(&id);
            return Err(connection_closed());
        }
        if let Err(error) = self.send(&LppMessage::request(id, method, params)) {
            lock(&self.pending).remove(&id);
            return Err(RpcError::new("CONNECTION_CLOSED", error.to_string()));
        }
        receiver.recv().unwrap_or_else(|_| Err(connection_closed()))
    }

    fn complete(&self, id: u64, result: Option<Value>, error: Option<RpcError>) {
        let Some(sender) = lock(&self.pending).remove(&id) else {
            log_line(&format!("DEBUG response {id} has no waiting plugin call"));
            return;
        };
        let reply = match error {
            Some(error) => Err(error),
            None => Ok(result.unwrap_or(Value::Nil)),
        };
        if sender.send(reply).is_err() {
            log_line(&format!(
                "DEBUG plugin call {id} stopped waiting for its response"
            ));
        }
    }

    /// Fails every waiting plugin → host call.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let pending = std::mem::take(&mut *lock(&self.pending));
        for (id, sender) in pending {
            if sender.send(Err(connection_closed())).is_err() {
                log_line(&format!(
                    "DEBUG plugin call {id} stopped waiting for its response"
                ));
            }
        }
    }
}

fn respond(plugin: &PluginInstance, id: u64, method: &str, params: &Value) -> LppMessage {
    match plugin.call(id, method, params, MAX_FRAME_SIZE) {
        Ok(result) => LppMessage::success(id, result),
        Err(error) => LppMessage::failure(id, RpcError::new(error.code, error.message)),
    }
}

unsafe extern "C" fn host_call(
    context: *mut c_void,
    method: Bytes,
    params: Bytes,
    out: *mut Buffer,
) -> i32 {
    if context.is_null() || out.is_null() {
        return abi::STATUS_INVALID_ARGUMENT;
    }
    let bridge = unsafe { &*context.cast::<Bridge>() };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let method = std::str::from_utf8(unsafe { method.as_slice() })
            .map_err(|_| RpcError::new("INVALID_PARAMS", "method name is not UTF-8"))?;
        let params = value::decode(unsafe { params.as_slice() })
            .map_err(|error| RpcError::new(error.code, error.message))?;
        bridge.call_host(method, params)
    }));
    let (status, payload) = match outcome {
        Ok(Ok(result)) => (abi::STATUS_OK, result),
        Ok(Err(error)) => (
            abi::STATUS_ERROR,
            Error::new(error.code, error.message).to_value(),
        ),
        Err(_) => (abi::STATUS_PANIC, Value::Nil),
    };
    match value::encode(&payload) {
        Ok(bytes) => {
            unsafe { out.write(Buffer::from_vec(bytes)) };
            status
        }
        Err(_) => abi::STATUS_INVALID_ARGUMENT,
    }
}

unsafe extern "C" fn host_free_buffer(_context: *mut c_void, buffer: *mut Buffer) {
    if !buffer.is_null() {
        unsafe { (*buffer).free_vec() };
    }
}

unsafe extern "C" fn host_log(_context: *mut c_void, level: u32, message: Bytes) {
    let label = match level {
        abi::LOG_ERROR => "ERROR",
        abi::LOG_WARN => "WARN",
        abi::LOG_INFO => "INFO",
        _ => "DEBUG",
    };
    let message = String::from_utf8_lossy(unsafe { message.as_slice() });
    log_line(&format!("{label} {message}"));
}

/// One stderr line; LovelyCarve records it as plugin log output.
fn log_line(line: &str) {
    let mut stderr = io::stderr().lock();
    if writeln!(stderr, "{line}").is_err() {
        // The host closed stderr; there is no channel left to report on.
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn connection_closed() -> RpcError {
    RpcError::new(
        "CONNECTION_CLOSED",
        "LovelyCarve closed the plugin connection",
    )
}

fn plugin_error(error: Error) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{PipeReader, PipeWriter},
        thread::JoinHandle,
        time::Duration,
    };

    use crate::{abi::PluginApiV1, runtime, Plugin, Run};

    use super::*;

    /// Reads the first input's head into the summary; `wait` blocks until
    /// the run is cancelled.
    fn head(run: &Run) -> crate::Result<()> {
        let file = run
            .inputs()
            .first()
            .ok_or_else(|| Error::invalid_params("no input"))?;
        if file.name() == "wait" {
            run.progress(1, None, None)?;
            while !run.is_cancelled() {
                thread::sleep(Duration::from_millis(2));
            }
            return Err(Error::cancelled());
        }
        let head = file.read_at(0, 4)?;
        run.set_summary(String::from_utf8_lossy(&head));
        Ok(())
    }

    fn test_plugin() -> Plugin {
        Plugin::new("org.test.bridge").analyzer("head", head)
    }

    unsafe extern "C" fn test_entry(host: *const HostApiV1, plugin: *mut PluginApiV1) -> i32 {
        unsafe { runtime::entry(host, plugin, test_plugin) }
    }

    /// Plays LovelyCarve's side of the pipes.
    struct FakeHost {
        to_plugin: PipeWriter,
        from_plugin: PipeReader,
        server: Option<JoinHandle<io::Result<()>>>,
    }

    impl FakeHost {
        fn start() -> Self {
            let (plugin_input, to_plugin) = io::pipe().expect("pipe");
            let (from_plugin, plugin_output) = io::pipe().expect("pipe");
            let server =
                thread::spawn(move || serve(test_entry, plugin_input, Box::new(plugin_output)));
            let mut host = Self {
                to_plugin,
                from_plugin,
                server: Some(server),
            };
            let LppMessage::Request {
                id: 1,
                method,
                params,
                ..
            } = host.receive()
            else {
                panic!("expected plugin.hello");
            };
            assert_eq!(method, protocol::method::HELLO);
            let hello: protocol::Hello = protocol::from_value(params).expect("hello");
            assert_eq!(hello.plugin, "org.test.bridge");
            assert_eq!(hello.protocol, wire::PROTOCOL_VERSION);
            host.send(LppMessage::success(1, Value::Nil));
            host
        }

        fn send(&mut self, message: LppMessage) {
            wire::write_frame(&mut self.to_plugin, &message).expect("send frame");
        }

        fn receive(&mut self) -> LppMessage {
            wire::read_frame(&mut self.from_plugin)
                .expect("read frame")
                .expect("frame before end of stream")
        }

        fn analyze(&mut self, id: u64, name: &str) {
            let start = protocol::RunStart {
                run_id: "run-1".to_owned(),
                analyzer: "head".to_owned(),
                target: protocol::Target::Files,
                inputs: vec![protocol::FileInfo {
                    file_id: "file_1".to_owned(),
                    name: name.to_owned(),
                    size: 4,
                    mime: None,
                    view_path: None,
                    root: None,
                    root_path: None,
                    node_id: None,
                    deleted: false,
                    timestamps: protocol::Timestamps::default(),
                }],
                options: Default::default(),
                profile: Default::default(),
                locale: "zh-CN".to_owned(),
            };
            self.send(LppMessage::request(
                id,
                protocol::method::RUN_START,
                protocol::to_value(&start).expect("run.start"),
            ));
        }

        fn shutdown(mut self) {
            self.send(LppMessage::request(
                100,
                protocol::method::SHUTDOWN,
                Value::Map(Vec::new()),
            ));
            assert!(matches!(
                self.receive(),
                LppMessage::Response {
                    id: 100,
                    error: None,
                    ..
                }
            ));
            self.server
                .take()
                .expect("server")
                .join()
                .expect("server thread")
                .expect("serve");
        }
    }

    #[test]
    fn describe_reports_the_plugin_without_a_host() {
        let hello = describe(test_entry).expect("describe");
        assert_eq!(hello.plugin, "org.test.bridge");
        assert_eq!(hello.analyzers, vec!["head"]);
    }

    #[test]
    fn nested_host_reads_are_answered_over_the_same_pipes() {
        let mut host = FakeHost::start();
        host.analyze(2, "a.bin");
        let LppMessage::Request { id, method, .. } = host.receive() else {
            panic!("expected file.read");
        };
        assert_eq!(method, protocol::method::FILE_READ);
        assert_eq!(id % 2, 1);
        host.send(LppMessage::success(id, Value::Binary(b"kali".to_vec())));
        let LppMessage::Response {
            id: 2,
            result: Some(result),
            error: None,
            ..
        } = host.receive()
        else {
            panic!("expected the analysis result");
        };
        assert_eq!(value::optional_str(&result, "summary"), Some("kali"));
        host.shutdown();
    }

    #[test]
    fn host_cancel_stops_a_running_call() {
        let mut host = FakeHost::start();
        host.analyze(2, "wait");
        let LppMessage::Request { id, method, .. } = host.receive() else {
            panic!("expected run.progress");
        };
        assert_eq!(method, protocol::method::RUN_PROGRESS);
        host.send(LppMessage::success(id, Value::Nil));
        host.send(LppMessage::Cancel {
            v: wire::PROTOCOL_VERSION,
            request_id: 2,
        });
        let LppMessage::Response {
            id: 2,
            error: Some(error),
            ..
        } = host.receive()
        else {
            panic!("expected a cancellation failure");
        };
        assert_eq!(error.code, "CANCELLED");
        host.shutdown();
    }

    #[test]
    fn closing_the_input_ends_the_session() {
        let host = FakeHost::start();
        let FakeHost {
            to_plugin, server, ..
        } = host;
        drop(to_plugin);
        server
            .expect("server")
            .join()
            .expect("server thread")
            .expect("clean end of stream");
    }
}
