//! Runs analyzers against local directories, without LovelyCarve
//! (feature `testing`). The harness plays the host side of LPP v2 through
//! the real C ABI entry point, so a test exercises exactly what the plugin
//! library does in production, and every emitted record is validated
//! against its schema.
//!
//! ```ignore
//! let run = Harness::new(plugin)
//!     .run("base", Fixture::system("linux", "tests/fixtures/rootfs"))
//!     .expect("run");
//! assert_eq!(run.count("linux.user"), 2);
//! ```

use std::{
    collections::{BTreeMap, HashMap},
    ffi::c_void,
    fs,
    mem::MaybeUninit,
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use rmpv::Value;

use crate::{
    abi::{self, Buffer, Bytes, HostApiV1, PluginApiV1},
    glob::Glob,
    protocol::{
        self, method, EmitAck, EmitBatch, FileHandleId, FileInfo, FileRead, FileReadv, FindPage,
        Hello, Lease, MountInfo, NodeInfo, NodePage, RunFinish, RunProgress, RunStart, RunWarn,
        SystemInfo, Target, Timestamps, ViewFind, ViewInfo, ViewList, ViewPath,
    },
    record::{Severity, SourceRef},
    schema::RecordSchema,
    value, Error, Plugin, Result,
};

/// What a test run looks at.
#[derive(Clone, Debug)]
pub enum Fixture {
    /// One operating system: `root` is `/`, `mounts` add directories at
    /// view paths (`("home", dir)`).
    System {
        family: String,
        root: PathBuf,
        mounts: Vec<(String, PathBuf)>,
    },
    /// Volumes of an evidence item: `(volume key, directory)`.
    Evidence(Vec<(String, PathBuf)>),
    /// Local files as the run's inputs.
    Files(Vec<PathBuf>),
}

impl Fixture {
    pub fn system(family: &str, root: impl Into<PathBuf>) -> Self {
        Self::System {
            family: family.to_owned(),
            root: root.into(),
            mounts: Vec::new(),
        }
    }

    /// Adds a mount to a system fixture.
    pub fn mount(mut self, path: &str, directory: impl Into<PathBuf>) -> Self {
        if let Self::System { mounts, .. } = &mut self {
            mounts.push((path.trim_matches('/').to_owned(), directory.into()));
        }
        self
    }

    pub fn evidence(volumes: &[(&str, &Path)]) -> Self {
        Self::Evidence(
            volumes
                .iter()
                .map(|(key, path)| ((*key).to_owned(), path.to_path_buf()))
                .collect(),
        )
    }

    pub fn files(paths: &[&Path]) -> Self {
        Self::Files(paths.iter().map(|path| path.to_path_buf()).collect())
    }
}

/// One emitted record, with values by field id.
#[derive(Clone, Debug, PartialEq)]
pub struct TestRecord {
    pub record_type: String,
    pub title: String,
    pub values: BTreeMap<String, Value>,
    pub severity: Option<Severity>,
    pub sources: Vec<SourceRef>,
}

impl TestRecord {
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.values.get(field).filter(|value| !value.is_nil())
    }

    pub fn text(&self, field: &str) -> Option<&str> {
        self.get(field).and_then(Value::as_str)
    }

    pub fn int(&self, field: &str) -> Option<i64> {
        self.get(field).and_then(Value::as_i64)
    }
}

/// Everything a test run produced.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TestRun {
    pub records: Vec<TestRecord>,
    /// `(code, message, input file name)`.
    pub warnings: Vec<(String, String, Option<String>)>,
    pub summary: Option<String>,
    pub progress: Vec<u64>,
}

impl TestRun {
    pub fn of_type(&self, record_type: &str) -> Vec<&TestRecord> {
        self.records
            .iter()
            .filter(|record| record.record_type == record_type)
            .collect()
    }

    pub fn count(&self, record_type: &str) -> usize {
        self.of_type(record_type).len()
    }

    /// Record counts by type.
    pub fn counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for record in &self.records {
            *counts.entry(record.record_type.clone()).or_insert(0) += 1;
        }
        counts
    }
}

/// A plugin instance served by an in-memory host.
pub struct Harness {
    api: PluginApiV1,
    host: Box<FixtureHost>,
    _table: Box<HostApiV1>,
    hello: Hello,
}

// SAFETY: the C ABI makes both tables callable from any thread.
unsafe impl Send for Harness {}

impl Harness {
    pub fn new(constructor: fn() -> Plugin) -> Self {
        let host = Box::new(FixtureHost::default());
        let table = Box::new(HostApiV1 {
            abi_version: abi::ABI_VERSION,
            struct_size: abi::HOST_API_SIZE,
            context: (&*host as *const FixtureHost).cast_mut().cast(),
            call: host_call,
            free_buffer: host_free,
            log: host_log,
        });
        let mut api = MaybeUninit::<PluginApiV1>::uninit();
        let status = unsafe { crate::runtime::entry(&*table, api.as_mut_ptr(), constructor) };
        assert_eq!(status, abi::STATUS_OK, "plugin entry point failed");
        let api = unsafe { api.assume_init() };
        let mut out = Buffer::empty();
        let status = unsafe { (api.describe)(api.instance, &mut out) };
        let described = value::decode(unsafe { out.as_slice() });
        unsafe { (api.free_buffer)(api.instance, &mut out) };
        let described = described.expect("describe reply");
        assert_eq!(
            status,
            abi::STATUS_OK,
            "describe failed: {}",
            Error::from_value(&described)
        );
        let hello: Hello = protocol::from_value(described).expect("plugin.hello");
        *lock(&host.schemas) = hello
            .records
            .iter()
            .map(|schema| (schema.record_type.clone(), schema.clone()))
            .collect();
        Self {
            api,
            host,
            _table: table,
            hello,
        }
    }

    /// What the plugin reports in `plugin.hello`.
    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    pub fn run(&self, analyzer: &str, fixture: Fixture) -> Result<TestRun> {
        self.run_with(analyzer, fixture, BTreeMap::new(), BTreeMap::new())
    }

    /// Runs `analyzer` with options and profile facts. Declared inputs are
    /// passed with [`Harness::run_with_inputs`].
    pub fn run_with(
        &self,
        analyzer: &str,
        fixture: Fixture,
        options: BTreeMap<String, Value>,
        profile: BTreeMap<String, Value>,
    ) -> Result<TestRun> {
        self.run_with_inputs(analyzer, fixture, &[], options, profile)
    }

    /// Runs `analyzer` with the files of a view fixture matching `inputs`
    /// (the analyzer's declared input patterns).
    pub fn run_with_inputs(
        &self,
        analyzer: &str,
        fixture: Fixture,
        inputs: &[&str],
        options: BTreeMap<String, Value>,
        profile: BTreeMap<String, Value>,
    ) -> Result<TestRun> {
        let host = &self.host;
        *lock(&host.output) = TestRun::default();
        let (target, files) = host.prepare(&fixture, inputs)?;
        let start = RunStart {
            run_id: "run-test".to_owned(),
            analyzer: analyzer.to_owned(),
            target,
            inputs: files,
            options,
            profile,
            locale: "zh-CN".to_owned(),
        };
        let params = protocol::encode(&start)?;
        let mut out = Buffer::empty();
        let status = unsafe {
            (self.api.call)(
                self.api.instance,
                1,
                Bytes::from_slice(method::RUN_START.as_bytes()),
                Bytes::from_slice(&params),
                &mut out,
            )
        };
        let reply = value::decode(unsafe { out.as_slice() });
        unsafe { (self.api.free_buffer)(self.api.instance, &mut out) };
        let reply = reply?;
        if status != abi::STATUS_OK {
            return Err(Error::from_value(&reply));
        }
        let finish: RunFinish = protocol::from_value(reply)?;
        let mut output = std::mem::take(&mut *lock(&host.output));
        output.summary = finish.summary;
        Ok(output)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        unsafe { (self.api.destroy)(self.api.instance) };
    }
}

#[derive(Clone)]
struct ViewMount {
    path: String,
    root: String,
    directory: PathBuf,
}

#[derive(Default)]
struct FixtureHost {
    schemas: Mutex<HashMap<String, RecordSchema>>,
    mounts: Mutex<Vec<ViewMount>>,
    files: Mutex<HashMap<String, (PathBuf, FileInfo)>>,
    output: Mutex<TestRun>,
}

impl FixtureHost {
    fn prepare(&self, fixture: &Fixture, inputs: &[&str]) -> Result<(Target, Vec<FileInfo>)> {
        lock(&self.files).clear();
        let (mounts, view) = match fixture {
            Fixture::System {
                family,
                root,
                mounts,
            } => {
                let mut table = vec![ViewMount {
                    path: String::new(),
                    root: "part:0".to_owned(),
                    directory: root.clone(),
                }];
                for (index, (path, directory)) in mounts.iter().enumerate() {
                    table.push(ViewMount {
                        path: path.clone(),
                        root: format!("part:{}", index + 1),
                        directory: directory.clone(),
                    });
                }
                let view = ViewInfo {
                    view_id: "view-test".to_owned(),
                    label: format!("{family} fixture"),
                    system: Some(SystemInfo {
                        id: format!("{family}@part:0"),
                        family: family.clone(),
                        product: format!("{family} fixture"),
                        version: None,
                        root: "part:0".to_owned(),
                    }),
                    mounts: table.iter().map(mount_info).collect(),
                };
                (table, Some(Target::System { view }))
            }
            Fixture::Evidence(volumes) => {
                let table: Vec<ViewMount> = volumes
                    .iter()
                    .map(|(key, directory)| ViewMount {
                        path: key.clone(),
                        root: key.clone(),
                        directory: directory.clone(),
                    })
                    .collect();
                let view = ViewInfo {
                    view_id: "view-test".to_owned(),
                    label: "evidence fixture".to_owned(),
                    system: None,
                    mounts: table.iter().map(mount_info).collect(),
                };
                (table, Some(Target::Evidence { view }))
            }
            Fixture::Files(paths) => {
                let files = paths
                    .iter()
                    .map(|path| self.register(path, None, "files", path_name(path)))
                    .collect::<Result<Vec<_>>>()?;
                return Ok((Target::Files, files));
            }
        };
        *lock(&self.mounts) = mounts;
        let mut files = Vec::new();
        if !inputs.is_empty() {
            let globs = inputs
                .iter()
                .map(|pattern| Glob::new(pattern).map_err(Error::invalid_params))
                .collect::<Result<Vec<_>>>()?;
            for path in self.walk("", &globs)? {
                files.push(self.open(&path)?.ok_or_else(|| Error::not_found(path))?);
            }
        }
        Ok((view.unwrap_or(Target::Files), files))
    }

    /// The local path and owning mount of a view path.
    fn resolve(&self, path: &str) -> Result<Option<(PathBuf, ViewMount, String)>> {
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        if parts.iter().any(|part| *part == ".." || *part == ".") {
            return Err(Error::new(
                "VIEW_PATH_INVALID",
                "paths must stay inside the view",
            ));
        }
        let mounts = lock(&self.mounts).clone();
        let best = mounts
            .iter()
            .filter(|mount| {
                let prefix: Vec<&str> = mount
                    .path
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .collect();
                parts.len() >= prefix.len()
                    && prefix.iter().zip(&parts).all(|(left, right)| left == right)
            })
            .max_by_key(|mount| {
                mount
                    .path
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .count()
            });
        let Some(mount) = best else {
            return Ok(None);
        };
        let depth = mount
            .path
            .split('/')
            .filter(|part| !part.is_empty())
            .count();
        let relative = parts[depth..].join("/");
        let local = parts[depth..]
            .iter()
            .fold(mount.directory.clone(), |path, part| path.join(part));
        Ok(Some((local, mount.clone(), relative)))
    }

    fn is_virtual_root(&self, path: &str) -> bool {
        path.trim_matches('/').is_empty()
            && lock(&self.mounts)
                .iter()
                .all(|mount| !mount.path.is_empty())
    }

    fn stat(&self, path: &str) -> Result<Option<NodeInfo>> {
        if self.is_virtual_root(path) {
            return Ok(Some(dir_node("")));
        }
        let Some((local, _, _)) = self.resolve(path)? else {
            return Ok(None);
        };
        Ok(fs::metadata(&local)
            .ok()
            .map(|metadata| node_info(path_name(&local), &metadata)))
    }

    fn list(&self, path: &str) -> Result<Vec<NodeInfo>> {
        let trimmed = path.trim_matches('/');
        let mut nodes = Vec::new();
        if self.is_virtual_root(path) {
            for mount in lock(&self.mounts).iter() {
                nodes.push(dir_node(&mount.path));
            }
            return Ok(nodes);
        }
        let (local, _, _) = self
            .resolve(path)?
            .ok_or_else(|| Error::new("VIEW_PATH_NOT_FOUND", format!("{path} does not exist")))?;
        let entries = fs::read_dir(&local)
            .map_err(|_| Error::new("VIEW_PATH_NOT_FOUND", format!("{path} is not a directory")))?;
        for entry in entries {
            let entry = entry?;
            let metadata = entry.metadata()?;
            nodes.push(node_info(
                entry.file_name().to_string_lossy().into_owned(),
                &metadata,
            ));
        }
        // Mount points below this directory.
        for mount in lock(&self.mounts).iter() {
            if let Some((parent, name)) = mount
                .path
                .rsplit_once('/')
                .or(Some(("", mount.path.as_str())))
            {
                if !name.is_empty()
                    && parent == trimmed
                    && !nodes.iter().any(|node| node.name == name)
                {
                    nodes.push(dir_node(name));
                }
            }
        }
        nodes.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(nodes)
    }

    fn open(&self, path: &str) -> Result<Option<FileInfo>> {
        let Some((local, mount, relative)) = self.resolve(path)? else {
            return Ok(None);
        };
        match fs::metadata(&local) {
            Ok(metadata) if metadata.is_file() => {
                let info = self.register(&local, Some(path), &mount.root, path_name(&local))?;
                let mut files = lock(&self.files);
                if let Some((_, registered)) = files.get_mut(&info.file_id) {
                    registered.root_path = Some(relative.clone());
                }
                Ok(Some(FileInfo {
                    root_path: Some(relative),
                    ..info
                }))
            }
            Ok(_) => Err(Error::new(
                "VIEW_NOT_A_FILE",
                format!("{path} is not a file"),
            )),
            Err(_) => Ok(None),
        }
    }

    fn register(
        &self,
        local: &Path,
        view_path: Option<&str>,
        root: &str,
        name: String,
    ) -> Result<FileInfo> {
        let metadata = fs::metadata(local)?;
        let mut files = lock(&self.files);
        let file_id = format!("file-{}", files.len() + 1);
        let info = FileInfo {
            file_id: file_id.clone(),
            name,
            size: metadata.len(),
            mime: None,
            view_path: view_path.map(str::to_owned),
            root: Some(root.to_owned()),
            root_path: view_path.map(str::to_owned),
            node_id: None,
            deleted: false,
            timestamps: Timestamps::default(),
        };
        files.insert(file_id, (local.to_path_buf(), info.clone()));
        Ok(info)
    }

    fn walk(&self, start: &str, globs: &[Glob]) -> Result<Vec<String>> {
        let mut found = Vec::new();
        let mut stack = vec![start.trim_matches('/').to_owned()];
        while let Some(directory) = stack.pop() {
            for node in self.list(&directory)? {
                let path = if directory.is_empty() {
                    node.name.clone()
                } else {
                    format!("{directory}/{}", node.name)
                };
                match node.kind.as_str() {
                    "dir" if globs.iter().any(|glob| glob.may_match_below(&path)) => {
                        stack.push(path)
                    }
                    "file" if globs.iter().any(|glob| glob.matches(&path)) => found.push(path),
                    _ => {}
                }
            }
        }
        found.sort();
        Ok(found)
    }

    fn read(&self, file_id: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let (path, info) = lock(&self.files)
            .get(file_id)
            .cloned()
            .ok_or_else(|| Error::new("INVALID_FILE_HANDLE", "unknown file handle"))?;
        if length > protocol::MAX_READ {
            return Err(Error::new("RESOURCE_LIMIT", "read exceeds 4 MiB"));
        }
        let available = info.size.saturating_sub(offset).min(length);
        let mut file = fs::File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; available as usize];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn emit(&self, batch: EmitBatch) -> Result<EmitAck> {
        let schemas = lock(&self.schemas);
        let mut output = lock(&self.output);
        let count = batch.records.len() as u64;
        for record in batch.records {
            let schema = schemas
                .get(&record.record_type)
                .ok_or_else(|| Error::new("UNKNOWN_RECORD_TYPE", record.record_type.clone()))?;
            schema
                .validate_values(&record.values)
                .map_err(|message| Error::new("INVALID_RECORD", message))?;
            output.records.push(TestRecord {
                title: record
                    .title
                    .clone()
                    .unwrap_or_else(|| schema.render_title(&record.values)),
                values: schema
                    .fields
                    .iter()
                    .zip(record.values)
                    .map(|(field, value)| (field.id.clone(), value))
                    .collect(),
                record_type: record.record_type,
                severity: record.severity,
                sources: record.sources,
            });
        }
        Ok(EmitAck { accepted: count })
    }

    fn answer(&self, method: &str, params: &[u8]) -> Result<Value> {
        match method {
            method::RUN_EMIT => protocol::to_value(&self.emit(protocol::decode(params)?)?),
            method::RUN_WARN => {
                let warning: RunWarn = protocol::decode(params)?;
                let file = warning.file_id.and_then(|file_id| {
                    lock(&self.files)
                        .get(&file_id)
                        .map(|(_, info)| info.name.clone())
                });
                lock(&self.output)
                    .warnings
                    .push((warning.code, warning.message, file));
                Ok(Value::Nil)
            }
            method::RUN_PROGRESS => {
                let progress: RunProgress = protocol::decode(params)?;
                lock(&self.output).progress.push(progress.current);
                Ok(Value::Nil)
            }
            method::FILE_READ => {
                let read: FileRead = protocol::decode(params)?;
                Ok(Value::Binary(self.read(
                    &read.file_id,
                    read.offset,
                    read.length,
                )?))
            }
            method::FILE_READV => {
                let read: FileReadv = protocol::decode(params)?;
                Ok(Value::Array(
                    read.ranges
                        .iter()
                        .map(|(offset, length)| {
                            self.read(&read.file_id, *offset, *length)
                                .map(Value::Binary)
                        })
                        .collect::<Result<Vec<_>>>()?,
                ))
            }
            method::FILE_MATERIALIZE => {
                let handle: FileHandleId = protocol::decode(params)?;
                let (path, info) = lock(&self.files)
                    .get(&handle.file_id)
                    .cloned()
                    .ok_or_else(|| Error::new("INVALID_FILE_HANDLE", "unknown file handle"))?;
                protocol::to_value(&Lease {
                    lease_id: format!("lease-{}", handle.file_id),
                    path: path.to_string_lossy().into_owned(),
                    size: info.size,
                })
            }
            method::FILE_RELEASE => Ok(Value::Nil),
            method::VIEW_STAT => {
                let request: ViewPath = protocol::decode(params)?;
                protocol::to_value(&self.stat(&request.path)?)
            }
            method::VIEW_LIST => {
                let request: ViewList = protocol::decode(params)?;
                let nodes = self.list(&request.path)?;
                let total = nodes.len() as u64;
                protocol::to_value(&NodePage {
                    nodes: nodes
                        .into_iter()
                        .skip(request.skip as usize)
                        .take(request.limit.min(protocol::MAX_LIST_PAGE) as usize)
                        .collect(),
                    total,
                })
            }
            method::VIEW_OPEN => {
                let request: ViewPath = protocol::decode(params)?;
                protocol::to_value(&self.open(&request.path)?)
            }
            method::VIEW_FIND => {
                let request: ViewFind = protocol::decode(params)?;
                let globs = request
                    .patterns
                    .iter()
                    .map(|pattern| Glob::new(pattern).map_err(Error::invalid_params))
                    .collect::<Result<Vec<_>>>()?;
                let paths = self.walk("", &globs)?;
                protocol::to_value(&FindPage {
                    visited: paths.len() as u64,
                    paths,
                    cursor: None,
                })
            }
            other => Err(Error::new("METHOD_NOT_FOUND", other)),
        }
    }
}

fn mount_info(mount: &ViewMount) -> MountInfo {
    MountInfo {
        path: mount.path.clone(),
        root: mount.root.clone(),
        source: "fixture".to_owned(),
    }
}

fn path_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn dir_node(name: &str) -> NodeInfo {
    NodeInfo {
        name: name.to_owned(),
        kind: "dir".to_owned(),
        size: 0,
        deleted: false,
        link_target: None,
        timestamps: Timestamps::default(),
    }
}

fn node_info(name: String, metadata: &fs::Metadata) -> NodeInfo {
    NodeInfo {
        name,
        kind: if metadata.is_dir() {
            "dir"
        } else if metadata.is_file() {
            "file"
        } else {
            "other"
        }
        .to_owned(),
        size: if metadata.is_file() {
            metadata.len()
        } else {
            0
        },
        deleted: false,
        link_target: None,
        timestamps: Timestamps::default(),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

unsafe extern "C" fn host_call(
    context: *mut c_void,
    method: Bytes,
    params: Bytes,
    out: *mut Buffer,
) -> i32 {
    let host = unsafe { &*context.cast::<FixtureHost>() };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let method = std::str::from_utf8(unsafe { method.as_slice() })
            .map_err(|_| Error::invalid_params("method name is not UTF-8"))?;
        host.answer(method, unsafe { params.as_slice() })
    }));
    unsafe { crate::runtime::reply(out, outcome) }
}

unsafe extern "C" fn host_free(_context: *mut c_void, buffer: *mut Buffer) {
    if !buffer.is_null() {
        unsafe { (*buffer).free_vec() };
    }
}

unsafe extern "C" fn host_log(_context: *mut c_void, _level: u32, message: Bytes) {
    let message = String::from_utf8_lossy(unsafe { message.as_slice() });
    eprintln!("plugin log: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Record, Run};

    #[derive(Record)]
    #[record(id = "test.user", label = "用户", title = "{name} ({uid})")]
    struct User {
        #[field(label = "用户名", key)]
        name: String,
        #[field(label = "UID")]
        uid: i64,
        #[field(label = "主目录", kind = "path")]
        home: Option<String>,
    }

    #[derive(Record)]
    #[record(id = "test.history", label = "历史命令")]
    struct History {
        #[field(label = "用户", key)]
        user: String,
        #[field(label = "命令")]
        command: String,
        #[field(label = "行号")]
        line: u64,
    }

    #[derive(Record)]
    #[record(id = "test.undeclared", label = "未注册")]
    struct Undeclared {
        #[field(label = "值")]
        value: String,
    }

    fn users(run: &Run) -> Result<()> {
        let view = run.require_view()?;
        let passwd = view
            .open("etc/passwd")?
            .ok_or_else(|| Error::not_found("etc/passwd"))?;
        for (index, line) in passwd.read_lines(1 << 20)?.iter().enumerate() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                run.warn_file(
                    &passwd,
                    "MALFORMED_LINE",
                    format!("第 {} 行字段不足", index + 1),
                )?;
                continue;
            }
            let home = parts[5].trim_start_matches('/');
            run.record(&User {
                name: parts[0].to_owned(),
                uid: parts[2].parse().unwrap_or(-1),
                home: Some(parts[5].to_owned()),
            })
            .from(&passwd)
            .note(format!("第 {} 行", index + 1))
            .emit()?;
            if let Some(history) = view.open(&format!("{home}/.bash_history"))? {
                for (number, command) in history.read_lines(1 << 20)?.iter().enumerate() {
                    run.emit_from(
                        &history,
                        &History {
                            user: parts[0].to_owned(),
                            command: command.clone(),
                            line: number as u64 + 1,
                        },
                    )?;
                }
            }
        }
        let hostname = view.read_text("etc/hostname", 256)?.unwrap_or_default();
        run.provide("hostname", hostname.trim())?;
        run.progress(1, Some(1), None)?;
        run.set_summary(format!("{} records", run.emitted()));
        Ok(())
    }

    fn inputs(run: &Run) -> Result<()> {
        for input in run.inputs() {
            run.record(&History {
                user: input.name().to_owned(),
                command: input.read_text(64)?,
                line: 1,
            })
            .from(input)
            .at(0, input.size())
            .emit()?;
        }
        Ok(())
    }

    fn undeclared(run: &Run) -> Result<()> {
        run.emit(&Undeclared {
            value: "x".to_owned(),
        })
    }

    fn test_plugin() -> Plugin {
        Plugin::new("org.test.harness")
            .record::<User>()
            .record::<History>()
            .analyzer("users", users)
            .analyzer("inputs", inputs)
            .analyzer("undeclared", undeclared)
    }

    fn write(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("directories");
        fs::write(path, content).expect("fixture file");
    }

    #[test]
    fn hello_describes_analyzers_and_record_schemas() {
        let harness = Harness::new(test_plugin);
        let hello = harness.hello();
        assert_eq!(hello.plugin, "org.test.harness");
        assert_eq!(hello.analyzers, vec!["users", "inputs", "undeclared"]);
        assert_eq!(
            hello
                .records
                .iter()
                .map(|schema| schema.record_type.as_str())
                .collect::<Vec<_>>(),
            vec!["profile.fact", "test.user", "test.history"]
        );
        assert_eq!(
            hello.schema_hash,
            crate::schema::schema_hash(&hello.records)
        );
        assert_eq!(
            User::schema().fields[2].kind,
            crate::schema::FieldKind::Path
        );
    }

    #[test]
    fn system_runs_read_through_mounts_and_keep_provenance() {
        let root = tempfile::tempdir().expect("root");
        let home = tempfile::tempdir().expect("home");
        write(
            &root.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nbroken\nkali:x:1000:1000::/home/kali:/bin/zsh\n",
        );
        write(&root.path().join("etc/hostname"), "forensic-box\n");
        write(&root.path().join("root/.bash_history"), "id\n");
        write(&home.path().join("kali/.bash_history"), "ls\nsudo -i\n");
        let harness = Harness::new(test_plugin);
        let run = harness
            .run(
                "users",
                Fixture::system("linux", root.path()).mount("home", home.path()),
            )
            .expect("run");
        assert_eq!(
            run.counts(),
            BTreeMap::from([
                ("profile.fact".to_owned(), 1),
                ("test.history".to_owned(), 3),
                ("test.user".to_owned(), 2),
            ])
        );
        let kali = &run.of_type("test.user")[1];
        assert_eq!(kali.title, "kali (1000)");
        assert_eq!(kali.sources[0].root.as_deref(), Some("part:0"));
        assert_eq!(kali.sources[0].path.as_deref(), Some("etc/passwd"));
        assert_eq!(kali.sources[0].note.as_deref(), Some("第 3 行"));
        let sudo = run
            .of_type("test.history")
            .into_iter()
            .find(|record| record.text("command") == Some("sudo -i"))
            .expect("history from the mounted /home");
        assert_eq!(sudo.sources[0].root.as_deref(), Some("part:1"));
        assert_eq!(sudo.sources[0].path.as_deref(), Some("kali/.bash_history"));
        assert_eq!(sudo.int("line"), Some(2));
        assert_eq!(
            run.of_type("profile.fact")[0].text("value"),
            Some("forensic-box")
        );
        assert_eq!(
            run.warnings,
            vec![(
                "MALFORMED_LINE".to_owned(),
                "第 2 行字段不足".to_owned(),
                Some("passwd".to_owned())
            )]
        );
        assert_eq!(run.progress, vec![1]);
        assert_eq!(run.summary.as_deref(), Some("6 records"));
    }

    #[test]
    fn declared_inputs_and_file_runs_attach_their_files() {
        let volume = tempfile::tempdir().expect("volume");
        write(
            &volume.path().join("data/log/canbus/adas_can.asc"),
            "base hex",
        );
        write(&volume.path().join("data/log/other.txt"), "ignored");
        let harness = Harness::new(test_plugin);
        let run = harness
            .run_with_inputs(
                "inputs",
                Fixture::evidence(&[("part:1", volume.path())]),
                &["part:1/**/*_can.asc"],
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .expect("run");
        assert_eq!(run.count("test.history"), 1);
        let record = &run.records[0];
        assert_eq!(record.text("command"), Some("base hex"));
        assert_eq!(
            record.sources[0],
            SourceRef {
                root: Some("part:1".to_owned()),
                path: Some("data/log/canbus/adas_can.asc".to_owned()),
                node_id: None,
                offset: Some(0),
                length: Some(8),
                note: None,
            }
        );

        let file = volume.path().join("data/log/other.txt");
        let run = harness
            .run("inputs", Fixture::files(&[file.as_path()]))
            .expect("file run");
        assert_eq!(run.records[0].text("user"), Some("other.txt"));
    }

    #[test]
    fn unregistered_record_types_fail_the_run() {
        let harness = Harness::new(test_plugin);
        let error = harness
            .run("undeclared", Fixture::files(&[]))
            .expect_err("unregistered type");
        assert_eq!(error.code, "UNKNOWN_RECORD_TYPE");
        let error = harness
            .run("missing", Fixture::files(&[]))
            .expect_err("unknown analyzer");
        assert_eq!(error.code, "INVALID_ANALYZER");
    }
}
