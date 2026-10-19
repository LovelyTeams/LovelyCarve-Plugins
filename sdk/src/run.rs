//! Analyzers and the run they work in.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, PoisonError},
};

use rmpv::Value;

use crate::{
    file::FileRef,
    host::LogLevel,
    protocol::{
        self, method, EmitAck, RunFinish, RunProgress, RunStart, RunWarn, SystemInfo, Target,
        WireRecord,
    },
    record::{DynamicRecord, Record, Severity, SourceRef, PROFILE_FACT},
    schema::RecordSchema,
    view::View,
    Context, Error, Result,
};

/// Records buffered before a `run.emit` batch is sent.
const BATCH_RECORDS: usize = 1000;
/// Encoded bytes buffered before a batch is sent (well below a frame).
const BATCH_BYTES: usize = 2 * 1024 * 1024;
/// Largest single encoded record.
const MAX_RECORD_BYTES: usize = 6 * 1024 * 1024;

/// One analysis function of a plugin, registered with
/// [`crate::Plugin::analyzer`] under the id its manifest declares.
///
/// `run` executes on a host worker thread and may block. It emits records
/// as it goes ([`Run::emit`] and friends) and returns once the analysis is
/// complete; an error discards everything the run emitted. Host calls fail
/// with `CANCELLED` once the run is cancelled; CPU-only loops should poll
/// [`Run::check_cancelled`].
pub trait Analyzer: Send + Sync {
    fn run(&self, run: &Run) -> Result<()>;
}

impl<F> Analyzer for F
where
    F: Fn(&Run) -> Result<()> + Send + Sync,
{
    fn run(&self, run: &Run) -> Result<()> {
        self(run)
    }
}

/// The options a run was started with (from the analyzer's declared
/// `options`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Options {
    values: BTreeMap<String, Value>,
}

impl Options {
    pub fn new(values: BTreeMap<String, Value>) -> Self {
        Self { values }
    }

    pub fn get(&self, id: &str) -> Option<&Value> {
        self.values.get(id)
    }

    pub fn flag(&self, id: &str) -> bool {
        self.get(id).and_then(Value::as_bool).unwrap_or(false)
    }

    pub fn text(&self, id: &str) -> Option<&str> {
        self.get(id).and_then(Value::as_str)
    }

    /// The selected choices of a multi-choice option.
    pub fn list(&self, id: &str) -> Vec<String> {
        match self.get(id) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
            Some(Value::String(text)) => text.as_str().map(str::to_owned).into_iter().collect(),
            _ => Vec::new(),
        }
    }

    /// Whether `choice` of multi-choice option `id` is selected; an absent
    /// or empty selection selects every choice.
    pub fn wants(&self, id: &str, choice: &str) -> bool {
        let selected = self.list(id);
        selected.is_empty() || selected.iter().any(|item| item == choice)
    }
}

/// Evidence profile facts known when the run started.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Profile {
    values: BTreeMap<String, Value>,
}

impl Profile {
    pub fn new(values: BTreeMap<String, Value>) -> Self {
        Self { values }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.values.get(key)
    }

    pub fn text(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }

    /// IANA time zone of the system (`Asia/Shanghai`), when known.
    pub fn timezone(&self) -> Option<&str> {
        self.text("timezone")
    }

    pub fn hostname(&self) -> Option<&str> {
        self.text("hostname")
    }
}

#[derive(Default)]
struct Emitter {
    encoded: Vec<Vec<u8>>,
    bytes: usize,
    emitted: u64,
}

/// One execution of an analyzer: its target, inputs, options and the
/// channel its records go out on.
pub struct Run {
    context: Context,
    run_id: String,
    analyzer: String,
    view: Option<View>,
    inputs: Vec<FileRef>,
    options: Options,
    profile: Profile,
    locale: String,
    schemas: Arc<HashMap<String, RecordSchema>>,
    emitter: Mutex<Emitter>,
    summary: Mutex<Option<String>>,
}

impl Run {
    pub(crate) fn new(
        context: Context,
        start: RunStart,
        schemas: Arc<HashMap<String, RecordSchema>>,
    ) -> Self {
        let view = match start.target {
            Target::Files => None,
            Target::System { view } | Target::Evidence { view } => {
                Some(View::new(context.clone(), view))
            }
        };
        Self {
            inputs: start
                .inputs
                .into_iter()
                .map(|info| FileRef::new(context.clone(), info))
                .collect(),
            run_id: start.run_id,
            analyzer: start.analyzer,
            view,
            options: Options::new(start.options),
            profile: Profile::new(start.profile),
            locale: start.locale,
            schemas,
            emitter: Mutex::default(),
            summary: Mutex::default(),
            context,
        }
    }

    pub fn id(&self) -> &str {
        &self.run_id
    }

    pub fn analyzer(&self) -> &str {
        &self.analyzer
    }

    /// The system or evidence view; `None` for a run over files.
    pub fn view(&self) -> Option<&View> {
        self.view.as_ref()
    }

    /// The view, or `INVALID_TARGET` for a run over files.
    pub fn require_view(&self) -> Result<&View> {
        self.view.as_ref().ok_or_else(|| {
            Error::new(
                "INVALID_TARGET",
                format!("analyzer {} needs a system or evidence view", self.analyzer),
            )
        })
    }

    /// The operating system of a system run.
    pub fn system(&self) -> Option<&SystemInfo> {
        self.view.as_ref().and_then(View::system)
    }

    /// Files resolved for the run: the selected file of a file run, or the
    /// matches of the analyzer's declared inputs.
    pub fn inputs(&self) -> &[FileRef] {
        &self.inputs
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// UI locale (`zh-CN`, `en`) for text the analyzer writes itself.
    pub fn locale(&self) -> &str {
        &self.locale
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn is_cancelled(&self) -> bool {
        self.context.is_cancelled()
    }

    pub fn check_cancelled(&self) -> Result<()> {
        self.context.check_cancelled()
    }

    pub fn log(&self, level: LogLevel, message: &str) {
        self.context.log(level, message);
    }

    /// Emits a record without a source.
    pub fn emit<R: Record>(&self, record: &R) -> Result<()> {
        self.record(record).emit()
    }

    /// Emits a record read from `file`.
    pub fn emit_from<R: Record>(&self, file: &FileRef, record: &R) -> Result<()> {
        self.record(record).from(file).emit()
    }

    /// Starts a record with sources, a title or a severity.
    pub fn record<R: Record>(&self, record: &R) -> Emit<'_> {
        Emit::new(self, R::TYPE.to_owned(), record.values())
    }

    /// Starts a record of a run-time schema.
    pub fn dynamic(&self, record: &DynamicRecord) -> Emit<'_> {
        Emit::new(
            self,
            record.schema().record_type.clone(),
            record.values().to_vec(),
        )
    }

    /// Starts a record from positional values of a registered record type
    /// (table-driven analyzers that build values themselves).
    pub fn record_values(&self, record_type: &str, values: Vec<Value>) -> Emit<'_> {
        Emit::new(self, record_type.to_owned(), values)
    }

    /// Records an evidence profile fact (`timezone`, `hostname`, `users`, …)
    /// that analyzers declaring `requires` on it read in later runs. The
    /// analyzer must declare the key in its manifest `provides`.
    pub fn provide(&self, key: &str, value: impl Into<Value>) -> Result<()> {
        let system = self
            .system()
            .map(|system| Value::from(system.id.as_str()))
            .unwrap_or(Value::Nil);
        Emit::new(
            self,
            PROFILE_FACT.to_owned(),
            vec![Value::from(key), value.into(), system],
        )
        .emit()
    }

    /// Records something the run could not do. Warnings are kept with the
    /// run's results; they do not fail it.
    pub fn warn(&self, code: &str, message: impl Into<String>) -> Result<()> {
        self.send_warning(code, message.into(), None)
    }

    /// [`Run::warn`] about one input file.
    pub fn warn_file(&self, file: &FileRef, code: &str, message: impl Into<String>) -> Result<()> {
        self.send_warning(code, message.into(), Some(file.id().to_owned()))
    }

    fn send_warning(&self, code: &str, message: String, file_id: Option<String>) -> Result<()> {
        self.context
            .call_typed::<_, Value>(
                method::RUN_WARN,
                &RunWarn {
                    run_id: self.run_id.clone(),
                    code: code.to_owned(),
                    message,
                    file_id,
                },
            )
            .map(drop)
    }

    /// Reports progress to the task center.
    pub fn progress(&self, current: u64, total: Option<u64>, message: Option<&str>) -> Result<()> {
        self.context
            .call_typed::<_, Value>(
                method::RUN_PROGRESS,
                &RunProgress {
                    run_id: self.run_id.clone(),
                    current,
                    total,
                    message: message.map(str::to_owned),
                },
            )
            .map(drop)
    }

    /// A one-line summary shown with the run (the host counts records and
    /// warnings itself).
    pub fn set_summary(&self, summary: impl Into<String>) {
        *self.summary.lock().unwrap_or_else(PoisonError::into_inner) = Some(summary.into());
    }

    /// Records emitted so far.
    pub fn emitted(&self) -> u64 {
        self.emitter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .emitted
    }

    fn push(&self, record: WireRecord) -> Result<()> {
        let schema = self.schemas.get(&record.record_type).ok_or_else(|| {
            Error::new(
                "UNKNOWN_RECORD_TYPE",
                format!(
                    "record type {} is not registered with Plugin::record",
                    record.record_type
                ),
            )
        })?;
        schema
            .validate_values(&record.values)
            .map_err(|message| Error::new("INVALID_RECORD", message))?;
        let encoded = protocol::encode(&record)?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(Error::new(
                "RESOURCE_LIMIT",
                format!(
                    "a {} record encodes to {} bytes; the limit is {MAX_RECORD_BYTES}",
                    record.record_type,
                    encoded.len()
                ),
            ));
        }
        let full = {
            let mut emitter = self.emitter.lock().unwrap_or_else(PoisonError::into_inner);
            emitter.bytes += encoded.len();
            emitter.encoded.push(encoded);
            emitter.emitted += 1;
            emitter.encoded.len() >= BATCH_RECORDS || emitter.bytes >= BATCH_BYTES
        };
        if full {
            self.flush()?;
        }
        Ok(())
    }

    /// Sends the buffered records. Runs flush on their own; analyzers only
    /// call this to bound memory between long phases.
    pub fn flush(&self) -> Result<()> {
        let records = {
            let mut emitter = self.emitter.lock().unwrap_or_else(PoisonError::into_inner);
            emitter.bytes = 0;
            std::mem::take(&mut emitter.encoded)
        };
        if records.is_empty() {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(records.iter().map(Vec::len).sum::<usize>() + 64);
        let framing = |error: rmp::encode::ValueWriteError| Error::plugin(error.to_string());
        rmp::encode::write_map_len(&mut payload, 2).map_err(framing)?;
        rmp::encode::write_str(&mut payload, "run_id").map_err(framing)?;
        rmp::encode::write_str(&mut payload, &self.run_id).map_err(framing)?;
        rmp::encode::write_str(&mut payload, "records").map_err(framing)?;
        rmp::encode::write_array_len(&mut payload, records.len() as u32).map_err(framing)?;
        for record in &records {
            payload.extend_from_slice(record);
        }
        self.context.check_cancelled()?;
        let reply = self.context.host().call_bytes(method::RUN_EMIT, &payload)?;
        let ack: EmitAck = protocol::decode(&reply)?;
        if ack.accepted != records.len() as u64 {
            return Err(Error::new(
                "PROTOCOL_ERROR",
                format!(
                    "host accepted {} of {} records",
                    ack.accepted,
                    records.len()
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<RunFinish> {
        self.flush()?;
        Ok(RunFinish {
            summary: self
                .summary
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        })
    }
}

/// A record being emitted (see [`Run::record`]).
#[must_use = "a record is only sent by Emit::emit"]
pub struct Emit<'a> {
    run: &'a Run,
    record: WireRecord,
}

impl<'a> Emit<'a> {
    fn new(run: &'a Run, record_type: String, values: Vec<Value>) -> Self {
        Self {
            run,
            record: WireRecord {
                record_type,
                values,
                title: None,
                severity: None,
                sources: Vec::new(),
            },
        }
    }

    /// Adds `file` as a source.
    pub fn from(mut self, file: &FileRef) -> Self {
        self.record.sources.push(file.source());
        self
    }

    /// Adds a source.
    pub fn source(mut self, source: SourceRef) -> Self {
        self.record.sources.push(source);
        self
    }

    /// Narrows the last source to `length` bytes at `offset`.
    pub fn at(mut self, offset: u64, length: u64) -> Self {
        if let Some(source) = self.record.sources.last_mut() {
            source.offset = Some(offset);
            source.length = Some(length);
        }
        self
    }

    /// Notes where in the last source the record is (`line 12`).
    pub fn note(mut self, note: impl Into<String>) -> Self {
        if let Some(source) = self.record.sources.last_mut() {
            source.note = Some(note.into());
        }
        self
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.record.title = Some(title.into());
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.record.severity = Some(severity);
        self
    }

    pub fn emit(self) -> Result<()> {
        self.run.push(self.record)
    }
}
