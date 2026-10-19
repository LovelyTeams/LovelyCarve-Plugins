use std::{collections::HashMap, sync::Arc};

use crate::{
    protocol::Hello,
    record::{profile_fact_schema, Record},
    schema::{schema_hash, validate_identifier, RecordSchema, MAX_RECORD_TYPES},
    wire::PROTOCOL_VERSION,
    Analyzer, FileSystemParser,
};

/// SDK version reported in `plugin.hello`.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A plugin's record types and implementations. The constructor passed to
/// [`crate::export_plugin!`] builds one per instance. The id must match the
/// package manifest, every analyzer the manifest declares must be
/// registered under its id, and every record type an analyzer emits must
/// be registered with [`Plugin::record`].
pub struct Plugin {
    pub(crate) id: String,
    pub(crate) records: Vec<RecordSchema>,
    pub(crate) analyzers: Vec<(String, Box<dyn Analyzer>)>,
    pub(crate) parsers: Vec<Box<dyn FileSystemParser>>,
}

impl Plugin {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            records: vec![profile_fact_schema()],
            analyzers: Vec::new(),
            parsers: Vec::new(),
        }
    }

    /// Registers a record type.
    pub fn record<R: Record>(self) -> Self {
        self.schema(R::schema())
    }

    /// Registers a run-time schema (for [`crate::DynamicRecord`]).
    pub fn schema(mut self, schema: RecordSchema) -> Self {
        self.records.push(schema);
        self
    }

    /// Registers an analyzer under the id its manifest declares.
    pub fn analyzer(mut self, id: impl Into<String>, analyzer: impl Analyzer + 'static) -> Self {
        self.analyzers.push((id.into(), Box::new(analyzer)));
        self
    }

    pub fn filesystem(mut self, parser: impl FileSystemParser + 'static) -> Self {
        self.parsers.push(Box::new(parser));
        self
    }

    /// Checks ids, schemas and duplicates; a plugin that fails is refused
    /// at the handshake.
    pub fn validate(&self) -> Result<(), String> {
        if self.records.len() > MAX_RECORD_TYPES {
            return Err(format!(
                "a plugin registers at most {MAX_RECORD_TYPES} record types"
            ));
        }
        let mut types = std::collections::HashSet::new();
        for schema in &self.records {
            schema.validate()?;
            if !types.insert(schema.record_type.as_str()) {
                return Err(format!(
                    "record type {} is registered twice",
                    schema.record_type
                ));
            }
        }
        let mut analyzers = std::collections::HashSet::new();
        for (id, _) in &self.analyzers {
            validate_identifier("analyzer id", id)?;
            if !analyzers.insert(id.as_str()) {
                return Err(format!("analyzer {id} is registered twice"));
            }
        }
        Ok(())
    }

    pub(crate) fn hello(&self) -> Hello {
        Hello {
            protocol: PROTOCOL_VERSION,
            plugin: self.id.clone(),
            sdk: SDK_VERSION.to_owned(),
            analyzers: self.analyzers.iter().map(|(id, _)| id.clone()).collect(),
            filesystems: self
                .parsers
                .iter()
                .map(|parser| parser.filesystem().to_owned())
                .collect(),
            records: self.records.clone(),
            schema_hash: schema_hash(&self.records),
        }
    }

    pub(crate) fn schema_map(&self) -> Arc<HashMap<String, RecordSchema>> {
        Arc::new(
            self.records
                .iter()
                .map(|schema| (schema.record_type.clone(), schema.clone()))
                .collect(),
        )
    }
}
