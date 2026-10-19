//! Records: what an analyzer emits.
//!
//! A record type implements [`Record`], normally through
//! `#[derive(Record)]`. Its values are positional, in schema field order;
//! [`FieldType`] maps Rust field types to field kinds and values.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::schema::{civil_from_days, parse_timestamp, FieldKind, FieldSchema, RecordSchema};

/// A record type with a fixed schema.
pub trait Record {
    /// Namespaced record type (`linux.login`).
    const TYPE: &'static str;

    fn schema() -> RecordSchema;

    /// Field values in schema order.
    fn values(&self) -> Vec<Value>;
}

/// A Rust type usable as a record field.
pub trait FieldType {
    const KIND: FieldKind;

    fn to_value(&self) -> Value;
}

macro_rules! integer_field {
    ($($ty:ty),*) => {$(
        impl FieldType for $ty {
            const KIND: FieldKind = FieldKind::Int;
            fn to_value(&self) -> Value {
                Value::from(*self)
            }
        }
    )*};
}

integer_field!(i8, i16, i32, i64, u8, u16, u32, u64);

impl FieldType for usize {
    const KIND: FieldKind = FieldKind::Int;
    fn to_value(&self) -> Value {
        Value::from(*self as u64)
    }
}

impl FieldType for isize {
    const KIND: FieldKind = FieldKind::Int;
    fn to_value(&self) -> Value {
        Value::from(*self as i64)
    }
}

impl FieldType for f64 {
    const KIND: FieldKind = FieldKind::Float;
    fn to_value(&self) -> Value {
        if self.is_finite() {
            Value::F64(*self)
        } else {
            Value::Nil
        }
    }
}

impl FieldType for f32 {
    const KIND: FieldKind = FieldKind::Float;
    fn to_value(&self) -> Value {
        f64::from(*self).to_value()
    }
}

impl FieldType for bool {
    const KIND: FieldKind = FieldKind::Bool;
    fn to_value(&self) -> Value {
        Value::Boolean(*self)
    }
}

impl FieldType for String {
    const KIND: FieldKind = FieldKind::Text;
    fn to_value(&self) -> Value {
        Value::from(self.as_str())
    }
}

impl FieldType for &str {
    const KIND: FieldKind = FieldKind::Text;
    fn to_value(&self) -> Value {
        Value::from(*self)
    }
}

impl FieldType for Vec<String> {
    const KIND: FieldKind = FieldKind::List;
    fn to_value(&self) -> Value {
        Value::Array(self.iter().map(|item| Value::from(item.as_str())).collect())
    }
}

impl<T: FieldType> FieldType for Option<T> {
    const KIND: FieldKind = T::KIND;
    fn to_value(&self) -> Value {
        self.as_ref().map(FieldType::to_value).unwrap_or(Value::Nil)
    }
}

impl FieldType for Timestamp {
    const KIND: FieldKind = FieldKind::Timestamp;
    fn to_value(&self) -> Value {
        Value::from(self.0.as_str())
    }
}

/// Structured data of a `json` field.
#[derive(Clone, Debug, PartialEq)]
pub struct Json(pub Value);

impl FieldType for Json {
    const KIND: FieldKind = FieldKind::Json;
    fn to_value(&self) -> Value {
        self.0.clone()
    }
}

/// A point in time: RFC 3339 with an offset, or a local wall-clock time
/// whose time zone the evidence does not record. Never label a local time
/// as UTC: build it with [`Timestamp::local`].
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct Timestamp(String);

impl Timestamp {
    /// UTC from Unix seconds.
    pub fn from_unix(seconds: i64) -> Self {
        Self::from_unix_nanos(seconds, 0)
    }

    /// UTC from Unix milliseconds.
    pub fn from_unix_millis(milliseconds: i64) -> Self {
        let seconds = milliseconds.div_euclid(1_000);
        let nanos = (milliseconds.rem_euclid(1_000) as u32) * 1_000_000;
        Self::from_unix_nanos(seconds, nanos)
    }

    /// UTC from Unix seconds plus a sub-second part.
    pub fn from_unix_nanos(seconds: i64, nanos: u32) -> Self {
        let nanos = nanos.min(999_999_999);
        let days = seconds.div_euclid(86_400);
        let second_of_day = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        Self(format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{}Z",
            second_of_day / 3_600,
            second_of_day % 3_600 / 60,
            second_of_day % 60,
            fraction(nanos)
        ))
    }

    /// A local wall-clock time without a known time zone.
    pub fn local(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Option<Self> {
        Self::local_nanos(year, month, day, hour, minute, second, 0)
    }

    /// [`Timestamp::local`] with a sub-second part.
    #[allow(clippy::too_many_arguments)]
    pub fn local_nanos(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        nanos: u32,
    ) -> Option<Self> {
        if !(0..=9999).contains(&year) {
            return None;
        }
        let text = format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{}",
            fraction(nanos.min(999_999_999))
        );
        parse_timestamp(&text).map(|_| Self(text))
    }

    /// A wall-clock time at a fixed UTC offset (minutes east of UTC).
    #[allow(clippy::too_many_arguments)]
    pub fn with_offset(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        offset_minutes: i32,
    ) -> Option<Self> {
        if !(0..=9999).contains(&year) || offset_minutes.abs() >= 24 * 60 {
            return None;
        }
        let sign = if offset_minutes < 0 { '-' } else { '+' };
        let offset = offset_minutes.unsigned_abs();
        let text = format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{sign}{:02}:{:02}",
            offset / 60,
            offset % 60
        );
        parse_timestamp(&text).map(|_| Self(text))
    }

    /// Accepts RFC 3339 or a local `YYYY-MM-DDTHH:MM:SS[.f]` time.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        parse_timestamp(text).map(|_| Self(text.replacen(' ', "T", 1)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the time zone is known.
    pub fn has_offset(&self) -> bool {
        parse_timestamp(&self.0).is_some_and(|parsed| parsed.offset_minutes.is_some())
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn fraction(nanos: u32) -> String {
    if nanos == 0 {
        return String::new();
    }
    let digits = format!("{nanos:09}");
    format!(".{}", digits.trim_end_matches('0'))
}

/// Severity of a record that flags something (a finding).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Where a record came from: an evidence address, optionally down to a
/// byte range. `root` is the volume key (`part:1`, `lvm:0:1`, `root`) and
/// `path` the path inside that volume, so the source can be located
/// whichever view the analyzer read it through.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    /// What part of the source holds the record (`line 12`, `row 4`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl SourceRef {
    pub fn path(root: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            root: Some(root.into()),
            path: Some(path.into()),
            ..Self::default()
        }
    }

    pub fn at(mut self, offset: u64, length: u64) -> Self {
        self.offset = Some(offset);
        self.length = Some(length);
        self
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// A record whose schema is built at run time (no derive), for generic
/// parsers that only learn their columns from the evidence.
#[derive(Clone, Debug)]
pub struct DynamicRecord {
    schema: std::sync::Arc<RecordSchema>,
    values: Vec<Value>,
}

impl DynamicRecord {
    pub fn new(schema: std::sync::Arc<RecordSchema>) -> Self {
        let values = vec![Value::Nil; schema.fields.len()];
        Self { schema, values }
    }

    /// Sets a field by id; unknown ids are ignored.
    pub fn set(mut self, field: &str, value: impl FieldType) -> Self {
        if let Some(index) = self.schema.field_index(field) {
            self.values[index] = value.to_value();
        }
        self
    }

    pub fn schema(&self) -> &RecordSchema {
        &self.schema
    }

    pub fn values(&self) -> &[Value] {
        &self.values
    }
}

/// The built-in record type behind [`crate::Run::provide`]: one evidence
/// profile fact (time zone, host name, user names, …).
pub(crate) const PROFILE_FACT: &str = "profile.fact";

pub(crate) fn profile_fact_schema() -> RecordSchema {
    RecordSchema::new(PROFILE_FACT, "检材画像")
        .title("{key}")
        .field(FieldSchema::new("key", "键", FieldKind::Text).key())
        .field(FieldSchema::new("value", "值", FieldKind::Json))
        .field(FieldSchema::new("system", "系统", FieldKind::Text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_format_utc_and_keep_unknown_zones_local() {
        assert_eq!(Timestamp::from_unix(0).as_str(), "1970-01-01T00:00:00Z");
        assert_eq!(
            Timestamp::from_unix_nanos(1_704_164_645, 500_000_000).as_str(),
            "2024-01-02T03:04:05.5Z"
        );
        assert_eq!(
            Timestamp::from_unix_millis(-1).as_str(),
            "1969-12-31T23:59:59.999Z"
        );
        let local = Timestamp::local(2024, 2, 29, 23, 59, 59).expect("leap day");
        assert_eq!(local.as_str(), "2024-02-29T23:59:59");
        assert!(!local.has_offset());
        assert!(Timestamp::local(2023, 2, 29, 0, 0, 0).is_none());
        assert_eq!(
            Timestamp::with_offset(2024, 1, 2, 11, 4, 5, 480)
                .expect("offset")
                .as_str(),
            "2024-01-02T11:04:05+08:00"
        );
        assert_eq!(
            Timestamp::parse("2024-01-02 03:04:05").map(|time| time.0),
            Some("2024-01-02T03:04:05".to_owned())
        );
    }

    #[test]
    fn dynamic_records_follow_their_schema() {
        let schema = std::sync::Arc::new(
            RecordSchema::new("test.row", "行")
                .field(FieldSchema::new("name", "名称", FieldKind::Text))
                .field(FieldSchema::new("size", "大小", FieldKind::Size)),
        );
        let record = DynamicRecord::new(schema)
            .set("size", 4_u64)
            .set("missing", "ignored");
        assert_eq!(record.values(), &[Value::Nil, Value::from(4_u64)]);
    }
}
