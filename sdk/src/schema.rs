//! Record schemas: the typed shape of the records an analyzer emits.
//!
//! A plugin registers one [`RecordSchema`] per record type (usually through
//! `#[derive(Record)]`). The host stores records in typed tables built from
//! the schema, renders columns by [`FieldKind`], projects timestamp fields
//! with a timeline role into the case timeline and keeps the schema next to
//! the stored rows, so results stay readable without the plugin. Both sides
//! validate with the functions of this module.

use rmpv::Value;
use serde::{Deserialize, Serialize};

mod presentation;
pub use presentation::PropertyLayout;

/// Most fields one record type may declare.
pub const MAX_FIELDS: usize = 128;
/// Longest text-like value (text, path, hash, ip, enum, title, …).
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
/// Most items of a `list` value.
pub const MAX_LIST_ITEMS: usize = 4096;
/// Deepest nesting of a `json` value.
pub const MAX_JSON_DEPTH: usize = 8;
/// Most scalar and container entries of one `json` value.
pub const MAX_JSON_ENTRIES: usize = 4096;
/// Most record types one plugin may register.
pub const MAX_RECORD_TYPES: usize = 256;

/// How a field value is stored, rendered, sorted and searched.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// UTF-8 text.
    Text,
    /// Signed or unsigned 64-bit integer.
    Int,
    /// Finite floating-point number.
    Float,
    Bool,
    /// RFC 3339 with an offset (`2024-01-02T03:04:05Z`), or a local time
    /// without offset (`2024-01-02T03:04:05`) when the time zone is unknown.
    Timestamp,
    /// A byte count (non-negative integer).
    Size,
    /// Seconds (non-negative number).
    Duration,
    /// A file system path as recorded by the evidence.
    Path,
    /// A digest or other hexadecimal identifier.
    Hash,
    /// An IPv4 / IPv6 address (or host name where the source mixes both).
    Ip,
    /// One of the declared choices.
    Enum,
    /// A list of text values.
    List,
    /// Structured data without a fixed shape.
    Json,
}

impl FieldKind {
    pub const ALL: [Self; 13] = [
        Self::Text,
        Self::Int,
        Self::Float,
        Self::Bool,
        Self::Timestamp,
        Self::Size,
        Self::Duration,
        Self::Path,
        Self::Hash,
        Self::Ip,
        Self::Enum,
        Self::List,
        Self::Json,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Timestamp => "timestamp",
            Self::Size => "size",
            Self::Duration => "duration",
            Self::Path => "path",
            Self::Hash => "hash",
            Self::Ip => "ip",
            Self::Enum => "enum",
            Self::List => "list",
            Self::Json => "json",
        }
    }

    /// Whether keyword search looks into values of this kind.
    pub fn searchable(self) -> bool {
        match self {
            Self::Text | Self::Path | Self::Hash | Self::Ip | Self::Enum | Self::List => true,
            Self::Int
            | Self::Float
            | Self::Bool
            | Self::Timestamp
            | Self::Size
            | Self::Duration
            | Self::Json => false,
        }
    }
}

/// One choice of an `enum` field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Choice {
    pub id: String,
    pub label: String,
}

/// One field of a record type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldSchema {
    pub id: String,
    /// Default (Chinese) label; translations live in the package's locales.
    pub label: String,
    pub kind: FieldKind,
    /// Identifies the record together with the other key fields; key fields
    /// form the default title and get an index.
    #[serde(default, skip_serializing_if = "is_false")]
    pub key: bool,
    /// Kept in the record but not shown as a table column.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    /// Timeline role (`login`, `modified`, …) of a timestamp field; such
    /// fields are projected into the case timeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<Choice>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl FieldSchema {
    pub fn new(id: impl Into<String>, label: impl Into<String>, kind: FieldKind) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            kind,
            key: false,
            hidden: false,
            timeline: None,
            choices: Vec::new(),
        }
    }

    pub fn key(mut self) -> Self {
        self.key = true;
        self
    }

    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    pub fn timeline(mut self, role: impl Into<String>) -> Self {
        self.timeline = Some(role.into());
        self
    }

    pub fn choice(mut self, id: impl Into<String>, label: impl Into<String>) -> Self {
        self.choices.push(Choice {
            id: id.into(),
            label: label.into(),
        });
        self
    }
}

/// The shape of one record type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordSchema {
    /// Namespaced lowercase type (`linux.login`).
    #[serde(rename = "type")]
    pub record_type: String,
    /// Default (Chinese) label of the result item.
    pub label: String,
    /// Title template over field ids (`{user} @ {terminal}`); the key fields
    /// joined with ` · ` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Display group of the result item; the analyzer's category when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// A vertical list of properties instead of the default record table.
    /// Omitted for tables, preserving the serialization of existing schemas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<PropertyLayout>,
    pub fields: Vec<FieldSchema>,
}

impl RecordSchema {
    pub fn new(record_type: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            record_type: record_type.into(),
            label: label.into(),
            title: None,
            category: None,
            properties: None,
            fields: Vec::new(),
        }
    }

    pub fn title(mut self, template: impl Into<String>) -> Self {
        self.title = Some(template.into());
        self
    }

    pub fn category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    pub fn field(mut self, field: FieldSchema) -> Self {
        self.fields.push(field);
        self
    }

    pub fn properties(mut self, layout: PropertyLayout) -> Self {
        self.properties = Some(layout);
        self
    }

    pub fn field_index(&self, id: &str) -> Option<usize> {
        self.fields.iter().position(|field| field.id == id)
    }

    /// Checks identifiers, limits and the title template.
    pub fn validate(&self) -> Result<(), String> {
        validate_record_type(&self.record_type)?;
        validate_label("record label", &self.label)?;
        if let Some(category) = &self.category {
            validate_identifier("record category", category)?;
        }
        if self.fields.is_empty() || self.fields.len() > MAX_FIELDS {
            return Err(format!(
                "{} must declare 1..={MAX_FIELDS} fields",
                self.record_type
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for field in &self.fields {
            validate_identifier("field id", &field.id)?;
            validate_label("field label", &field.label)?;
            if !seen.insert(field.id.as_str()) {
                return Err(format!(
                    "{} declares field {} twice",
                    self.record_type, field.id
                ));
            }
            if let Some(role) = &field.timeline {
                validate_identifier("timeline role", role)?;
                if field.kind != FieldKind::Timestamp {
                    return Err(format!(
                        "{}.{} has a timeline role but is not a timestamp",
                        self.record_type, field.id
                    ));
                }
            }
            if !field.choices.is_empty() && field.kind != FieldKind::Enum {
                return Err(format!(
                    "{}.{} declares choices but is not an enum",
                    self.record_type, field.id
                ));
            }
            let mut choice_ids = std::collections::HashSet::new();
            for choice in &field.choices {
                validate_identifier("enum choice", &choice.id)?;
                validate_label("enum choice label", &choice.label)?;
                if !choice_ids.insert(choice.id.as_str()) {
                    return Err(format!(
                        "{}.{} declares choice {} twice",
                        self.record_type, field.id, choice.id
                    ));
                }
            }
        }
        if let Some(layout) = &self.properties {
            layout
                .validate(&self.fields)
                .map_err(|error| format!("{}: {error}", self.record_type))?;
        }
        if let Some(template) = &self.title {
            for placeholder in title_placeholders(template)? {
                if self.field_index(placeholder).is_none() {
                    return Err(format!(
                        "{} title references unknown field {placeholder}",
                        self.record_type
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validates one positional value list against the fields.
    pub fn validate_values(&self, values: &[Value]) -> Result<(), String> {
        if values.len() != self.fields.len() {
            return Err(format!(
                "{} expects {} values, got {}",
                self.record_type,
                self.fields.len(),
                values.len()
            ));
        }
        for (field, value) in self.fields.iter().zip(values) {
            validate_value(field, value)
                .map_err(|error| format!("{}.{}: {error}", self.record_type, field.id))?;
        }
        Ok(())
    }

    /// The record title: the template filled with the values, or the key
    /// fields (else the first non-empty text field) joined with ` · `.
    pub fn render_title(&self, values: &[Value]) -> String {
        let text = |index: usize| values.get(index).map(display_value).unwrap_or_default();
        let title = match &self.title {
            Some(template) => {
                let mut output = String::new();
                let mut rest = template.as_str();
                while let Some(start) = rest.find('{') {
                    output.push_str(&rest[..start]);
                    let after = &rest[start + 1..];
                    if let Some(stripped) = after.strip_prefix('{') {
                        output.push('{');
                        rest = stripped;
                        continue;
                    }
                    let Some(end) = after.find('}') else {
                        output.push_str(&rest[start..]);
                        rest = "";
                        break;
                    };
                    if let Some(index) = self.field_index(&after[..end]) {
                        output.push_str(&text(index));
                    }
                    rest = &after[end + 1..];
                }
                output.push_str(&rest.replace("}}", "}"));
                output.trim().to_owned()
            }
            None => {
                let keys: Vec<String> = self
                    .fields
                    .iter()
                    .enumerate()
                    .filter(|(_, field)| field.key)
                    .map(|(index, _)| text(index))
                    .filter(|value| !value.is_empty())
                    .collect();
                if keys.is_empty() {
                    self.fields
                        .iter()
                        .enumerate()
                        .filter(|(_, field)| field.kind == FieldKind::Text)
                        .map(|(index, _)| text(index))
                        .find(|value| !value.is_empty())
                        .unwrap_or_default()
                } else {
                    keys.join(" · ")
                }
            }
        };
        if title.is_empty() {
            self.label.clone()
        } else {
            truncate(&title, 1024)
        }
    }
}

fn truncate(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Field ids referenced by a title template (`{id}`; `{{` / `}}` escape).
fn title_placeholders(template: &str) -> Result<Vec<&str>, String> {
    let mut placeholders = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        if let Some(stripped) = after.strip_prefix('{') {
            rest = stripped;
            continue;
        }
        let end = after
            .find('}')
            .ok_or_else(|| format!("title template {template:?} has an unclosed {{"))?;
        placeholders.push(&after[..end]);
        rest = &after[end + 1..];
    }
    Ok(placeholders)
}

/// A value as display text (titles, search text).
pub fn display_value(value: &Value) -> String {
    match value {
        Value::Nil => String::new(),
        Value::Boolean(flag) => flag.to_string(),
        Value::Integer(number) => number.to_string(),
        Value::F32(number) => number.to_string(),
        Value::F64(number) => number.to_string(),
        Value::String(text) => text.as_str().unwrap_or_default().to_owned(),
        Value::Array(items) => items
            .iter()
            .map(display_value)
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        Value::Map(_) | Value::Binary(_) | Value::Ext(..) => value.to_string(),
    }
}

/// Validates one value against its field.
pub fn validate_value(field: &FieldSchema, value: &Value) -> Result<(), String> {
    if value.is_nil() {
        return Ok(());
    }
    match field.kind {
        FieldKind::Text | FieldKind::Path | FieldKind::Hash | FieldKind::Ip => {
            text_value(value)?;
        }
        FieldKind::Enum => {
            let text = text_value(value)?;
            if !field.choices.is_empty() && !field.choices.iter().any(|choice| choice.id == text) {
                return Err(format!("{text:?} is not a declared choice"));
            }
        }
        FieldKind::Int => {
            if !matches!(value, Value::Integer(_)) {
                return Err("expected an integer".to_owned());
            }
        }
        FieldKind::Size => match value {
            Value::Integer(number) if number.as_u64().is_some() => {}
            _ => return Err("expected a non-negative integer byte count".to_owned()),
        },
        FieldKind::Float | FieldKind::Duration => {
            let number = match value {
                Value::Integer(number) => number.as_f64().unwrap_or(f64::NAN),
                Value::F32(number) => f64::from(*number),
                Value::F64(number) => *number,
                _ => return Err("expected a number".to_owned()),
            };
            if !number.is_finite() {
                return Err("numbers must be finite".to_owned());
            }
            if field.kind == FieldKind::Duration && number < 0.0 {
                return Err("durations must not be negative".to_owned());
            }
        }
        FieldKind::Bool => {
            if !matches!(value, Value::Boolean(_)) {
                return Err("expected a boolean".to_owned());
            }
        }
        FieldKind::Timestamp => {
            let text = text_value(value)?;
            if parse_timestamp(text).is_none() {
                return Err(format!(
                    "{text:?} is neither RFC 3339 nor a local YYYY-MM-DDTHH:MM:SS time"
                ));
            }
        }
        FieldKind::List => {
            let Value::Array(items) = value else {
                return Err("expected a list of text".to_owned());
            };
            if items.len() > MAX_LIST_ITEMS {
                return Err(format!("lists hold at most {MAX_LIST_ITEMS} items"));
            }
            let mut total = 0_usize;
            for item in items {
                total += text_value(item)?.len();
            }
            if total > MAX_TEXT_BYTES {
                return Err(format!("list text exceeds {MAX_TEXT_BYTES} bytes"));
            }
        }
        FieldKind::Json => {
            let mut entries = 0;
            validate_json(value, 0, &mut entries)?;
        }
    }
    Ok(())
}

fn text_value(value: &Value) -> Result<&str, String> {
    let Value::String(text) = value else {
        return Err("expected text".to_owned());
    };
    let text = text
        .as_str()
        .ok_or_else(|| "text is not valid UTF-8".to_owned())?;
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!("text exceeds {MAX_TEXT_BYTES} bytes"));
    }
    Ok(text)
}

fn validate_json(value: &Value, depth: usize, entries: &mut usize) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err(format!("json nests deeper than {MAX_JSON_DEPTH} levels"));
    }
    *entries += 1;
    if *entries > MAX_JSON_ENTRIES {
        return Err(format!("json holds more than {MAX_JSON_ENTRIES} entries"));
    }
    match value {
        Value::Nil | Value::Boolean(_) | Value::Integer(_) => Ok(()),
        Value::F32(number) if number.is_finite() => Ok(()),
        Value::F64(number) if number.is_finite() => Ok(()),
        Value::F32(_) | Value::F64(_) => Err("json numbers must be finite".to_owned()),
        Value::String(_) => text_value(value).map(drop),
        Value::Array(items) => items
            .iter()
            .try_for_each(|item| validate_json(item, depth + 1, entries)),
        Value::Map(pairs) => {
            let mut keys = std::collections::HashSet::new();
            for (key, item) in pairs {
                let key = key
                    .as_str()
                    .ok_or_else(|| "json object keys must be text".to_owned())?;
                if !keys.insert(key) {
                    return Err(format!("json object repeats key {key:?}"));
                }
                validate_json(item, depth + 1, entries)?;
            }
            Ok(())
        }
        Value::Binary(_) | Value::Ext(..) => {
            Err("binary and extension values are not allowed".to_owned())
        }
    }
}

/// A parsed timestamp. `offset_minutes` is `None` for a local time whose
/// time zone is unknown; `epoch_seconds` then reads the wall clock as UTC
/// (for ordering only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedTimestamp {
    pub epoch_seconds: i64,
    pub nanos: u32,
    pub offset_minutes: Option<i32>,
}

impl ParsedTimestamp {
    /// Microseconds since the epoch, for sorting.
    pub fn epoch_micros(&self) -> i64 {
        self.epoch_seconds
            .saturating_mul(1_000_000)
            .saturating_add(i64::from(self.nanos / 1_000))
    }
}

/// Parses RFC 3339 (`Z` or `±HH:MM`) or a local `YYYY-MM-DDTHH:MM:SS[.f]`
/// (a space instead of `T` is accepted too).
pub fn parse_timestamp(text: &str) -> Option<ParsedTimestamp> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 || bytes.len() > 64 {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let digits = bytes.get(range)?;
        digits.iter().try_fold(0_u32, |total, digit| {
            digit
                .is_ascii_digit()
                .then(|| total * 10 + u32::from(digit - b'0'))
        })
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut position = 19;
    let mut nanos = 0_u32;
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        let start = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        let digits = position - start;
        if digits == 0 || digits > 9 {
            return None;
        }
        nanos = number(start..position)? * 10_u32.pow(9 - digits as u32);
    }
    let offset_minutes = match bytes.get(position) {
        None => None,
        Some(b'Z' | b'z') if position + 1 == bytes.len() => Some(0),
        Some(sign @ (b'+' | b'-')) if position + 6 == bytes.len() => {
            if bytes[position + 3] != b':' {
                return None;
            }
            let hours = number(position + 1..position + 3)?;
            let minutes = number(position + 4..position + 6)?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let total = (hours * 60 + minutes) as i32;
            Some(if *sign == b'-' { -total } else { total })
        }
        Some(_) => return None,
    };
    let days = days_from_civil(i64::from(year), month, day);
    let local_seconds = days * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second.min(59));
    Some(ParsedTimestamp {
        epoch_seconds: local_seconds - i64::from(offset_minutes.unwrap_or(0)) * 60,
        nanos,
        offset_minutes,
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        _ => 28,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date of a day count since 1970-01-01.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// A lowercase identifier: `a-z`, then `a-z`, `0-9`, `_` (at most 64 bytes).
pub fn validate_identifier(label: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{label} {value:?} must be a lowercase identifier (a-z, 0-9, _)"
        ))
    }
}

/// A namespaced record type: dot-separated lowercase identifiers.
pub fn validate_record_type(value: &str) -> Result<(), String> {
    let valid = value.len() <= 128
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "record type {value:?} must be namespaced lowercase identifiers such as linux.login"
        ))
    }
}

fn validate_label(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 256 {
        Err(format!("{label} must be 1..=256 bytes"))
    } else {
        Ok(())
    }
}

/// A stable digest of a plugin's record schemas (`fnv1a64:<hex>`), compared
/// at the handshake with the schema shipped in the package.
pub fn schema_hash(records: &[RecordSchema]) -> String {
    let mut sorted: Vec<&RecordSchema> = records.iter().collect();
    sorted.sort_by(|left, right| left.record_type.cmp(&right.record_type));
    let encoded = rmp_serde::to_vec_named(&sorted).unwrap_or_default();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in encoded {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64:{hash:016x}")
}

/// The schema of one record type's fields hash, used to name its table.
pub fn record_schema_hash(schema: &RecordSchema) -> String {
    schema_hash(std::slice::from_ref(schema))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> RecordSchema {
        RecordSchema::new("linux.login", "登录信息")
            .title("{user} @ {terminal}")
            .field(FieldSchema::new("user", "用户", FieldKind::Text).key())
            .field(FieldSchema::new("terminal", "终端", FieldKind::Text))
            .field(FieldSchema::new("time", "时间", FieldKind::Timestamp).timeline("login"))
            .field(
                FieldSchema::new("outcome", "结果", FieldKind::Enum)
                    .choice("success", "成功")
                    .choice("failure", "失败"),
            )
    }

    #[test]
    fn schemas_validate_and_render_titles() {
        let schema = login();
        schema.validate().expect("valid schema");
        let values = vec![
            Value::from("root"),
            Value::from("pts/0"),
            Value::from("2024-01-02T03:04:05Z"),
            Value::from("success"),
        ];
        schema.validate_values(&values).expect("valid values");
        assert_eq!(schema.render_title(&values), "root @ pts/0");
        let untitled = RecordSchema {
            title: None,
            ..schema.clone()
        };
        assert_eq!(untitled.render_title(&values), "root");
        assert_eq!(
            untitled.render_title(&[Value::Nil, Value::Nil, Value::Nil, Value::Nil]),
            "登录信息"
        );
    }

    #[test]
    fn invalid_schemas_and_values_are_rejected() {
        let mut schema = login();
        schema.title = Some("{missing}".to_owned());
        assert!(schema.validate().is_err());
        let mut schema = login();
        schema.fields[1].timeline = Some("login".to_owned());
        assert!(schema.validate().is_err());
        let schema = login();
        assert!(schema
            .validate_values(&[Value::from("root"), Value::from(1), Value::Nil, Value::Nil])
            .is_err());
        assert!(schema
            .validate_values(&[Value::Nil, Value::Nil, Value::from("yesterday"), Value::Nil])
            .is_err());
        assert!(schema
            .validate_values(&[Value::Nil, Value::Nil, Value::Nil, Value::from("other")])
            .is_err());
        assert!(RecordSchema::new("plain", "x")
            .field(FieldSchema::new("a", "a", FieldKind::Text))
            .validate()
            .is_err());
    }

    #[test]
    fn timestamps_parse_with_and_without_offsets() {
        let utc = parse_timestamp("2024-01-02T03:04:05.5Z").expect("utc");
        assert_eq!(utc.epoch_seconds, 1_704_164_645);
        assert_eq!(utc.nanos, 500_000_000);
        assert_eq!(utc.offset_minutes, Some(0));
        let shanghai = parse_timestamp("2024-01-02T11:04:05+08:00").expect("offset");
        assert_eq!(shanghai.epoch_seconds, utc.epoch_seconds);
        assert_eq!(shanghai.offset_minutes, Some(480));
        let local = parse_timestamp("2024-01-02 03:04:05").expect("local");
        assert_eq!(local.offset_minutes, None);
        assert_eq!(local.epoch_seconds, utc.epoch_seconds);
        for invalid in [
            "2024-02-30T00:00:00Z",
            "2024-01-02T03:04",
            "2024-01-02T03:04:05+0800",
            "2024-01-02T03:04:05.Z",
        ] {
            assert!(parse_timestamp(invalid).is_none(), "{invalid}");
        }
        assert_eq!(
            civil_from_days(days_from_civil(1999, 12, 31)),
            (1999, 12, 31)
        );
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn schema_hashes_ignore_registration_order() {
        let other = RecordSchema::new("linux.user", "用户").field(FieldSchema::new(
            "name",
            "用户名",
            FieldKind::Text,
        ));
        assert_eq!(
            schema_hash(&[login(), other.clone()]),
            schema_hash(&[other, login()])
        );
        assert!(schema_hash(&[login()]).starts_with("fnv1a64:"));
    }
}
