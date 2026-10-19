//! 软件信息: dpkg `status` paragraphs and the RPM `rpmdb.sqlite` database.

use std::{collections::HashMap, io::Write as _};

use lovelycarve_plugin::{text::split_lines, Attributes, Error, LogLevel, Result, Value, View};
use rusqlite::{Connection, OpenFlags};

use crate::{
    item::Artifact,
    text::{clean_optional, retain_truthy, rfc3339, strip},
    BINARY_DB_CAP,
};

const RPM_DATABASE: &str = "var/lib/rpm/rpmdb.sqlite";
const RPM_HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];
const RPM_TYPE_INT32: u32 = 4;
const RPM_TYPE_STRING: u32 = 6;
const RPM_TYPE_I18NSTRING: u32 = 9;
/// Header tags kept, by attribute name.
const RPM_HEADER_TAGS: [(u32, &str); 8] = [
    (1000, "linux.software"),
    (1001, "linux.version"),
    (1002, "linux.release"),
    (1004, "linux.summary"),
    (1008, "linux.install_time"),
    (1009, "linux.size"),
    (1011, "linux.vendor"),
    (1022, "linux.arch"),
];

pub fn parse_dpkg_status(text: Option<&str>) -> Vec<Attributes> {
    let mut packages = Vec::new();
    let Some(text) = text.filter(|text| !text.is_empty()) else {
        return packages;
    };
    // Field order matters for continuation lines; the first value of a
    // repeated field wins.
    let mut paragraph: Vec<(String, String)> = Vec::new();
    let mut lines = split_lines(text);
    lines.push("");
    for line in lines {
        if !strip(line).is_empty() {
            if let Some((key, value)) = line.split_once(':') {
                let key = strip(key);
                if !paragraph.iter().any(|(existing, _)| existing == key) {
                    paragraph.push((key.to_owned(), strip(value).to_owned()));
                }
            } else if let Some((_, last)) = paragraph.last_mut() {
                last.push(' ');
                last.push_str(strip(line));
            }
            continue;
        }
        let field = |name: &str| {
            paragraph
                .iter()
                .find_map(|(key, value)| (key == name).then_some(value.as_str()))
        };
        if let Some(package) = field("Package").filter(|package| !package.is_empty()) {
            let status = field("Status").unwrap_or_default();
            let mut attributes = Attributes::new();
            attributes.insert("linux.software", package);
            attributes.insert_optional("linux.version", clean_optional(field("Version"), 200));
            attributes.insert_optional("linux.arch", field("Architecture"));
            if status.contains("installed") {
                attributes.insert("linux.status", "已安装");
            } else {
                attributes.insert_optional(
                    "linux.status",
                    Some(status).filter(|status| !status.is_empty()),
                );
            }
            attributes.insert("linux.source", "dpkg");
            packages.push(attributes);
        }
        paragraph.clear();
    }
    packages
}

#[derive(Clone, Debug, PartialEq)]
pub enum RpmValue {
    Text(String),
    Number(u32),
}

/// Minimal RPM header parse (string and single int32 tags). Accepts the
/// on-disk header with its magic and the bare `headerExport` blob stored
/// in rpmdb.sqlite.
pub fn parse_rpm_header(blob: &[u8]) -> Option<HashMap<&'static str, RpmValue>> {
    let base = if blob.len() >= 32 && blob[..3] == RPM_HEADER_MAGIC {
        8
    } else {
        0
    };
    let index_count = u64::from(be_u32(blob, base)?);
    let data_size = u64::from(be_u32(blob, base + 4)?);
    let index_base = base as u64 + 8;
    let data_base = index_base.checked_add(index_count.checked_mul(16)?)?;
    let end = data_base.checked_add(data_size)?;
    let length = blob.len() as u64;
    // A bare blob must be exactly one header; with the magic, trailing
    // bytes are allowed as before.
    if end > length || (base == 0 && (end != length || index_count == 0)) {
        return None;
    }
    let mut values = HashMap::new();
    for slot in 0..index_count {
        let entry = usize::try_from(index_base + slot * 16).ok()?;
        let (Some(tag), Some(kind), Some(offset), Some(count)) = (
            be_u32(blob, entry),
            be_u32(blob, entry + 4),
            be_u32(blob, entry + 8),
            be_u32(blob, entry + 12),
        ) else {
            return None;
        };
        let Some(name) = RPM_HEADER_TAGS
            .iter()
            .find_map(|(known, name)| (*known == tag).then_some(*name))
        else {
            continue;
        };
        let Ok(position) = usize::try_from(data_base + u64::from(offset)) else {
            continue;
        };
        match kind {
            RPM_TYPE_STRING | RPM_TYPE_I18NSTRING => {
                let Some(tail) = blob.get(position..) else {
                    continue;
                };
                let Some(length) = tail.iter().position(|byte| *byte == 0) else {
                    continue;
                };
                values.insert(
                    name,
                    RpmValue::Text(String::from_utf8_lossy(&tail[..length]).into_owned()),
                );
            }
            RPM_TYPE_INT32 if count == 1 => {
                if let Some(number) = be_u32(blob, position) {
                    values.insert(name, RpmValue::Number(number));
                }
            }
            _ => {}
        }
    }
    (!values.is_empty()).then_some(values)
}

fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([field[0], field[1], field[2], field[3]]))
}

/// Package attributes from an `rpmdb.sqlite` image.
pub fn parse_rpm_sqlite(data: &[u8]) -> Result<Vec<Attributes>> {
    let scratch = tempfile::Builder::new()
        .prefix("lc-rpm-")
        .tempdir()
        .map_err(|error| Error::plugin(format!("temporary directory: {error}")))?;
    let path = scratch.path().join("rpmdb.sqlite");
    std::fs::File::create_new(&path)
        .and_then(|mut file| {
            // Only the main database file is available: read it in
            // rollback-journal mode instead of looking for WAL files.
            match data.get(18..20) {
                Some([2, 2]) => {
                    file.write_all(&data[..18])?;
                    file.write_all(&[1, 1])?;
                    file.write_all(&data[20..])
                }
                _ => file.write_all(data),
            }
        })
        .map_err(|error| Error::plugin(format!("rpmdb copy: {error}")))?;
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite_error)?;
    let mut statement = connection
        .prepare("SELECT blob FROM Packages")
        .map_err(sqlite_error)?;
    let blobs = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sqlite_error)?;
    let mut packages = Vec::new();
    for blob in blobs {
        let Some(values) = parse_rpm_header(&blob) else {
            continue;
        };
        let text = |name: &str| match values.get(name) {
            Some(RpmValue::Text(text)) => Some(text.as_str()),
            Some(RpmValue::Number(_)) | None => None,
        };
        let number = |name: &str| match values.get(name) {
            Some(RpmValue::Number(number)) => Some(*number),
            Some(RpmValue::Text(_)) | None => None,
        };
        let mut attributes = Attributes::new();
        for name in [
            "linux.software",
            "linux.version",
            "linux.release",
            "linux.arch",
            "linux.vendor",
            "linux.summary",
        ] {
            attributes.insert_optional(name, text(name));
        }
        attributes.insert_optional(
            "linux.size",
            number("linux.size").map(|size| size.to_string()),
        );
        attributes.insert_optional(
            "linux.install_time",
            number("linux.install_time").and_then(|seconds| rfc3339(i64::from(seconds))),
        );
        attributes.insert("linux.source", "rpm");
        packages.push(attributes);
    }
    Ok(packages)
}

fn sqlite_error(error: rusqlite::Error) -> Error {
    Error::plugin(format!("rpmdb.sqlite: {error}"))
}

pub fn collect(volume: &View) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let status = crate::evidence::text(volume, "var/lib/dpkg/status", 64 * 1024 * 1024)?;
    for mut attributes in parse_dpkg_status(status.as_deref()) {
        attributes.insert("source.path", "var/lib/dpkg/status");
        artifacts.push(software_artifact(attributes));
    }
    if let Some(node) = volume.stat(RPM_DATABASE)? {
        if node.is_file() {
            let data =
                crate::evidence::read(volume, RPM_DATABASE, BINARY_DB_CAP)?.unwrap_or_default();
            // A broken RPM database must not hide the dpkg packages.
            match parse_rpm_sqlite(&data) {
                Ok(packages) => artifacts.extend(packages.into_iter().map(|mut attributes| {
                    attributes.insert("source.path", RPM_DATABASE);
                    software_artifact(attributes)
                })),
                Err(error) => volume.context().log(
                    LogLevel::Warn,
                    &format!("rpmdb.sqlite parse failed: {error}"),
                ),
            }
        }
    }
    Ok(artifacts)
}

fn software_artifact(mut attributes: Attributes) -> Artifact {
    let name = attributes
        .get("linux.software")
        .cloned()
        .unwrap_or(Value::Nil);
    let title = format!("软件 {}", name.as_str().unwrap_or("None"));
    retain_truthy(&mut attributes);
    Artifact {
        artifact_type: "linux.software".to_owned(),
        title,
        value: Some(name),
        attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_paragraphs_and_installed_status() {
        let packages = parse_dpkg_status(Some(
            "Package: kali-linux\nStatus: install ok installed\nVersion: 2026.2\n\
             Architecture: amd64\nDescription: Kali Linux base\n metapackage\n\n\
             Package: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\
             Architecture: all\n",
        ));
        let field = |index: usize, key: &str| {
            packages[index]
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        assert_eq!(packages.len(), 2);
        assert_eq!(field(0, "linux.software").as_deref(), Some("kali-linux"));
        assert_eq!(field(0, "linux.status").as_deref(), Some("已安装"));
        assert_eq!(field(0, "linux.version").as_deref(), Some("2026.2"));
        assert_eq!(
            field(1, "linux.status").as_deref(),
            Some("deinstall ok config-files")
        );
    }

    /// `(tag, type, offset, count)` of one header index entry.
    type IndexEntry = (u32, u32, u32, u32);

    fn header(entries: &[IndexEntry], data: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
        for (tag, kind, offset, count) in entries {
            for field in [tag, kind, offset, count] {
                blob.extend_from_slice(&field.to_be_bytes());
            }
        }
        blob.extend_from_slice(data);
        blob
    }

    fn sample() -> (Vec<IndexEntry>, Vec<u8>) {
        let entries = vec![
            (1000, 6, 0, 1),
            (1001, 6, 4, 1),
            (1002, 6, 8, 1),
            (1022, 6, 14, 1),
            (1009, 4, 21, 1),
        ];
        let mut data = b"zsh\x005.9\x001.el9\x00x86_64\x00".to_vec();
        data.extend_from_slice(&2_345_678_u32.to_be_bytes());
        data.push(0);
        (entries, data)
    }

    #[test]
    fn rpm_header_with_magic() {
        let (entries, data) = sample();
        let mut blob = vec![0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
        blob.extend(header(&entries, &data));
        let values = parse_rpm_header(&blob).expect("header");
        assert_eq!(values["linux.software"], RpmValue::Text("zsh".to_owned()));
        assert_eq!(values["linux.release"], RpmValue::Text("1.el9".to_owned()));
        assert_eq!(values["linux.arch"], RpmValue::Text("x86_64".to_owned()));
        assert_eq!(values["linux.size"], RpmValue::Number(2_345_678));
        assert_eq!(parse_rpm_header(&[0; 64]), None);
    }

    #[test]
    fn rpm_header_export_blob_from_sqlite() {
        let (entries, data) = sample();
        let blob = header(&entries, &data);
        let values = parse_rpm_header(&blob).expect("bare header");
        assert_eq!(values["linux.version"], RpmValue::Text("5.9".to_owned()));
        let mut padded = blob.clone();
        padded.push(0);
        assert_eq!(parse_rpm_header(&padded), None);
    }

    #[test]
    fn rpm_sqlite_packages_table() {
        let (entries, data) = sample();
        let blob = header(&entries, &data);
        let scratch = tempfile::tempdir().expect("tempdir");
        let path = scratch.path().join("rpmdb.sqlite");
        let connection = Connection::open(&path).expect("database");
        connection
            .execute_batch(
                "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);",
            )
            .expect("schema");
        connection
            .execute("INSERT INTO Packages (blob) VALUES (?1)", [&blob])
            .expect("row");
        drop(connection);
        let mut database = std::fs::read(&path).expect("read");
        // A WAL-mode header (as rpm writes it) must still be readable.
        database[18] = 2;
        database[19] = 2;
        let packages = parse_rpm_sqlite(&database).expect("parse");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].get("linux.size"), Some(&Value::from("2345678")));
        assert_eq!(packages[0].get("linux.source"), Some(&Value::from("rpm")));
    }
}
