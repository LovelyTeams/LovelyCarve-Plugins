//! utmp / wtmp / btmp: 384-byte little-endian records.

use lovelycarve_plugin::{Attributes, Result, Value, View};

use crate::{
    item::Artifact,
    text::{retain_truthy, rfc3339},
    BINARY_DB_CAP,
};

const RECORD_SIZE: usize = 384;
const BOOT_TIME: i32 = 2;
const USER_PROCESS: i32 = 7;
const SHUTDOWN_TIME: i32 = 11;

#[derive(Clone, Debug, PartialEq)]
pub struct UtmpRecord {
    pub kind: i32,
    pub pid: i32,
    pub line: String,
    pub user: String,
    pub host: String,
    pub timestamp: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginOutcome {
    Success,
    Failure,
}

pub fn parse(data: &[u8]) -> Vec<UtmpRecord> {
    let (records, _) = data.as_chunks::<RECORD_SIZE>();
    records
        .iter()
        .map(|record| UtmpRecord {
            kind: le_i32(record, 0),
            pid: le_i32(record, 4),
            line: c_string(&record[8..40]),
            user: c_string(&record[44..76]),
            host: c_string(&record[76..332]),
            timestamp: le_i32(record, 340),
        })
        .collect()
}

fn le_i32(record: &[u8; RECORD_SIZE], offset: usize) -> i32 {
    i32::from_le_bytes([
        record[offset],
        record[offset + 1],
        record[offset + 2],
        record[offset + 3],
    ])
}

fn c_string(field: &[u8]) -> String {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

pub fn read(volume: &View, path: &str) -> Result<Vec<UtmpRecord>> {
    let Some(node) = volume.stat(path)? else {
        return Ok(Vec::new());
    };
    if !node.is_file() {
        return Ok(Vec::new());
    }
    let data = crate::evidence::read(volume, path, BINARY_DB_CAP)?.unwrap_or_default();
    if !data.len().is_multiple_of(RECORD_SIZE) {
        return Err(lovelycarve_plugin::Error::plugin(format!(
            "{path} 含不完整的 utmp 记录"
        )));
    }
    Ok(parse(&data))
}

/// Login records; the login (and logout) times are their timeline events.
pub fn login_artifacts(records: &[UtmpRecord], outcome: LoginOutcome) -> Vec<Artifact> {
    let (artifact_type, title) = match outcome {
        LoginOutcome::Success => ("linux.login", "登录信息"),
        LoginOutcome::Failure => ("linux.loginfail", "登录失败"),
    };
    let mut artifacts = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if record.kind != USER_PROCESS || record.user.is_empty() {
            continue;
        }
        let when = rfc3339(i64::from(record.timestamp));
        let mut attributes = Attributes::new();
        attributes.insert("linux.user", record.user.as_str());
        attributes.insert("linux.terminal", record.line.as_str());
        attributes.insert("linux.remote_host", record.host.as_str());
        attributes.insert_optional("linux.time", when.as_deref());
        attributes.insert(
            "linux.source",
            match outcome {
                LoginOutcome::Success => "var/log/wtmp",
                LoginOutcome::Failure => "var/log/btmp",
            },
        );
        if outcome == LoginOutcome::Success {
            // A reused terminal/PID or a reboot ends the search. Do not pair
            // this login with a later session's logout.
            if let Some(end) = records[index + 1..]
                .iter()
                .find(|later| {
                    later.kind == BOOT_TIME
                        || ((later.kind == 7 || later.kind == 8)
                            && later.pid == record.pid
                            && later.line == record.line)
                })
                .filter(|later| later.kind == 8 && later.timestamp >= record.timestamp)
            {
                attributes.insert_optional("linux.logout_time", rfc3339(i64::from(end.timestamp)));
                attributes.insert(
                    "linux.duration_seconds",
                    i64::from(end.timestamp) - i64::from(record.timestamp),
                );
            }
        }
        retain_truthy(&mut attributes);
        // Record 0 at offset 0 is an address, not an empty value.
        attributes.insert("linux.record", index as u64);
        attributes.insert("linux.offset", (index * RECORD_SIZE) as u64);
        artifacts.push(Artifact {
            artifact_type: artifact_type.to_owned(),
            title: title.to_owned(),
            value: Some(Value::from(record.user.as_str())),
            attributes,
        });
    }
    artifacts
}

/// Boot and shutdown records; their times are their timeline events.
pub fn boot_artifacts(records: &[UtmpRecord]) -> Vec<Artifact> {
    let mut artifacts = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let (event, event_type) = match record.kind {
            BOOT_TIME => ("开机", "linux.boot"),
            SHUTDOWN_TIME => ("关机", "linux.shutdown"),
            _ => continue,
        };
        let when = rfc3339(i64::from(record.timestamp));
        let mut attributes = Attributes::new();
        attributes.insert("linux.event", event);
        attributes.insert_optional("linux.time", when.as_deref());
        attributes.insert("linux.source", "var/log/wtmp");
        attributes.insert("linux.record", index as u64);
        attributes.insert("linux.offset", (index * RECORD_SIZE) as u64);
        artifacts.push(Artifact {
            artifact_type: event_type.to_owned(),
            title: "开关机时间".to_owned(),
            value: Some(Value::from(event)),
            attributes,
        });
    }
    artifacts
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn does_not_silently_drop_records_above_old_soft_cap() {
        let records = vec![
            UtmpRecord {
                kind: USER_PROCESS,
                pid: 1,
                line: "pts/0".into(),
                user: "user".into(),
                host: String::new(),
                timestamp: 1
            };
            4500
        ];
        let artifacts = login_artifacts(&records, LoginOutcome::Failure);
        assert_eq!(artifacts.len(), 4500);
        assert_eq!(
            artifacts
                .last()
                .unwrap()
                .attributes
                .get("linux.record")
                .and_then(Value::as_u64),
            Some(4499)
        );
    }

    fn record(kind: i32, user: &[u8], line: &[u8], host: &[u8], seconds: i32) -> Vec<u8> {
        let mut bytes = vec![0_u8; RECORD_SIZE];
        bytes[0..4].copy_from_slice(&kind.to_le_bytes());
        bytes[4..8].copy_from_slice(&1234_i32.to_le_bytes());
        bytes[8..8 + line.len()].copy_from_slice(line);
        bytes[40..42].copy_from_slice(b"~~");
        bytes[44..44 + user.len()].copy_from_slice(user);
        bytes[76..76 + host.len()].copy_from_slice(host);
        bytes[336..340].copy_from_slice(&7_i32.to_le_bytes());
        bytes[340..344].copy_from_slice(&seconds.to_le_bytes());
        bytes
    }

    #[test]
    fn filters_user_process_and_boot_records() {
        let blob = [
            record(7, b"kali", b"pts/0", b"10.0.0.5", 1_700_000_000),
            record(8, b"kali", b"pts/0", b"10.0.0.5", 1_700_000_600),
            record(2, b"reboot", b"~", b"", 1_699_999_000),
            record(11, b"shutdown", b"~", b"", 1_699_999_500),
            record(1, b"", b"", b"", 0),
        ]
        .concat();
        let records = parse(&blob);
        assert_eq!(
            records.iter().map(|record| record.kind).collect::<Vec<_>>(),
            vec![7, 8, 2, 11, 1]
        );
        let logins = login_artifacts(&records, LoginOutcome::Success);
        assert_eq!(logins.len(), 1);
        assert_eq!(
            logins[0].attributes.get("linux.remote_host"),
            Some(&Value::from("10.0.0.5"))
        );
        assert_eq!(
            logins[0].attributes.get("linux.logout_time"),
            Some(&Value::from("2023-11-14T22:23:20+00:00"))
        );
        let boots = boot_artifacts(&records);
        assert_eq!(
            boots
                .iter()
                .map(|artifact| artifact.value.clone())
                .collect::<Vec<_>>(),
            vec![Some(Value::from("开机")), Some(Value::from("关机"))]
        );
        assert_eq!(boots[1].artifact_type, "linux.shutdown");
    }
}
