//! USB使用记录: kernel / udisks lines in the text logs under var/log.

use chrono::{DateTime, NaiveDate};
use std::collections::HashMap;

use lovelycarve_plugin::{
    text::split_lines, Artifact, Attributes, EvidenceVolume, Result, TimelineEvent, Value,
};

use crate::text::{clean_text, is_digits, is_space, retain_truthy, split_whitespace};

const USB_LOG_MARKERS: [&str; 12] = [
    "New USB device found",
    "new high-speed USB device",
    "new full-speed USB device",
    "new low-speed USB device",
    "new super-speed USB device",
    "usb-storage",
    "udisks",
    "Mounted",
    "Cleaning up mount point",
    "Product:",
    "Manufacturer:",
    "SerialNumber:",
];
const TIMELINE_MARKERS: [&str; 3] = ["usb-storage", "Mounted", "Cleaning up mount point"];
const USB_LOG_CANDIDATES: [&str; 13] = [
    "syslog",
    "syslog.1",
    "syslog.2",
    "messages",
    "messages.1",
    "kern.log",
    "kern.log.1",
    "daemon.log",
    "daemon.log.1",
    "user.log",
    "debug",
    "secure",
    "auth.log",
];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const LOG_CAP: u64 = 16 * 1024 * 1024;

/// Local clock of a syslog line prefix `Mon dd HH:MM:SS` in `year`
/// (`^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`).
pub fn syslog_timestamp(line: &str, year: i32) -> Option<String> {
    let month_name = line.get(..3)?;
    let month = MONTHS.iter().position(|name| *name == month_name)? as u32 + 1;
    let fields = split_whitespace(line[3..].strip_prefix(is_space)?);
    let (day, clock) = (fields.first()?, fields.get(1)?);
    if day.len() > 2 || !is_digits(day) {
        return None;
    }
    let clock = clock.get(..8)?;
    let parts: Vec<&str> = clock.split(':').collect();
    let [hour, minute, second] = parts.as_slice() else {
        return None;
    };
    if [hour, minute, second]
        .iter()
        .any(|part| part.len() != 2 || !is_digits(part))
    {
        return None;
    }
    Some(
        NaiveDate::from_ymd_opt(year, month, day.parse().ok()?)?
            .and_hms_opt(
                hour.parse().ok()?,
                minute.parse().ok()?,
                second.parse().ok()?,
            )?
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string(),
    )
}

pub fn collect(volume: &EvidenceVolume) -> Result<(Vec<Artifact>, Vec<TimelineEvent>)> {
    let mut artifacts = Vec::new();
    let mut timeline = Vec::new();
    let nodes = crate::list_or_empty(volume, "var/log")?;
    let logs: HashMap<_, _> = nodes
        .into_iter()
        .filter(|node| node.is_file())
        .map(|node| (node.name.clone(), node))
        .collect();
    for name in USB_LOG_CANDIDATES {
        let Some(node) = logs.get(name) else {
            continue;
        };
        if node.size == 0 {
            continue;
        }
        let modified = node.timestamps.modified.as_deref().unwrap_or_default();
        let year = modified
            .get(..4)
            .filter(|year| is_digits(year))
            .and_then(|year| year.parse().ok());
        let source = format!("var/log/{name}");
        let text = crate::evidence::text(volume, &source, LOG_CAP)?.unwrap_or_default();
        for (index, raw_line) in split_lines(&text).into_iter().enumerate() {
            volume.context().check_cancelled()?;
            if !USB_LOG_MARKERS
                .iter()
                .any(|marker| raw_line.contains(marker))
            {
                continue;
            }
            let Some(detail) = clean_text(raw_line, 400) else {
                continue;
            };
            let explicit = raw_line
                .split_whitespace()
                .next()
                .and_then(|prefix| DateTime::parse_from_rfc3339(prefix).ok())
                .map(|time| time.to_rfc3339());
            let local = year.and_then(|year| syslog_timestamp(raw_line, year));
            let mut attributes = Attributes::new();
            attributes.insert("linux.log", name);
            attributes.insert("linux.detail", detail);
            attributes.insert("linux.source", source.as_str());
            attributes.insert("source.line", (index + 1) as u64);
            attributes.insert_optional("linux.time", explicit.as_deref());
            attributes.insert_optional("linux.local_time", local);
            if explicit.is_none() {
                attributes.insert(
                    "linux.time_basis",
                    "日志本地时间；若补足年份，则来自源文件修改时间",
                );
            }
            retain_truthy(&mut attributes);
            artifacts.push(Artifact {
                artifact_type: "linux.usb".to_owned(),
                title: "USB 使用记录".to_owned(),
                value: Some(Value::from(name)),
                attributes,
            });
            if let Some(when) = explicit {
                if TIMELINE_MARKERS
                    .iter()
                    .any(|marker| raw_line.contains(marker))
                {
                    let mut attributes = Attributes::new();
                    attributes.insert("linux.log", name);
                    timeline.push(TimelineEvent {
                        timestamp: when,
                        event_type: "linux.usb".to_owned(),
                        description: clean_text(raw_line, 200)
                            .unwrap_or_else(|| "USB 事件".to_owned()),
                        attributes,
                    });
                }
            }
            if artifacts.len() + timeline.len() > 10_000 {
                return Err(lovelycarve_plugin::Error::new(
                    "RESOURCE_LIMIT",
                    "USB 日志超过 10000 项",
                ));
            }
        }
    }
    Ok((artifacts, timeline))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_prefix_preserves_local_clock() {
        assert_eq!(
            syslog_timestamp("Mar  1 10:20:30 kali kernel: usb-storage 1-1:1.0", 2024).as_deref(),
            Some("2024-03-01T10:20:30")
        );
        assert_eq!(syslog_timestamp("Feb 30 10:20:30 x", 2024), None);
        assert_eq!(syslog_timestamp("Foo  1 10:20:30 x", 2024), None);
        assert_eq!(syslog_timestamp("Mar 123 10:20:30 x", 2024), None);
        assert_eq!(syslog_timestamp("Mar 1 1:20:30 x", 2024), None);
    }
}
