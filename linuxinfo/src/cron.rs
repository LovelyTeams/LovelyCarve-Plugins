//! 定时任务: /etc/crontab and the per-user crontabs under var/spool/cron.

use lovelycarve_plugin::{text::split_lines, Attributes, Result, Value, View};

use crate::{
    item::Artifact,
    list_or_empty,
    text::{clean_text, is_upper, split_whitespace, split_whitespace_max, strip},
};

const CRON_SPECIAL: [&str; 7] = [
    "@reboot",
    "@yearly",
    "@annually",
    "@monthly",
    "@weekly",
    "@daily",
    "@hourly",
];

/// Whether each crontab line names the user it runs as (/etc/crontab) or
/// not (var/spool/cron).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserColumn {
    Present,
    Absent,
}

pub fn parse_crontab(
    text: Option<&str>,
    user: &str,
    source: &str,
    user_column: UserColumn,
) -> Vec<Artifact> {
    let mut entries = Vec::new();
    for line in text.map(split_lines).unwrap_or_default() {
        let stripped = strip(line);
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let Some(first_field) = split_whitespace(stripped).first().copied() else {
            continue;
        };
        let mut entry_user = user.to_owned();
        let (schedule, command) = if CRON_SPECIAL
            .iter()
            .any(|special| stripped.starts_with(special))
        {
            let mut rest = strip(&stripped[first_field.len()..]);
            if user_column == UserColumn::Present && !rest.is_empty() {
                let (named, command) = rest.split_once(' ').unwrap_or((rest, ""));
                entry_user = named.to_owned();
                rest = strip(command);
            }
            (first_field.to_owned(), rest)
        } else if first_field
            .split_once('=')
            .is_some_and(|(name, _)| is_upper(name))
        {
            // SHELL= / PATH= / MAILTO= environment lines.
            continue;
        } else {
            let (max_splits, expected) = match user_column {
                UserColumn::Present => (6, 7),
                UserColumn::Absent => (5, 6),
            };
            let parts = split_whitespace_max(stripped, max_splits);
            if parts.len() != expected {
                continue;
            }
            if user_column == UserColumn::Present {
                entry_user = parts[5].to_owned();
            }
            (parts[..5].join(" "), parts[parts.len() - 1])
        };
        if command.is_empty() {
            continue;
        }
        let mut attributes = Attributes::new();
        attributes.insert("linux.user", entry_user);
        attributes.insert("linux.schedule", schedule);
        attributes.insert_optional("linux.command", clean_text(command, 400));
        attributes.insert("linux.source", source);
        entries.push(Artifact {
            artifact_type: "linux.cron".to_owned(),
            title: "定时任务".to_owned(),
            value: Some(Value::from(command)),
            attributes,
        });
    }
    entries
}

pub fn collect(volume: &View) -> Result<Vec<Artifact>> {
    let mut artifacts = parse_crontab(
        crate::evidence::text(volume, "etc/crontab", 1024 * 1024)?.as_deref(),
        "system",
        "etc/crontab",
        UserColumn::Present,
    );
    for base in ["var/spool/cron", "var/spool/cron/crontabs"] {
        for node in list_or_empty(volume, base)? {
            if !node.is_file() {
                continue;
            }
            let path = format!("{base}/{}", node.name);
            artifacts.extend(parse_crontab(
                crate::evidence::text(volume, &path, 1024 * 1024)?.as_deref(),
                &node.name,
                &path,
                UserColumn::Absent,
            ));
        }
    }
    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(artifact: &Artifact, key: &str) -> String {
        artifact
            .attributes
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn system_and_user_lines() {
        let entries = parse_crontab(
            Some(
                "SHELL=/bin/bash\n17 *\t* * *\troot cd / && run-parts --report /etc/cron.hourly\n\
                 @reboot root /usr/local/bin/beacon.sh\n# comment\n",
            ),
            "system",
            "etc/crontab",
            UserColumn::Present,
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(attribute(&entries[0], "linux.schedule"), "17 * * * *");
        assert_eq!(attribute(&entries[0], "linux.user"), "root");
        assert!(attribute(&entries[0], "linux.command").starts_with("cd /"));
        assert_eq!(attribute(&entries[1], "linux.schedule"), "@reboot");
        assert_eq!(attribute(&entries[1], "linux.user"), "root");
        assert!(attribute(&entries[1], "linux.command").starts_with("/usr/local/bin"));

        let user_entries = parse_crontab(
            Some("*/5 * * * * /home/kali/sync.sh --quiet\n"),
            "kali",
            "var/spool/cron/crontabs/kali",
            UserColumn::Absent,
        );
        assert_eq!(attribute(&user_entries[0], "linux.user"), "kali");
        assert_eq!(
            attribute(&user_entries[0], "linux.command"),
            "/home/kali/sync.sh --quiet"
        );
    }
}
