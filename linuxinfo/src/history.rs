//! Bash and Zsh histories, one artifact per logical command, with evidence timestamps only.
use std::collections::BTreeSet;

use lovelycarve_plugin::{Artifact, Attributes, Error, EvidenceVolume, Result};

use crate::{text::rfc3339, users::parse_passwd};

pub fn parse(text: &str, user: &str, shell: &str, source: &str) -> Vec<Artifact> {
    let mut records = Vec::new();
    let mut timestamp = None;
    let mut command = String::new();
    let mut first_line = 0;
    for (index, line) in text.lines().enumerate() {
        if command.is_empty() {
            first_line = index + 1;
            if shell == "bash"
                && line.starts_with('#')
                && line[1..].bytes().all(|byte| byte.is_ascii_digit())
            {
                timestamp = line[1..].parse::<i64>().ok().and_then(rfc3339);
                continue;
            }
        }
        let line = if shell == "zsh" && command.is_empty() {
            if let Some((header, content)) = line
                .strip_prefix(": ")
                .and_then(|rest| rest.split_once(';'))
            {
                timestamp = header
                    .split_once(':')
                    .and_then(|(seconds, _)| seconds.parse::<i64>().ok())
                    .and_then(rfc3339);
                content
            } else {
                line
            }
        } else {
            line
        };
        command.push_str(line);
        if shell == "zsh" && command.ends_with('\\') {
            command.pop();
            command.push('\n');
            continue;
        }
        if !command.is_empty() {
            let mut attributes: Attributes = [
                ("linux.user", user),
                ("linux.shell", shell),
                ("linux.command", command.as_str()),
                ("linux.source", source),
            ]
            .into_iter()
            .collect();
            attributes.insert("linux.line", first_line as u64);
            attributes.insert_optional("linux.time", timestamp.take());
            records.push(Artifact {
                artifact_type: "linux.shellhistory".into(),
                title: command.clone(),
                value: Some(command.clone().into()),
                attributes,
            });
        }
        command.clear();
    }
    if !command.is_empty() {
        let mut attributes: Attributes = [
            ("linux.user", user),
            ("linux.shell", shell),
            ("linux.command", command.as_str()),
            ("linux.source", source),
        ]
        .into_iter()
        .collect();
        attributes.insert("linux.line", first_line as u64);
        attributes.insert_optional("linux.time", timestamp);
        records.push(Artifact {
            artifact_type: "linux.shellhistory".into(),
            title: command.clone(),
            value: Some(command.into()),
            attributes,
        });
    }
    records
}

pub fn collect(volume: &EvidenceVolume) -> Result<Vec<Artifact>> {
    let mut homes = BTreeSet::from([("root".to_owned(), "root".to_owned())]);
    for user in
        parse_passwd(crate::evidence::text(volume, "etc/passwd", 8 * 1024 * 1024)?.as_deref())
    {
        if let (Some(name), Some(home)) = (
            user.get("linux.username").and_then(|value| value.as_str()),
            user.get("linux.home").and_then(|value| value.as_str()),
        ) {
            if home != "/" && home != "/nonexistent" {
                homes.insert((name.to_owned(), home.trim_start_matches('/').to_owned()));
            }
        }
    }
    let mut records = Vec::new();
    for (user, home) in homes {
        for (file, shell) in [(".bash_history", "bash"), (".zsh_history", "zsh")] {
            let source = format!("{home}/{file}");
            let Some(node) = volume.stat(&source)? else {
                continue;
            };
            if node.size > 8 * 1024 * 1024 {
                return Err(Error::new(
                    "RESOURCE_LIMIT",
                    format!("历史文件超过 8 MiB: {source}"),
                ));
            }
            if let Some(text) = crate::evidence::text(volume, &source, node.size)? {
                records.extend(parse(&text, &user, shell, &source));
            }
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelycarve_plugin::Value;

    #[test]
    fn extended_zsh_and_bash_timestamps_and_multiline_commands() {
        let records = parse(
            ": 1700000000:0;printf hello\\\nworld\nplain command\n",
            "root",
            "zsh",
            "root/.zsh_history",
        );
        assert_eq!(
            records
                .iter()
                .map(|record| record.title.as_str())
                .collect::<Vec<_>>(),
            ["printf hello\nworld", "plain command"]
        );
        assert_eq!(
            records[0].attributes.get("linux.time"),
            Some(&Value::from("2023-11-14T22:13:20+00:00"))
        );
        assert_eq!(records[1].attributes.get("linux.time"), Some(&Value::Nil));
        let records = parse(
            "#1700000000\nls\n# comment\n",
            "root",
            "bash",
            "root/.bash_history",
        );
        assert_eq!(
            records
                .iter()
                .map(|record| record.title.as_str())
                .collect::<Vec<_>>(),
            ["ls", "# comment"]
        );
    }
}
