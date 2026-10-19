//! 用户列表: passwd + shadow password policy, groups and bash histories.

use std::collections::HashMap;

use lovelycarve_plugin::{text::split_lines, Attributes, Result, Value, View};

use crate::{
    item::Artifact,
    text::{clean_text, is_digits, rfc3339},
};

const PASSWORD_HASH_ALGORITHMS: [(&str, &str); 7] = [
    ("$1", "MD5"),
    ("$2", "Blowfish"),
    ("$5", "SHA-256"),
    ("$6", "SHA-512"),
    ("$y", "yescrypt"),
    ("$g", "gost-yescrypt"),
    ("$7", "scrypt"),
];

pub fn parse_passwd(text: Option<&str>) -> Vec<Attributes> {
    let mut users = Vec::new();
    for line in text.map(split_lines).unwrap_or_default() {
        let parts: Vec<&str> = line.split(':').collect();
        let [name, _, uid, gid, gecos, home, shell, ..] = parts.as_slice() else {
            continue;
        };
        let mut attributes = Attributes::new();
        attributes.insert("linux.username", *name);
        attributes.insert("linux.uid", *uid);
        attributes.insert("linux.gid", *gid);
        attributes.insert_optional("linux.gecos", clean_text(gecos, 200));
        attributes.insert("linux.home", *home);
        attributes.insert("linux.shell", *shell);
        users.push(attributes);
    }
    users
}

pub fn parse_shadow(text: Option<&str>) -> HashMap<String, Attributes> {
    let mut policies = HashMap::new();
    for line in text.map(split_lines).unwrap_or_default() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 9 {
            continue;
        }
        let (name, digest, last_change) = (parts[0], parts[1], parts[2]);
        let mut attributes = Attributes::new();
        if !digest.is_empty() {
            let prefix: String = digest.chars().take(2).collect();
            let algorithm = PASSWORD_HASH_ALGORITHMS
                .iter()
                .find_map(|(marker, algorithm)| (*marker == prefix).then_some(*algorithm))
                .or_else(|| digest.starts_with("$argon2").then_some("argon2"));
            if let Some(algorithm) = algorithm {
                attributes.insert("linux.password_algo", algorithm);
                attributes.insert("linux.password_hash", digest);
            } else if digest.starts_with('!') {
                attributes.insert("linux.password_status", "已锁定");
            } else if digest == "*" {
                attributes.insert("linux.password_status", "无密码(禁用)");
            } else if digest == "x" {
                attributes.insert("linux.password_status", "影子口令");
            }
        }
        if is_digits(last_change) {
            let days = last_change.parse::<i64>().ok();
            if days.is_some_and(|days| days > 0) {
                let changed = days
                    .and_then(|days| days.checked_mul(86_400))
                    .and_then(rfc3339);
                attributes.insert_optional("linux.password_last_change", changed);
            }
        }
        for (value, key) in [
            (parts[3], "linux.password_min_days"),
            (parts[4], "linux.password_max_days"),
            (parts[5], "linux.password_warn_days"),
        ] {
            if is_digits(value) {
                attributes.insert(key, value);
            }
        }
        policies.insert(name.to_owned(), attributes);
    }
    policies
}

pub fn parse_group(text: Option<&str>) -> Vec<Attributes> {
    let mut groups = Vec::new();
    for line in text.map(split_lines).unwrap_or_default() {
        let parts: Vec<&str> = line.split(':').collect();
        let [name, _, gid, members, ..] = parts.as_slice() else {
            continue;
        };
        let mut attributes = Attributes::new();
        attributes.insert("linux.group", *name);
        attributes.insert("linux.group_gid", *gid);
        attributes.insert(
            "linux.group_members",
            clean_text(members, 200).unwrap_or_else(|| "无".to_owned()),
        );
        groups.push(attributes);
    }
    groups
}

pub fn collect(volume: &View) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let policies =
        parse_shadow(crate::evidence::text(volume, "etc/shadow", 8 * 1024 * 1024)?.as_deref());
    for mut attributes in
        parse_passwd(crate::evidence::text(volume, "etc/passwd", 8 * 1024 * 1024)?.as_deref())
    {
        let name = attributes
            .get("linux.username")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if let Some(policy) = policies.get(&name) {
            attributes.update(policy);
            attributes.insert("linux.source", "etc/passwd;etc/shadow");
        } else {
            attributes.insert("linux.source", "etc/passwd");
        }
        let uid = attributes
            .get("linux.uid")
            .and_then(Value::as_str)
            .and_then(|id| id.parse::<u32>().ok());
        attributes.insert(
            "linux.user_class",
            if uid == Some(0) || uid.is_some_and(|id| id >= 1000 && id != 65534) {
                "常规用户"
            } else {
                "系统用户"
            },
        );
        artifacts.push(Artifact {
            artifact_type: "linux.user".to_owned(),
            title: format!("用户 {name}"),
            value: Some(Value::from(name)),
            attributes,
        });
    }
    Ok(artifacts)
}

pub fn groups(volume: &View) -> Result<Vec<Artifact>> {
    Ok(
        parse_group(crate::evidence::text(volume, "etc/group", 8 * 1024 * 1024)?.as_deref())
            .into_iter()
            .map(|mut attributes| {
                attributes.insert("linux.source", "etc/group");
                let name = attributes
                    .get("linux.group")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                Artifact {
                    artifact_type: "linux.group".to_owned(),
                    title: name.clone(),
                    value: Some(name.into()),
                    attributes,
                }
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(attributes: &Attributes, key: &str) -> Option<String> {
        attributes
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    #[test]
    fn policy_fields_and_hash_algorithm() {
        let policies = parse_shadow(Some(
            "root:$y$j9T$abc:19855:0:99999:7:::\n\
             daemon:*:19855:0:99999:7:::\n\
             locked:!:19855::::::\n\
             bcrypt:$2b$12$abc:0::::::\n",
        ));
        let root = &policies["root"];
        assert_eq!(
            text(root, "linux.password_algo").as_deref(),
            Some("yescrypt")
        );
        assert_eq!(
            text(root, "linux.password_max_days").as_deref(),
            Some("99999")
        );
        assert_eq!(
            text(root, "linux.password_last_change").as_deref(),
            Some("2024-05-12T00:00:00+00:00")
        );
        assert_eq!(
            text(&policies["daemon"], "linux.password_status").as_deref(),
            Some("无密码(禁用)")
        );
        assert_eq!(
            text(&policies["locked"], "linux.password_status").as_deref(),
            Some("已锁定")
        );
        assert_eq!(
            text(&policies["bcrypt"], "linux.password_algo").as_deref(),
            Some("Blowfish")
        );
        assert!(!policies["bcrypt"].contains_key("linux.password_last_change"));
    }

    #[test]
    fn passwd_and_group_records() {
        let users = parse_passwd(Some("root:x:0:0:root:/root:/usr/bin/zsh\nshort:x:1\n"));
        assert_eq!(users.len(), 1);
        assert_eq!(
            text(&users[0], "linux.shell").as_deref(),
            Some("/usr/bin/zsh")
        );
        let groups = parse_group(Some("root:x:0:\nsudo:x:27:kali,  alice\n"));
        assert_eq!(
            text(&groups[0], "linux.group_members").as_deref(),
            Some("无")
        );
        assert_eq!(
            text(&groups[1], "linux.group_members").as_deref(),
            Some("kali, alice")
        );
    }
}
