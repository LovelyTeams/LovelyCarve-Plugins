//! Result presentation: the title carries each record's identity, the
//! attributes keep the complete evidence, and the result nodes declare the
//! columns of the 「分析结果」 record tables.

use std::collections::BTreeMap;

use lovelycarve_plugin::{Artifact, ResultColumn, ResultNode, Value};

use crate::text::strip;

/// `(attribute key, column label)`.
type Column = (&'static str, &'static str);

/// `(artifact type, node display name, columns)`.
type NodeSchema = (&'static str, &'static str, &'static [Column]);

/// Result-tree node per artifact type.
const RESULT_NODES: &[NodeSchema] = &[
    (
        "linux.recent",
        "应用程序最近访问",
        &[
            ("linux.user", "用户"),
            ("recent.href", "文件 URI"),
            ("recent.mime", "文件类型"),
            ("recent.modified", "文件记录修改时间"),
            ("recent.application_modified", "应用访问记录修改时间"),
            ("recent.application_count", "访问次数"),
            ("recent.application_exec", "应用命令"),
            ("recent.added", "加入时间"),
            ("recent.visited", "访问时间（原值）"),
            ("linux.source", "源文件"),
        ],
    ),
    (
        "linux.systeminfo",
        "系统信息",
        &[
            ("linux.key", "英文名称"),
            ("linux.field_value", "值"),
            ("linux.source", "源文件"),
        ],
    ),
    ("linux.timezone", "时区信息", &[("linux.source", "源文件")]),
    (
        "linux.host",
        "Hosts",
        &[
            ("linux.address", "IP"),
            ("linux.aliases", "别名"),
            ("linux.source", "源文件"),
        ],
    ),
    (
        "linux.user",
        "用户列表",
        &[
            ("linux.username", "用户名"),
            ("linux.uid", "UID"),
            ("linux.user_class", "用户类型"),
            ("linux.gid", "GID"),
            ("linux.gecos", "描述"),
            ("linux.home", "主目录"),
            ("linux.shell", "Shell"),
            ("linux.password_status", "口令状态"),
            ("linux.password_algo", "口令算法"),
            ("linux.password_last_change", "口令最后修改"),
        ],
    ),
    (
        "linux.group",
        "用户组",
        &[
            ("linux.group", "组名"),
            ("linux.group_gid", "GID"),
            ("linux.group_members", "成员"),
        ],
    ),
    (
        "linux.login",
        "登录信息",
        &[
            ("linux.user", "用户"),
            ("linux.terminal", "终端"),
            ("linux.remote_host", "来源主机"),
            ("linux.logout_time", "登出时间"),
            ("linux.duration_seconds", "在线秒数"),
            ("linux.source", "源文件"),
            ("linux.time", "时间"),
        ],
    ),
    (
        "linux.loginfail",
        "登录失败",
        &[
            ("linux.user", "用户"),
            ("linux.terminal", "终端"),
            ("linux.remote_host", "来源主机"),
            ("linux.logout_time", "登出时间"),
            ("linux.duration_seconds", "在线秒数"),
            ("linux.source", "源文件"),
            ("linux.time", "时间"),
        ],
    ),
    (
        "linux.boot",
        "开机时间",
        &[("linux.event", "事件"), ("linux.time", "时间")],
    ),
    (
        "linux.shutdown",
        "关机时间",
        &[("linux.event", "事件"), ("linux.time", "时间")],
    ),
    (
        "linux.network",
        "网络信息",
        &[
            ("linux.source", "来源"),
            ("linux.iface", "接口"),
            ("linux.connection", "连接"),
            ("linux.type", "类型"),
            ("linux.mac", "MAC"),
            ("linux.ipv4", "IPv4"),
            ("linux.ipv6", "IPv6"),
            ("linux.lease_observed", "租约观测时间（UTC）"),
            ("linux.lease_expiry", "租约过期时间（UTC）"),
            ("linux.lease_seconds", "租期秒数"),
            ("linux.mask", "掩码"),
            ("linux.gateway", "网关"),
            ("linux.dns", "DNS"),
            ("linux.onboot", "开机启用"),
        ],
    ),
    (
        "linux.usb",
        "USB使用记录",
        &[
            ("linux.log", "日志文件"),
            ("linux.detail", "详情"),
            ("linux.time", "时间"),
            ("linux.local_time", "本地时间"),
            ("linux.time_basis", "时间依据"),
        ],
    ),
    (
        "linux.service",
        "服务列表",
        &[
            ("linux.source", "来源"),
            ("linux.description", "描述"),
            ("linux.service_type", "服务类型"),
            ("linux.exec_start", "启动命令"),
            ("linux.restart", "重启策略"),
            ("linux.enabled", "已启用"),
        ],
    ),
    (
        "linux.autostart",
        "开机启动项",
        &[
            ("linux.name", "名称"),
            ("linux.source", "来源"),
            ("linux.runlevels", "运行级别"),
            ("linux.target", "启动目标"),
            ("linux.description", "描述"),
            ("linux.exec_start", "启动命令"),
        ],
    ),
    (
        "linux.software",
        "软件信息",
        &[
            ("linux.software", "包名"),
            ("linux.version", "版本"),
            ("linux.arch", "架构"),
            ("linux.vendor", "厂商"),
            ("linux.summary", "摘要"),
            ("linux.size", "大小"),
            ("linux.install_time", "安装时间"),
            ("linux.status", "状态"),
            ("linux.source", "来源"),
        ],
    ),
    (
        "linux.cron",
        "定时任务",
        &[
            ("linux.user", "用户"),
            ("linux.schedule", "调度"),
            ("linux.command", "命令"),
            ("linux.source", "来源"),
        ],
    ),
    (
        "linux.shellhistory",
        "命令历史",
        &[
            ("linux.user", "用户"),
            ("linux.shell", "Shell"),
            ("linux.command", "命令"),
            ("linux.time", "时间"),
            ("linux.source", "源文件"),
            ("linux.line", "行号"),
        ],
    ),
];

/// Attribute that identifies a record and becomes its title. The column is
/// hidden only when every record's title already shows it, never because
/// values happen to coincide (equal UID/GID, same-named services from
/// different sources).
const PRIMARY_FIELDS: &[(&str, &str)] = &[
    ("linux.user", "linux.username"),
    ("linux.group", "linux.group"),
    ("linux.login", "linux.user"),
    ("linux.loginfail", "linux.user"),
    ("linux.boot", "linux.event"),
    ("linux.shutdown", "linux.event"),
    ("linux.network", "linux.iface"),
    ("linux.usb", "linux.log"),
    ("linux.autostart", "linux.name"),
    ("linux.software", "linux.software"),
    ("linux.cron", "linux.command"),
    ("linux.shellhistory", "linux.command"),
];

fn primary_field(artifact_type: &str) -> Option<&'static str> {
    PRIMARY_FIELDS
        .iter()
        .find_map(|(known, field)| (*known == artifact_type).then_some(*field))
}

/// 0 and false are valid forensic values; only missing values, blank
/// strings and empty collections count as empty.
pub fn has_content(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Nil) => false,
        Some(Value::String(text)) => !strip(&String::from_utf8_lossy(text.as_bytes())).is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Map(entries)) => !entries.is_empty(),
        Some(_) => true,
    }
}

/// Python `str()` of an identity value.
fn display(value: &Value) -> String {
    match value {
        Value::String(text) => String::from_utf8_lossy(text.as_bytes()).into_owned(),
        Value::Boolean(true) => "True".to_owned(),
        Value::Boolean(false) => "False".to_owned(),
        Value::Nil => "None".to_owned(),
        value => value.to_string(),
    }
}

/// Sets each record's title to its identity and derives stable columns from
/// the whole run (not a single page). Records and attributes are kept.
pub fn prepare_result_nodes(artifacts: &mut [Artifact]) -> Vec<ResultNode> {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, artifact) in artifacts.iter_mut().enumerate() {
        groups
            .entry(artifact.artifact_type.clone())
            .or_default()
            .push(index);
        let identity = if artifact.artifact_type == "linux.service" {
            artifact.value.clone()
        } else {
            primary_field(&artifact.artifact_type)
                .and_then(|field| artifact.attributes.get(field).cloned())
        };
        if let Some(identity) = identity.filter(|identity| has_content(Some(identity))) {
            artifact.title = display(&identity);
        }
    }

    let mut nodes = Vec::new();
    for (artifact_type, indices) in groups {
        let Some((_, name, schema)) = RESULT_NODES
            .iter()
            .find(|(known, _, _)| *known == artifact_type)
        else {
            continue;
        };
        let primary = primary_field(&artifact_type);
        let mut columns = Vec::new();
        for (key, label) in schema.iter() {
            let values: Vec<Option<&Value>> = indices
                .iter()
                .map(|index| artifacts[*index].attributes.get(key))
                .collect();
            let shown_in_title = primary == Some(*key)
                && indices.iter().zip(&values).all(|(index, value)| {
                    has_content(*value)
                        && value.is_some_and(|value| display(value) == artifacts[*index].title)
                });
            if shown_in_title {
                continue;
            }
            if values.iter().any(|value| has_content(*value)) {
                columns.push(ResultColumn {
                    key: (*key).to_owned(),
                    label: (*label).to_owned(),
                });
            }
        }
        nodes.push(ResultNode {
            node_type: artifact_type,
            name: (*name).to_owned(),
            columns,
        });
    }
    for node in &mut nodes {
        if artifacts.iter().any(|artifact| {
            artifact.artifact_type == node.node_type
                && artifact.attributes.contains_key("linux.root")
        }) {
            node.columns.push(ResultColumn {
                key: "linux.root".into(),
                label: "来源卷".into(),
            });
        }
    }
    nodes
}

#[cfg(test)]
mod tests {
    use lovelycarve_plugin::Attributes;

    use super::*;

    fn artifact(
        artifact_type: &str,
        title: &str,
        value: Option<&str>,
        attributes: &[(&str, Value)],
    ) -> Artifact {
        Artifact {
            artifact_type: artifact_type.to_owned(),
            title: title.to_owned(),
            value: value.map(Value::from),
            attributes: attributes
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect::<Attributes>(),
        }
    }

    fn column(key: &str, label: &str) -> ResultColumn {
        ResultColumn {
            key: key.to_owned(),
            label: label.to_owned(),
        }
    }

    #[test]
    fn autostart_names_and_sources_preserve_all_evidence() {
        let mut artifacts: Vec<_> = [
            "systemd/multi-user.target.wants",
            "systemd/rescue.target.wants",
        ]
        .iter()
        .map(|source| {
            artifact(
                "linux.autostart",
                "开机启动项",
                Some("ssh.service"),
                &[
                    ("linux.name", Value::from("ssh.service")),
                    ("linux.source", Value::from(*source)),
                ],
            )
        })
        .collect();
        let original = artifacts.clone();
        let nodes = prepare_result_nodes(&mut artifacts);
        assert_eq!(
            nodes,
            vec![ResultNode {
                node_type: "linux.autostart".to_owned(),
                name: "开机启动项".to_owned(),
                columns: vec![column("linux.source", "来源")],
            }]
        );
        let expected: Vec<_> = original
            .into_iter()
            .map(|mut item| {
                item.title = "ssh.service".to_owned();
                item
            })
            .collect();
        assert_eq!(artifacts, expected);
    }

    #[test]
    fn columns_consider_entire_run_and_keep_sysv_runlevels() {
        let mut artifacts: Vec<_> = (0..1001)
            .map(|_| {
                artifact(
                    "linux.autostart",
                    "开机启动项",
                    Some("ssh.service"),
                    &[
                        ("linux.name", Value::from("ssh.service")),
                        (
                            "linux.source",
                            Value::from("systemd/multi-user.target.wants"),
                        ),
                    ],
                )
            })
            .collect();
        artifacts.push(artifact(
            "linux.autostart",
            "开机启动项",
            Some("ssh"),
            &[
                ("linux.name", Value::from("ssh")),
                ("linux.source", Value::from("init.d")),
                ("linux.runlevels", Value::from("2 3 4 5")),
            ],
        ));
        assert_eq!(
            prepare_result_nodes(&mut artifacts)[0].columns,
            vec![
                column("linux.source", "来源"),
                column("linux.runlevels", "运行级别")
            ]
        );
    }

    #[test]
    fn real_zero_false_and_service_identity_are_not_lost() {
        let mut artifacts = vec![
            artifact(
                "linux.user",
                "用户 root",
                Some("root"),
                &[
                    ("linux.username", Value::from("root")),
                    ("linux.uid", Value::from(0_u64)),
                    ("linux.gid", Value::from(0_u64)),
                    ("linux.gecos", Value::from(" ")),
                ],
            ),
            artifact(
                "linux.service",
                "服务 ssh.service",
                Some("ssh.service"),
                &[
                    ("linux.source", Value::from("systemd")),
                    ("linux.enabled", Value::Boolean(false)),
                    ("linux.description", Value::Nil),
                ],
            ),
        ];
        assert_eq!(
            prepare_result_nodes(&mut artifacts),
            vec![
                ResultNode {
                    node_type: "linux.service".to_owned(),
                    name: "服务列表".to_owned(),
                    columns: vec![
                        column("linux.source", "来源"),
                        column("linux.enabled", "已启用")
                    ],
                },
                ResultNode {
                    node_type: "linux.user".to_owned(),
                    name: "用户列表".to_owned(),
                    columns: vec![column("linux.uid", "UID"), column("linux.gid", "GID")],
                },
            ]
        );
        assert_eq!(
            artifacts
                .iter()
                .map(|item| item.title.as_str())
                .collect::<Vec<_>>(),
            vec!["root", "ssh.service"]
        );
    }

    #[test]
    fn missing_identity_preserves_title_and_unknown_artifacts() {
        let mut artifacts = vec![
            artifact(
                "linux.network",
                "网络配置(OpenWrt)",
                None,
                &[("linux.source", Value::from("OpenWrt"))],
            ),
            artifact("custom", "Original", Some("untouched"), &[]),
        ];
        let original = artifacts.clone();
        assert_eq!(
            prepare_result_nodes(&mut artifacts),
            vec![ResultNode {
                node_type: "linux.network".to_owned(),
                name: "网络信息".to_owned(),
                columns: vec![column("linux.source", "来源")],
            }]
        );
        assert_eq!(artifacts, original);
    }
}
