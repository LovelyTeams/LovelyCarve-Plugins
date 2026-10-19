//! The typed records of every Linux result type: field kinds, labels,
//! timeline roles, and how each field is read from a collector artifact.
//! Attributes no field takes are kept in the hidden `extra` field, so a
//! record never loses what the collector read.

use lovelycarve_plugin::{
    schema::{FieldKind, FieldSchema, PropertyLayout, RecordSchema},
    Attributes, Error, Plugin, Result, Run, SourceRef, Timestamp, Value, View,
};

use crate::item::Artifact;

/// utmp / wtmp / btmp record size (the `linux.offset` attribute counts in
/// these records).
const UTMP_RECORD_SIZE: u64 = 384;

#[derive(Clone, Copy)]
struct Field {
    id: &'static str,
    label: &'static str,
    kind: FieldKind,
    /// Attribute keys tried in order; `@value` is the artifact's identity
    /// value and `@title` its title.
    from: &'static [&'static str],
    key: bool,
    hidden: bool,
    timeline: Option<&'static str>,
}

const fn field(
    id: &'static str,
    label: &'static str,
    kind: FieldKind,
    from: &'static [&'static str],
) -> Field {
    Field {
        id,
        label,
        kind,
        from,
        key: false,
        hidden: false,
        timeline: None,
    }
}

impl Field {
    const fn key(self) -> Self {
        Self { key: true, ..self }
    }

    const fn hidden(self) -> Self {
        Self {
            hidden: true,
            ..self
        }
    }

    const fn timeline(self, role: &'static str) -> Self {
        Self {
            timeline: Some(role),
            ..self
        }
    }
}

struct RecordType {
    id: &'static str,
    label: &'static str,
    title: &'static str,
    fields: &'static [Field],
}

use FieldKind::{Duration, Hash, Int, Ip, Path, Size, Text, Timestamp as Time};

const LOGIN_FIELDS: &[Field] = &[
    field("user", "用户", Text, &["linux.user", "@value"]).key(),
    field("terminal", "终端", Text, &["linux.terminal"]),
    field("remote_host", "来源主机", Text, &["linux.remote_host"]),
    field("time", "登录时间", Time, &["linux.time"]).timeline("login"),
    field("logout_time", "登出时间", Time, &["linux.logout_time"]).timeline("logout"),
    field(
        "duration",
        "在线时长",
        Duration,
        &["linux.duration_seconds"],
    ),
    field("record", "记录序号", Int, &["linux.record"]).hidden(),
];

const LOGIN_FAILURE_FIELDS: &[Field] = &[
    field("user", "用户", Text, &["linux.user", "@value"]).key(),
    field("terminal", "终端", Text, &["linux.terminal"]),
    field("remote_host", "来源主机", Text, &["linux.remote_host"]),
    field("time", "尝试时间", Time, &["linux.time"]).timeline("login_failed"),
    field("record", "记录序号", Int, &["linux.record"]).hidden(),
];

const TYPES: &[RecordType] = &[
    RecordType {
        id: "linux.systeminfo",
        label: "系统信息",
        title: "{name}",
        fields: &[
            field("name", "名称", Text, &["@title"]).key(),
            field("key", "英文名称", Text, &["linux.key"]),
            field("value", "值", Text, &["linux.field_value", "@value"]),
        ],
    },
    RecordType {
        id: "linux.timezone",
        label: "时区信息",
        title: "{timezone}",
        fields: &[field("timezone", "时区", Text, &["linux.timezone", "@value"]).key()],
    },
    RecordType {
        id: "linux.host",
        label: "Hosts",
        title: "{hostname}",
        fields: &[
            field("hostname", "主机名", Text, &["linux.hostname", "@title"]).key(),
            field("address", "IP", Ip, &["linux.address", "@value"]),
            field("aliases", "别名", Text, &["linux.aliases"]),
            field("line", "行号", Int, &["linux.line"]),
        ],
    },
    RecordType {
        id: "linux.user",
        label: "用户列表",
        title: "{username}",
        fields: &[
            field("username", "用户名", Text, &["linux.username", "@value"]).key(),
            field("uid", "UID", Int, &["linux.uid"]),
            field("user_class", "用户类型", Text, &["linux.user_class"]),
            field("gid", "GID", Int, &["linux.gid"]),
            field("gecos", "描述", Text, &["linux.gecos"]),
            field("home", "主目录", Path, &["linux.home"]),
            field("shell", "Shell", Path, &["linux.shell"]),
            field(
                "password_status",
                "口令状态",
                Text,
                &["linux.password_status"],
            ),
            field("password_algo", "口令算法", Text, &["linux.password_algo"]),
            field(
                "password_last_change",
                "口令最后修改",
                Time,
                &["linux.password_last_change"],
            )
            .timeline("password_changed"),
            field(
                "password_min_days",
                "最短使用天数",
                Int,
                &["linux.password_min_days"],
            ),
            field(
                "password_max_days",
                "最长使用天数",
                Int,
                &["linux.password_max_days"],
            ),
            field(
                "password_warn_days",
                "到期提醒天数",
                Int,
                &["linux.password_warn_days"],
            ),
            field("password_hash", "口令哈希", Hash, &["linux.password_hash"]).hidden(),
        ],
    },
    RecordType {
        id: "linux.group",
        label: "用户组",
        title: "{group}",
        fields: &[
            field("group", "组名", Text, &["linux.group", "@value"]).key(),
            field("gid", "GID", Int, &["linux.group_gid"]),
            field("members", "成员", Text, &["linux.group_members"]),
        ],
    },
    RecordType {
        id: "linux.login",
        label: "登录信息",
        title: "{user} @ {terminal}",
        fields: LOGIN_FIELDS,
    },
    RecordType {
        id: "linux.loginfail",
        label: "登录失败",
        title: "{user} @ {terminal}",
        fields: LOGIN_FAILURE_FIELDS,
    },
    RecordType {
        id: "linux.boot",
        label: "开机时间",
        title: "{event}",
        fields: &[
            field("event", "事件", Text, &["linux.event", "@value"]).key(),
            field("time", "时间", Time, &["linux.time"]).timeline("boot"),
            field("record", "记录序号", Int, &["linux.record"]).hidden(),
        ],
    },
    RecordType {
        id: "linux.shutdown",
        label: "关机时间",
        title: "{event}",
        fields: &[
            field("event", "事件", Text, &["linux.event", "@value"]).key(),
            field("time", "时间", Time, &["linux.time"]).timeline("shutdown"),
            field("record", "记录序号", Int, &["linux.record"]).hidden(),
        ],
    },
    RecordType {
        id: "linux.network",
        label: "网络信息",
        title: "{iface}",
        fields: &[
            field("iface", "接口", Text, &["linux.iface", "@value"]).key(),
            field(
                "origin",
                "来源",
                Text,
                &["linux.source_kind", "linux.source"],
            ),
            field("connection", "连接", Text, &["linux.connection"]),
            field("type", "类型", Text, &["linux.type"]),
            field("mac", "MAC", Text, &["linux.mac"]),
            field("method", "IPv4 方式", Text, &["linux.method"]),
            field("proto", "协议", Text, &["linux.proto"]),
            field("bootproto", "启动协议", Text, &["linux.bootproto"]),
            field("autoconnect", "自动连接", Text, &["linux.autoconnect"]),
            field("onboot", "开机启用", Text, &["linux.onboot"]),
            field("ipv4", "IPv4", Ip, &["linux.ipv4"]),
            field("mask", "掩码", Text, &["linux.mask"]),
            field("gateway", "网关", Ip, &["linux.gateway"]),
            field("dns", "DNS", Text, &["linux.dns"]),
            field("ipv6", "IPv6", Ip, &["linux.ipv6"]),
            field("domain", "域名", Text, &["linux.domain"]),
            field("dhcp_server", "DHCP 服务器", Ip, &["linux.dhcp_server"]),
            field(
                "lease_observed",
                "租约观测时间",
                Time,
                &["linux.lease_observed"],
            )
            .timeline("lease_observed"),
            field(
                "lease_expiry",
                "租约过期时间",
                Time,
                &["linux.lease_expiry"],
            ),
            field("lease_seconds", "租期", Duration, &["linux.lease_seconds"]),
            field(
                "local_time_raw",
                "日志本地时间",
                Text,
                &["linux.local_time_raw"],
            ),
        ],
    },
    RecordType {
        id: "linux.usb",
        label: "USB使用记录",
        title: "{detail}",
        fields: &[
            field("log", "日志文件", Text, &["linux.log", "@value"]).key(),
            field("detail", "详情", Text, &["linux.detail"]),
            field("time", "时间", Time, &["linux.time"]),
            field("local_time", "本地时间", Time, &["linux.local_time"]),
            field("time_basis", "时间依据", Text, &["linux.time_basis"]),
            field("event_time", "时间线时间", Time, &["linux.timeline_time"])
                .hidden()
                .timeline("usb"),
        ],
    },
    RecordType {
        id: "linux.service",
        label: "服务列表",
        title: "{name}",
        fields: &[
            field("name", "服务名", Text, &["@value"]).key(),
            field("unit", "单元文件", Path, &["linux.source"]),
            field("description", "描述", Text, &["linux.description"]),
            field("service_type", "服务类型", Text, &["linux.service_type"]),
            field("exec_start", "启动命令", Text, &["linux.exec_start"]),
            field("restart", "重启策略", Text, &["linux.restart"]),
            field("enabled", "已启用", Text, &["linux.enabled"]),
            field("user", "运行用户", Text, &["linux.service_user"]),
            field("wanted_by", "所属目标", Text, &["linux.install_wantedby"]),
        ],
    },
    RecordType {
        id: "linux.autostart",
        label: "开机启动项",
        title: "{name}",
        fields: &[
            field("name", "名称", Text, &["linux.name", "@value"]).key(),
            field("origin", "来源", Text, &["linux.source"]),
            field("runlevels", "运行级别", Text, &["linux.runlevels"]),
            field("target", "启动目标", Text, &["linux.target"]),
            field("description", "描述", Text, &["linux.description"]),
            field("exec_start", "启动命令", Text, &["linux.exec_start"]),
        ],
    },
    RecordType {
        id: "linux.software",
        label: "软件信息",
        title: "{name}",
        fields: &[
            field("name", "包名", Text, &["linux.software", "@value"]).key(),
            field("version", "版本", Text, &["linux.version"]),
            field("release", "发行号", Text, &["linux.release"]),
            field("arch", "架构", Text, &["linux.arch"]),
            field("vendor", "厂商", Text, &["linux.vendor"]),
            field("summary", "摘要", Text, &["linux.summary"]),
            field("size", "大小", Size, &["linux.size"]),
            field("install_time", "安装时间", Time, &["linux.install_time"]).timeline("installed"),
            field("status", "状态", Text, &["linux.status"]),
            field("manager", "包管理器", Text, &["linux.source"]),
        ],
    },
    RecordType {
        id: "linux.cron",
        label: "定时任务",
        title: "{command}",
        fields: &[
            field("user", "用户", Text, &["linux.user"]),
            field("schedule", "调度", Text, &["linux.schedule"]),
            field("command", "命令", Text, &["linux.command", "@value"]).key(),
        ],
    },
    RecordType {
        id: "linux.shellhistory",
        label: "命令历史",
        title: "{command}",
        fields: &[
            field("user", "用户", Text, &["linux.user"]),
            field("shell", "Shell", Text, &["linux.shell"]),
            field("command", "命令", Text, &["linux.command", "@value"]).key(),
            field("time", "时间", Time, &["linux.time"]).timeline("command"),
            field("line", "行号", Int, &["linux.line"]),
        ],
    },
    RecordType {
        id: "linux.recent",
        label: "应用程序最近访问",
        title: "{application}",
        fields: &[
            field("user", "用户", Text, &["linux.user"]),
            field("application", "应用", Text, &["recent.application_name"]).key(),
            field("href", "文件 URI", Text, &["recent.href", "@value"]),
            field("mime", "文件类型", Text, &["recent.mime"]),
            field("modified", "文件记录修改时间", Time, &["recent.modified"]),
            field(
                "application_modified",
                "应用访问时间",
                Time,
                &["recent.application_modified"],
            )
            .timeline("recent_access"),
            field(
                "application_count",
                "访问次数",
                Int,
                &["recent.application_count"],
            ),
            field(
                "application_exec",
                "应用命令",
                Text,
                &["recent.application_exec"],
            ),
            field("added", "加入时间", Time, &["recent.added"]),
            field("visited", "访问时间（原值）", Text, &["recent.visited"]),
        ],
    },
];

/// Attributes that carry provenance rather than record content.
const SOURCE_ATTRIBUTES: &[&str] = &[
    "source.path",
    "source.paths",
    "source.line",
    "source.line_end",
    "linux.offset",
    "linux.root",
];

impl RecordType {
    fn schema(&self) -> RecordSchema {
        let schema = self.fields.iter().fold(
            RecordSchema::new(self.id, self.label).title(self.title),
            |schema, field| {
                let mut built = FieldSchema::new(field.id, field.label, field.kind);
                if field.key {
                    built = built.key();
                }
                if field.hidden {
                    built = built.hidden();
                }
                if let Some(role) = field.timeline {
                    built = built.timeline(role);
                }
                schema.field(built)
            },
        );
        let schema = schema.field(FieldSchema::new("extra", "其他属性", FieldKind::Json).hidden());
        match self.id {
            "linux.systeminfo" => {
                schema.properties(PropertyLayout::new("value").label("name").secondary("key"))
            }
            "linux.timezone" => schema.properties(PropertyLayout::new("timezone")),
            _ => schema,
        }
    }

    /// Positional values: each field from its first non-empty attribute,
    /// coerced to the field's kind; everything else into `extra`.
    fn values(&self, artifact: &Artifact) -> Vec<Value> {
        let mut extra = artifact.attributes.clone();
        let mut values = Vec::with_capacity(self.fields.len() + 1);
        for field in self.fields {
            let raw = field.from.iter().find_map(|key| {
                let value = match *key {
                    "@value" => artifact.value.clone(),
                    "@title" => Some(Value::from(artifact.title.as_str())),
                    key => artifact.attributes.get(key).cloned(),
                };
                value.filter(has_content)
            });
            let value = raw
                .as_ref()
                .map_or(Value::Nil, |raw| coerce(field.kind, raw));
            for key in field.from {
                // A value that did not fit its kind stays in `extra`.
                if !value.is_nil() || raw.is_none() {
                    extra.remove(key);
                }
            }
            values.push(value);
        }
        for key in SOURCE_ATTRIBUTES {
            extra.remove(key);
        }
        if artifact
            .attributes
            .get("linux.source")
            .and_then(Value::as_str)
            .is_some_and(|source| source.contains('/'))
        {
            extra.remove("linux.source");
        }
        extra.retain(|_, value| has_content(value));
        values.push(if extra.is_empty() {
            Value::Nil
        } else {
            extra.to_value()
        });
        values
    }
}

/// Registers every Linux record type.
pub fn register(plugin: Plugin) -> Plugin {
    TYPES.iter().fold(plugin, |plugin, record_type| {
        plugin.schema(record_type.schema())
    })
}

/// Emits one collector artifact as its typed record.
pub fn emit(run: &Run, view: &View, artifact: &Artifact) -> Result<()> {
    let record_type = TYPES
        .iter()
        .find(|record_type| record_type.id == artifact.artifact_type)
        .ok_or_else(|| {
            Error::new(
                "UNKNOWN_RECORD_TYPE",
                format!("{} has no record schema", artifact.artifact_type),
            )
        })?;
    sources(view, &artifact.attributes)
        .into_iter()
        .fold(
            run.record_values(record_type.id, record_type.values(artifact)),
            |emit, source| emit.source(source),
        )
        .emit()
}

/// The evidence files a record came from: `source.path` (+ `source.paths`),
/// else every path-like part of `linux.source`. The first source keeps the
/// utmp record range or the line the record was read from.
fn sources(view: &View, attributes: &Attributes) -> Vec<SourceRef> {
    let text = |key: &str| {
        attributes
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let mut paths: Vec<String> = Vec::new();
    if let Some(path) = text("source.path") {
        paths.push(path);
    }
    if let Some(Value::Array(items)) = attributes.get("source.paths") {
        paths.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    if paths.is_empty() {
        paths.extend(
            text("linux.source")
                .unwrap_or_default()
                .split(';')
                .filter(|part| part.contains('/') && !part.starts_with("systemd/"))
                .map(str::to_owned),
        );
    }
    let mut seen = std::collections::HashSet::new();
    paths.retain(|path| seen.insert(path.clone()));
    let line = attributes
        .get("source.line")
        .or_else(|| attributes.get("linux.line"))
        .and_then(Value::as_u64);
    let line_end = attributes.get("source.line_end").and_then(Value::as_u64);
    let offset = attributes.get("linux.offset").and_then(Value::as_u64);
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let mut source = view.source(path);
            if index == 0 {
                if let Some(offset) = offset {
                    source = source.at(offset, UTMP_RECORD_SIZE);
                }
                match (line, line_end) {
                    (Some(start), Some(end)) if end > start => {
                        source = source.note(format!("第 {start}–{end} 行"));
                    }
                    (Some(start), _) => source = source.note(format!("第 {start} 行")),
                    (None, _) => {}
                }
            }
            source
        })
        .collect()
}

/// 0 and false are values; missing, blank and empty values are not.
fn has_content(value: &Value) -> bool {
    match value {
        Value::Nil => false,
        Value::String(text) => !text.as_str().unwrap_or_default().trim().is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Map(entries) => !entries.is_empty(),
        _ => true,
    }
}

/// A raw attribute as a value of `kind`; `nil` when it does not fit.
fn coerce(kind: FieldKind, raw: &Value) -> Value {
    let text = || match raw {
        Value::String(text) => text.as_str().map(|text| text.trim().to_owned()),
        Value::Integer(number) => Some(number.to_string()),
        Value::F64(number) => Some(number.to_string()),
        Value::F32(number) => Some(number.to_string()),
        Value::Boolean(flag) => Some(flag.to_string()),
        _ => None,
    };
    match kind {
        FieldKind::Text | FieldKind::Path | FieldKind::Hash | FieldKind::Ip | FieldKind::Enum => {
            match raw {
                Value::String(_) => raw.clone(),
                Value::Array(_) | Value::Map(_) => {
                    Value::from(lovelycarve_plugin::schema::display_value(raw))
                }
                _ => text().map(Value::from).unwrap_or(Value::Nil),
            }
        }
        FieldKind::Int => match raw {
            Value::Integer(_) => raw.clone(),
            _ => text()
                .and_then(|text| {
                    text.parse::<i64>()
                        .map(Value::from)
                        .or_else(|_| text.parse::<u64>().map(Value::from))
                        .ok()
                })
                .unwrap_or(Value::Nil),
        },
        FieldKind::Size => match raw {
            Value::Integer(number) if number.as_u64().is_some() => raw.clone(),
            _ => text()
                .and_then(|text| text.parse::<u64>().ok())
                .map(Value::from)
                .unwrap_or(Value::Nil),
        },
        FieldKind::Float | FieldKind::Duration => {
            let number = match raw {
                Value::Integer(number) => number.as_f64(),
                Value::F64(number) => Some(*number),
                Value::F32(number) => Some(f64::from(*number)),
                _ => text().and_then(|text| text.parse::<f64>().ok()),
            };
            number
                .filter(|number| number.is_finite() && (kind == FieldKind::Float || *number >= 0.0))
                .map(Value::F64)
                .unwrap_or(Value::Nil)
        }
        FieldKind::Bool => match raw {
            Value::Boolean(_) => raw.clone(),
            _ => match text().as_deref() {
                Some("true" | "yes" | "是") => Value::Boolean(true),
                Some("false" | "no" | "否") => Value::Boolean(false),
                _ => Value::Nil,
            },
        },
        FieldKind::Timestamp => text()
            .and_then(|text| Timestamp::parse(&text))
            .map(|time| Value::from(time.as_str()))
            .unwrap_or(Value::Nil),
        FieldKind::List => match raw {
            Value::Array(items) if items.iter().all(Value::is_str) => raw.clone(),
            _ => Value::Nil,
        },
        FieldKind::Json => raw.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(artifact_type: &str, attributes: &[(&str, Value)]) -> Artifact {
        Artifact {
            artifact_type: artifact_type.to_owned(),
            title: "标题".to_owned(),
            value: None,
            attributes: attributes
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
        }
    }

    #[test]
    fn every_record_type_has_a_valid_schema() {
        for record_type in TYPES {
            record_type
                .schema()
                .validate()
                .unwrap_or_else(|error| panic!("{}: {error}", record_type.id));
        }
        let properties: Vec<_> = TYPES
            .iter()
            .filter(|record| record.schema().properties.is_some())
            .map(|record| record.id)
            .collect();
        assert_eq!(properties, ["linux.systeminfo", "linux.timezone"]);
    }

    #[test]
    fn values_are_typed_and_leftovers_kept() {
        let user = TYPES
            .iter()
            .find(|record_type| record_type.id == "linux.user")
            .unwrap();
        let values = user.values(&artifact(
            "linux.user",
            &[
                ("linux.username", Value::from("root")),
                ("linux.uid", Value::from("0")),
                ("linux.gid", Value::from("x1")),
                (
                    "linux.password_last_change",
                    Value::from("2024-05-12T00:00:00+00:00"),
                ),
                ("linux.source", Value::from("etc/passwd;etc/shadow")),
                ("linux.custom", Value::from("kept")),
            ],
        ));
        let schema = user.schema();
        schema.validate_values(&values).expect("valid values");
        let value = |id: &str| &values[schema.field_index(id).unwrap()];
        assert_eq!(value("uid"), &Value::from(0));
        assert_eq!(value("gid"), &Value::Nil);
        assert_eq!(
            value("password_last_change"),
            &Value::from("2024-05-12T00:00:00+00:00")
        );
        let extra = value("extra");
        assert!(extra.to_string().contains("linux.custom"), "{extra}");
        assert!(
            extra.to_string().contains("x1"),
            "a gid that is not a number stays: {extra}"
        );
        assert!(
            !extra.to_string().contains("etc/passwd"),
            "sources are not extra: {extra}"
        );
        assert_eq!(schema.render_title(&values), "root");
    }
}
