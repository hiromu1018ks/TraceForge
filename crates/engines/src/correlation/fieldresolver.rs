//! Event field path resolver（Correlation predicate 共用）。
//!
//! Schema §7 の predicate `field` は `^[a-z][a-z0-9_.]*$` 形式の dot path をとる。
//! 本 module は dot path を [`tf_core::Event`] 上の値（[`serde_json::Value`]）へ解決する。
//!
//! 対応 path 一覧:
//! - `hostname` / `user` / `program` / `message`（Event 直接 field）
//! - `event_type` / `assertion`（Event の分類）
//! - `path.original` / `path.comparison_key` / `path.normalization_profile`
//! - `process.pid` / `process.ppid` / `process.command_line`
//! - `process.image_path.original` / `process.image_path.comparison_key`
//! - `attributes.<key>`（Event の attributes BTreeMap）
//!
//! 不明な path は `attributes.<path>` へ fallback し、それでも見つからない場合は `None`。

use serde_json::Value;

use tf_core::event::Event;

/// field path を Event 上の値へ解決する。
///
/// 戻り値:
/// - `Some(Value::Null)`: field は存在するが値が明示的に null。
/// - `Some(non-null Value)`: field が存在し、値がある。
/// - `None`: field が存在しない（predicate の `exists` 演算は false 扱い）。
pub fn resolve_field_path(path: &str, event: &Event) -> Option<Value> {
    // 1. 直接 field
    match path {
        "hostname" => return event.hostname.clone().map(Value::String),
        "user" => return event.user.clone().map(Value::String),
        "program" => return event.program.clone().map(Value::String),
        "message" => return Some(Value::String(event.message.clone())),
        "event_type" => return Some(Value::String(event.event_type.as_str().to_string())),
        "assertion" => return Some(Value::String(event.assertion.as_str().to_string())),
        _ => {}
    }

    // 2. path.* 系
    if let Some(rest) = path.strip_prefix("path.") {
        return event.path.as_ref().and_then(|p| match rest {
            "original" => Some(Value::String(p.original.clone())),
            "comparison_key" => p.comparison_key.clone().map(Value::String),
            "normalization_profile" => Some(Value::String(p.normalization_profile.clone())),
            _ => None,
        });
    }

    // 3. process.* 系
    if let Some(rest) = path.strip_prefix("process.") {
        return event.process.as_ref().and_then(|p| match rest {
            "pid" => p.pid.map(Value::from),
            "ppid" => p.ppid.map(Value::from),
            "command_line" => p.command_line.clone().map(Value::String),
            other if other.starts_with("image_path.") => {
                let sub = &other["image_path.".len()..];
                p.image_path.as_ref().and_then(|ip| match sub {
                    "original" => Some(Value::String(ip.original.clone())),
                    "comparison_key" => ip.comparison_key.clone().map(Value::String),
                    "normalization_profile" => {
                        Some(Value::String(ip.normalization_profile.clone()))
                    }
                    _ => None,
                })
            }
            _ => None,
        });
    }

    // 4. attributes.<key>（明示的）
    if let Some(rest) = path.strip_prefix("attributes.") {
        return event.attributes.get(rest).cloned();
    }

    // 5. fallback: そのまま attribute key として探す。
    event.attributes.get(path).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tf_core::event::{
        ArtifactSource, AssertionKind, EventType, ProcessRef, Provenance, RecordLocator,
    };
    use tf_core::path::WindowsPathValue;
    use tf_core::time::{EventTime, TimestampKind};

    fn sample_event() -> Event {
        let mut attrs = BTreeMap::new();
        attrs.insert("evtx.event_id".into(), Value::from(4624i64));
        attrs.insert("attributes.k".into(), Value::String("v".into()));
        Event {
            id: "tf-event-v1:t".into(),
            time: EventTime::unknown(TimestampKind::EventLogged),
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: Some("HOST".into()),
            user: Some("alice".into()),
            path: Some(WindowsPathValue::new("C:\\Users\\alice\\file.exe")),
            program: Some("cmd.exe".into()),
            process: Some(ProcessRef {
                pid: Some(1234),
                ppid: Some(500),
                process_guid: None,
                parent_process_guid: None,
                image_path: Some(WindowsPathValue::new("C:\\Windows\\cmd.exe")),
                command_line: Some("cmd /c dir".into()),
            }),
            message: "hello".into(),
            attributes: attrs,
            provenance: Provenance {
                evidence_id: "tf-evidence-v1:t".into(),
                artifact_id: "tf-artifact-v1:t".into(),
                source_locator: "Security.evtx".into(),
                source_sha256: "a".repeat(64),
                parser_id: "traceforge-evtx".into(),
                parser_version: "1.0.0".into(),
                record_locator: RecordLocator::SourceOrdinal,
                source_ordinal: 0,
            },
        }
    }

    #[test]
    fn resolve_direct_fields() {
        let e = sample_event();
        assert_eq!(
            resolve_field_path("hostname", &e),
            Some(Value::String("HOST".into()))
        );
        assert_eq!(
            resolve_field_path("user", &e),
            Some(Value::String("alice".into()))
        );
        assert_eq!(
            resolve_field_path("program", &e),
            Some(Value::String("cmd.exe".into()))
        );
        assert_eq!(
            resolve_field_path("message", &e),
            Some(Value::String("hello".into()))
        );
        assert_eq!(
            resolve_field_path("event_type", &e),
            Some(Value::String("event_logged".into()))
        );
    }

    #[test]
    fn resolve_path_subfields() {
        let e = sample_event();
        assert_eq!(
            resolve_field_path("path.original", &e),
            Some(Value::String("C:\\Users\\alice\\file.exe".into()))
        );
        assert_eq!(
            resolve_field_path("path.comparison_key", &e),
            Some(Value::String("c:\\users\\alice\\file.exe".into()))
        );
        assert_eq!(
            resolve_field_path("path.normalization_profile", &e),
            Some(Value::String("windows-path-v1".into()))
        );
    }

    #[test]
    fn resolve_process_subfields() {
        let e = sample_event();
        assert_eq!(
            resolve_field_path("process.pid", &e),
            Some(Value::from(1234u64))
        );
        assert_eq!(
            resolve_field_path("process.command_line", &e),
            Some(Value::String("cmd /c dir".into()))
        );
        assert_eq!(
            resolve_field_path("process.image_path.original", &e),
            Some(Value::String("C:\\Windows\\cmd.exe".into()))
        );
    }

    #[test]
    fn resolve_attributes_explicit() {
        let e = sample_event();
        assert_eq!(
            resolve_field_path("attributes.evtx.event_id", &e),
            Some(Value::from(4624i64))
        );
        // 明示的 prefix なしの attribute key も fallback で見つかる。
        assert_eq!(
            resolve_field_path("evtx.event_id", &e),
            Some(Value::from(4624i64))
        );
    }

    #[test]
    fn resolve_missing_returns_none() {
        let e = sample_event();
        assert_eq!(resolve_field_path("attributes.nonexistent", &e), None);
        assert_eq!(resolve_field_path("totally_unknown_path", &e), None);
    }

    #[test]
    fn resolve_returns_none_when_optional_field_absent() {
        let mut e = sample_event();
        e.hostname = None;
        e.user = None;
        e.path = None;
        e.process = None;
        assert_eq!(resolve_field_path("hostname", &e), None);
        assert_eq!(resolve_field_path("user", &e), None);
        assert_eq!(resolve_field_path("path.original", &e), None);
        assert_eq!(resolve_field_path("process.pid", &e), None);
    }
}
