//! Event と Provenance、関連する参照型（規範 §7、Schema §5.5）。
//!
//! ここで定義する型は Evidence 内に記録された事象を表現し、次の規範を守る:
//!
//! - `attributes` は `BTreeMap` 固定（規範 §13.2、決定性のための hash map 禁止）。
//! - Event type は観測した事実のみを反映し、観測していない行為を断定しない
//!   （規範 §7.1: 例えば `registry_observation` を使う）。
//! - `RecordLocator` は5種のいずれかを必ず持つ（規範 §7.3）。

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::path::WindowsPathValue;
use crate::time::EventTime;

/// Artifact 由来の種別（Schema §3.4）。小文字は [`ArtifactSource::as_str`] を参照。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactSource {
    Prefetch,
    Evtx,
    UsnJournal,
    Lnk,
    JumpList,
    Amcache,
    Registry,
    File,
    Unknown,
}

impl ArtifactSource {
    /// Schema §3.4 の lowercase 文字列。
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactSource::Prefetch => "prefetch",
            ArtifactSource::Evtx => "evtx",
            ArtifactSource::UsnJournal => "usn_journal",
            ArtifactSource::Lnk => "lnk",
            ArtifactSource::JumpList => "jump_list",
            ArtifactSource::Amcache => "amcache",
            ArtifactSource::Registry => "registry",
            ArtifactSource::File => "file",
            ArtifactSource::Unknown => "unknown",
        }
    }

    /// Schema §3.4 の lowercase 文字列から復元する。未知値は `None`。
    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "prefetch" => ArtifactSource::Prefetch,
            "evtx" => ArtifactSource::Evtx,
            "usn_journal" => ArtifactSource::UsnJournal,
            "lnk" => ArtifactSource::Lnk,
            "jump_list" => ArtifactSource::JumpList,
            "amcache" => ArtifactSource::Amcache,
            "registry" => ArtifactSource::Registry,
            "file" => ArtifactSource::File,
            "unknown" => ArtifactSource::Unknown,
            _ => return None,
        })
    }
}

/// Event の「観測か推論か」（規範 §7.1）。
///
/// Parser は原則 [`AssertionKind::Observed`] のみ生成する。`Inferred` は Correlation・
/// Sigma adapter・明示された inference component のみが生成できる。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionKind {
    Observed,
    Inferred,
}

impl AssertionKind {
    /// Schema §5.5 の lowercase 文字列（`observed` / `inferred`）。
    pub fn as_str(&self) -> &'static str {
        match self {
            AssertionKind::Observed => "observed",
            AssertionKind::Inferred => "inferred",
        }
    }

    /// lowercase 文字列から復元する。
    pub fn from_schema_str(s: &str) -> Option<Self> {
        match s {
            "observed" => Some(AssertionKind::Observed),
            "inferred" => Some(AssertionKind::Inferred),
            _ => None,
        }
    }
}

/// Event type 名（Schema §5.5）。
///
/// Schema は具体的な値を規定しないが、規範 §7.1 は「観測した事実のみを反映」することを
/// 求める。例えば Registry snapshot からは `registry_set` ではなく `registry_observation`
/// 等の観測型を使う（AGENTS.md 禁止事項）。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventType(pub String);

impl EventType {
    pub fn new(s: impl Into<String>) -> Self {
        EventType(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Process 参照（規範 §7.2、Schema §5.5）。
///
/// 親子関係の断定は GUID、PID+context、または Evidence が明示する parent field を使う。
/// process 名だけで親子関係を断定してはならない（規範 §7.2）。
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessRef {
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
    pub process_guid: Option<String>,
    pub parent_process_guid: Option<String>,
    pub image_path: Option<WindowsPathValue>,
    pub command_line: Option<String>,
}

impl ProcessRef {
    /// Schema §5.5 の Process 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("pid".into(), opt_u64(self.pid));
        map.insert("ppid".into(), opt_u64(self.ppid));
        map.insert(
            "process_guid".into(),
            self.process_guid
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "parent_process_guid".into(),
            self.parent_process_guid
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "image_path".into(),
            self.image_path
                .as_ref()
                .map(|p| p.to_canonical_value())
                .unwrap_or(Value::Null),
        );
        map.insert(
            "command_line".into(),
            self.command_line
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        Value::Object(map)
    }
}

/// Record の位置情報（規範 §7.3）。
///
/// Parser がより強い locator を取得できない場合だけ `SourceOrdinal` を使う。
#[derive(Clone, Debug, PartialEq)]
pub enum RecordLocator {
    /// 記録 ID（例: EVTX record ID、USN record ID）。
    RecordId(String),
    /// 先頭からの byte offset。
    ByteOffset(u64),
    /// byte 範囲 `[start, end]`。
    ByteRange { start: u64, end: u64 },
    /// 論理 path（hive の key path 等）。空要素は許可しない。
    LogicalPath(Vec<String>),
    /// Source ordinal のみ分かる（最弱の locator）。
    SourceOrdinal,
}

impl RecordLocator {
    /// Schema §5.5 / §5.6 の `type` 列挙値（lowercase）。
    pub fn type_str(&self) -> &'static str {
        match self {
            RecordLocator::RecordId(_) => "record_id",
            RecordLocator::ByteOffset(_) => "byte_offset",
            RecordLocator::ByteRange { .. } => "byte_range",
            RecordLocator::LogicalPath(_) => "logical_path",
            RecordLocator::SourceOrdinal => "source_ordinal",
        }
    }

    /// Schema §5.5 の `record_locator` 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        match self {
            RecordLocator::RecordId(id) => serde_json::json!({
                "type": "record_id",
                "value": id,
            }),
            RecordLocator::ByteOffset(off) => serde_json::json!({
                "type": "byte_offset",
                "value": off,
            }),
            RecordLocator::ByteRange { start, end } => serde_json::json!({
                "type": "byte_range",
                "start": start,
                "end": end,
            }),
            RecordLocator::LogicalPath(parts) => serde_json::json!({
                "type": "logical_path",
                "value": parts,
            }),
            RecordLocator::SourceOrdinal => serde_json::json!({
                "type": "source_ordinal",
            }),
        }
    }

    /// [`to_canonical_value`] の canonical JSON 文字列。Event ID の hash field #7（規範 §12.3）。
    ///
    /// [`to_canonical_value`]: RecordLocator::to_canonical_value
    pub fn to_canonical_json(&self) -> String {
        crate::canonical::to_canonical_string_or_panic(&self.to_canonical_value())
    }
}

/// Event の出所（規範 §7.3、Schema §5.5）。
#[derive(Clone, Debug, PartialEq)]
pub struct Provenance {
    pub evidence_id: String,
    pub artifact_id: String,
    pub source_locator: String,
    pub source_sha256: String,
    pub parser_id: String,
    pub parser_version: String,
    pub record_locator: RecordLocator,
    pub source_ordinal: u64,
}

impl Provenance {
    /// Schema §5.5 の `provenance` 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "evidence_id".into(),
            Value::String(self.evidence_id.clone()),
        );
        map.insert(
            "artifact_id".into(),
            Value::String(self.artifact_id.clone()),
        );
        map.insert(
            "source_locator".into(),
            Value::String(self.source_locator.clone()),
        );
        map.insert(
            "source_sha256".into(),
            Value::String(self.source_sha256.clone()),
        );
        map.insert("parser_id".into(), Value::String(self.parser_id.clone()));
        map.insert(
            "parser_version".into(),
            Value::String(self.parser_version.clone()),
        );
        map.insert(
            "record_locator".into(),
            self.record_locator.to_canonical_value(),
        );
        map.insert("source_ordinal".into(), Value::from(self.source_ordinal));
        Value::Object(map)
    }
}

/// 1件の Event（規範 §7.1、Schema §5.5）。
#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub id: String,
    pub time: EventTime,
    pub source: ArtifactSource,
    pub event_type: EventType,
    pub assertion: AssertionKind,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub path: Option<WindowsPathValue>,
    pub program: Option<String>,
    pub process: Option<ProcessRef>,
    pub message: String,
    /// Event 固有の追加属性。決定性のため `BTreeMap` 固定（規範 §13.2）。
    pub attributes: BTreeMap<String, Value>,
    pub provenance: Provenance,
}

impl Event {
    /// 規範 §12.3 の12 field から Event ID を決定的に計算する。
    ///
    /// `event_ordinal` は同一 source record から複数 Event を生成する場合の番号。
    /// 通常は 0 を指定する。`message`・`hostname` 等は ID へ含まれない。
    pub fn compute_id(&self, event_ordinal: u64) -> String {
        crate::id::event_id(
            &self.provenance.evidence_id,
            &self.provenance.artifact_id,
            &self.provenance.parser_id,
            &self.provenance.parser_version,
            &self.provenance.record_locator.to_canonical_json(),
            self.provenance.source_ordinal,
            self.event_type.as_str(),
            self.assertion.as_str(),
            &self.time.to_canonical_json(),
            event_ordinal,
        )
    }

    /// Schema §5.5 の Event 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("event_id".into(), Value::String(self.id.clone()));
        map.insert("time".into(), self.time.to_canonical_value());
        map.insert("source".into(), Value::String(self.source.as_str().into()));
        map.insert(
            "event_type".into(),
            Value::String(self.event_type.as_str().into()),
        );
        map.insert(
            "assertion".into(),
            Value::String(self.assertion.as_str().into()),
        );
        map.insert(
            "hostname".into(),
            self.hostname
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "user".into(),
            self.user.clone().map(Value::String).unwrap_or(Value::Null),
        );
        map.insert(
            "path".into(),
            self.path
                .as_ref()
                .map(|p| p.to_canonical_value())
                .unwrap_or(Value::Null),
        );
        map.insert(
            "program".into(),
            self.program
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "process".into(),
            self.process
                .as_ref()
                .map(|p| p.to_canonical_value())
                .unwrap_or(Value::Null),
        );
        map.insert("message".into(), Value::String(self.message.clone()));
        map.insert(
            "attributes".into(),
            Value::Object(attributes_to_map(&self.attributes)),
        );
        map.insert("provenance".into(), self.provenance.to_canonical_value());
        Value::Object(map)
    }
}

/// `BTreeMap<String, Value>` を `serde_json::Map`（key sort 済み）へ変換する。
fn attributes_to_map(attrs: &BTreeMap<String, Value>) -> Map<String, Value> {
    // BTreeMap は key が byte 順で保持されるため、そのまま移植すれば canonical になる。
    let mut map = Map::new();
    for (k, v) in attrs {
        map.insert(k.clone(), v.clone());
    }
    map
}

/// `Option<u64>` を JSON number or null へ変換する。
fn opt_u64(n: Option<u64>) -> Value {
    match n {
        Some(v) => Value::from(v),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::TimestampKind;

    fn sample_event(message: &str) -> Event {
        let time = EventTime::unknown(TimestampKind::EventLogged);
        let prov = Provenance {
            evidence_id: "tf-evidence-v1:evid".into(),
            artifact_id: "tf-artifact-v1:art".into(),
            source_locator: "Security.evtx".into(),
            source_sha256: "a".repeat(64),
            parser_id: "traceforge-evtx".into(),
            parser_version: "1.0.0".into(),
            record_locator: RecordLocator::RecordId("12345".into()),
            source_ordinal: 12344,
        };
        Event {
            id: String::new(),
            time,
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: Some("host".into()),
            user: None,
            path: Some(WindowsPathValue::new("C:\\Users\\alice\\file.exe")),
            program: None,
            process: None,
            message: message.into(),
            attributes: BTreeMap::new(),
            provenance: prov,
        }
    }

    #[test]
    fn event_id_invariant_to_message_change() {
        // 規範 §12.3: message は Event ID の hash field に含まれない。
        let mut a = sample_event("hello");
        let mut b = sample_event("world");
        a.id = a.compute_id(0);
        b.id = b.compute_id(0);
        assert_eq!(a.id, b.id, "message が異なっても Event ID は同一");
    }

    #[test]
    fn event_id_changes_on_event_type_change() {
        let mut a = sample_event("");
        let mut b = sample_event("");
        b.event_type = EventType::new("registry_observation");
        a.id = a.compute_id(0);
        b.id = b.compute_id(0);
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn event_id_changes_on_record_locator_change() {
        let mut a = sample_event("");
        let mut b = sample_event("");
        b.provenance.record_locator = RecordLocator::RecordId("99999".into());
        a.id = a.compute_id(0);
        b.id = b.compute_id(0);
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn attributes_btremap_is_deterministic_order() {
        // 規範 §13.2: BTreeMap で key 順が確定する。
        let mut attrs = BTreeMap::new();
        attrs.insert("z".into(), Value::from(1));
        attrs.insert("a".into(), Value::from(2));
        let mut e = sample_event("");
        e.attributes = attrs;
        let v = e.to_canonical_value();
        let attrs_obj = v["attributes"].as_object().unwrap();
        let keys: Vec<&String> = attrs_obj.keys().collect();
        assert_eq!(keys, vec![&"a".to_string(), &"z".to_string()]);
    }

    #[test]
    fn record_locator_canonical_forms() {
        assert_eq!(
            RecordLocator::RecordId("5".into()).to_canonical_json(),
            r#"{"type":"record_id","value":"5"}"#
        );
        assert_eq!(
            RecordLocator::ByteOffset(100).to_canonical_json(),
            r#"{"type":"byte_offset","value":100}"#
        );
        assert_eq!(
            RecordLocator::ByteRange { start: 1, end: 9 }.to_canonical_json(),
            r#"{"end":9,"start":1,"type":"byte_range"}"#
        );
        assert_eq!(
            RecordLocator::SourceOrdinal.to_canonical_json(),
            r#"{"type":"source_ordinal"}"#
        );
    }

    #[test]
    fn artifact_source_roundtrip() {
        // Schema §3.4 の lowercase との往復。
        for v in [
            ArtifactSource::Prefetch,
            ArtifactSource::Evtx,
            ArtifactSource::UsnJournal,
            ArtifactSource::Lnk,
            ArtifactSource::JumpList,
            ArtifactSource::Amcache,
            ArtifactSource::Registry,
            ArtifactSource::File,
            ArtifactSource::Unknown,
        ] {
            assert_eq!(ArtifactSource::from_schema_str(v.as_str()), Some(v));
        }
        assert_eq!(ArtifactSource::from_schema_str("nonsense"), None);
    }

    #[test]
    fn event_canonical_json_shape() {
        let mut e = sample_event("");
        e.id = e.compute_id(0);
        let v = e.to_canonical_value();
        // 必須 field が揃っている（Schema §5.5）。
        for key in [
            "event_id",
            "time",
            "source",
            "event_type",
            "assertion",
            "hostname",
            "user",
            "path",
            "program",
            "process",
            "message",
            "attributes",
            "provenance",
        ] {
            assert!(v.as_object().unwrap().contains_key(key), "欠落: {key}");
        }
        // path は WindowsPathValue object。
        assert!(v["path"].is_object());
        assert_eq!(v["path"]["normalization_profile"], "windows-path-v1");
    }
}
