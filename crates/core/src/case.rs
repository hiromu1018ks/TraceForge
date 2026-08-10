//! Case・Evidence・Artifact の Schema §5 型（規範 §4、§5）。
//!
//! Schema §5.1〜5.4 に従う。`snapshot_locator` は private runtime 情報のため
//! Case JSON へ出力しない（Schema §5.3）。

use serde_json::{Map, Value};

use crate::event::ArtifactSource;

/// Schema §3.2 の Severity（Case と Finding で共用）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Informational => "informational",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "informational" => Severity::Informational,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }
}

/// Schema §3.5 の Parse status。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseStatus {
    Complete,
    Partial,
    Skipped,
    Failed,
}

impl ParseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParseStatus::Complete => "complete",
            ParseStatus::Partial => "partial",
            ParseStatus::Skipped => "skipped",
            ParseStatus::Failed => "failed",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "complete" => ParseStatus::Complete,
            "partial" => ParseStatus::Partial,
            "skipped" => ParseStatus::Skipped,
            "failed" => ParseStatus::Failed,
            _ => return None,
        })
    }
}

/// 規範 §5.5 / §11 / Schema §5.4 の Probe 結果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    Confirmed,
    Probable,
    UnsupportedVersion,
    NotThisFormat,
    Malformed,
}

impl ProbeResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProbeResult::Confirmed => "confirmed",
            ProbeResult::Probable => "probable",
            ProbeResult::UnsupportedVersion => "unsupported_version",
            ProbeResult::NotThisFormat => "not_this_format",
            ProbeResult::Malformed => "malformed",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "confirmed" => ProbeResult::Confirmed,
            "probable" => ProbeResult::Probable,
            "unsupported_version" => ProbeResult::UnsupportedVersion,
            "not_this_format" => ProbeResult::NotThisFormat,
            "malformed" => ProbeResult::Malformed,
            _ => return None,
        })
    }
}

/// Evidence snapshot の整合性状態（規範 §5.5、Schema §5.3）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// before/after 一致・SHA-256 再検証 OK。Parser へ渡してよい唯一の状態。
    VerifiedSnapshot,
    /// snapshot 中に元 Evidence の size/mtime/identity が変化した。解析しない。
    ChangedDuringSnapshot,
    /// read error・disk full・hash error 等で snapshot 作成失敗。
    SnapshotFailed,
}

impl IntegrityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            IntegrityStatus::VerifiedSnapshot => "verified_snapshot",
            IntegrityStatus::ChangedDuringSnapshot => "changed_during_snapshot",
            IntegrityStatus::SnapshotFailed => "snapshot_failed",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "verified_snapshot" => IntegrityStatus::VerifiedSnapshot,
            "changed_during_snapshot" => IntegrityStatus::ChangedDuringSnapshot,
            "snapshot_failed" => IntegrityStatus::SnapshotFailed,
            _ => return None,
        })
    }
}

/// Schema §5.2 の Case metadata。
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CaseMetadata {
    pub case_id: String,
    pub external_case_id: Option<String>,
    pub name: String,
    pub analyst: Option<String>,
    pub description: Option<String>,
    pub default_timezone: Option<String>,
    pub tags: Vec<String>,
}

impl CaseMetadata {
    /// Schema §5.2 の `case` 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("case_id".into(), Value::String(self.case_id.clone()));
        map.insert(
            "external_case_id".into(),
            self.external_case_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert("name".into(), Value::String(self.name.clone()));
        map.insert(
            "analyst".into(),
            self.analyst
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "description".into(),
            self.description
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "default_timezone".into(),
            self.default_timezone
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "tags".into(),
            Value::Array(self.tags.iter().cloned().map(Value::String).collect()),
        );
        Value::Object(map)
    }
}

/// Schema §5.3 の Evidence。
///
/// `snapshot_locator` は private runtime 情報のため Case JSON へ出力しない（Schema §5.3）。
/// [`to_canonical_value`] は `snapshot_locator` を含めない。
///
/// [`to_canonical_value`]: EvidenceItem::to_canonical_value
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceItem {
    pub evidence_id: String,
    pub source_locator: String,
    pub size: u64,
    pub sha256: String,
    pub integrity_status: IntegrityStatus,
    pub parse_eligible: bool,
    /// private runtime 情報。Case JSON へ出力しない（Schema §5.3）。
    pub snapshot_locator: String,
}

impl EvidenceItem {
    /// Schema §5.3 の Evidence 形式の [`Value`] を構築する。`snapshot_locator` は含めない。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "evidence_id".into(),
            Value::String(self.evidence_id.clone()),
        );
        map.insert(
            "source_locator".into(),
            Value::String(self.source_locator.clone()),
        );
        map.insert("size".into(), Value::from(self.size));
        map.insert("sha256".into(), Value::String(self.sha256.clone()));
        map.insert(
            "integrity_status".into(),
            Value::String(self.integrity_status.as_str().into()),
        );
        map.insert("parse_eligible".into(), Value::Bool(self.parse_eligible));
        // snapshot_locator は出力しない（Schema §5.3）。
        Value::Object(map)
    }
}

/// Schema §5.4 の Artifact instance。
#[derive(Clone, Debug, PartialEq)]
pub struct ArtifactInstance {
    pub artifact_id: String,
    pub evidence_id: String,
    pub artifact_type: ArtifactSource,
    pub parser_id: String,
    pub parser_version: String,
    pub probe_result: ProbeResult,
    pub detection_reasons: Vec<String>,
    pub parse_status: ParseStatus,
}

impl ArtifactInstance {
    /// Schema §5.4 の Artifact 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "artifact_id".into(),
            Value::String(self.artifact_id.clone()),
        );
        map.insert(
            "evidence_id".into(),
            Value::String(self.evidence_id.clone()),
        );
        map.insert(
            "artifact_type".into(),
            Value::String(self.artifact_type.as_str().into()),
        );
        map.insert("parser_id".into(), Value::String(self.parser_id.clone()));
        map.insert(
            "parser_version".into(),
            Value::String(self.parser_version.clone()),
        );
        map.insert(
            "probe_result".into(),
            Value::String(self.probe_result.as_str().into()),
        );
        map.insert(
            "detection_reasons".into(),
            Value::Array(
                self.detection_reasons
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        map.insert(
            "parse_status".into(),
            Value::String(self.parse_status.as_str().into()),
        );
        Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_omits_snapshot_locator() {
        // Schema §5.3: snapshot_locator は Case JSON へ出力しない。
        let e = EvidenceItem {
            evidence_id: "tf-evidence-v1:x".into(),
            source_locator: "a.evtx".into(),
            size: 10,
            sha256: "a".repeat(64),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: "/tmp/private/x".into(),
        };
        let v = e.to_canonical_value();
        assert!(!v.as_object().unwrap().contains_key("snapshot_locator"));
        assert_eq!(v["integrity_status"], "verified_snapshot");
        assert_eq!(v["parse_eligible"], true);
    }

    #[test]
    fn integrity_status_roundtrip() {
        for v in [
            IntegrityStatus::VerifiedSnapshot,
            IntegrityStatus::ChangedDuringSnapshot,
            IntegrityStatus::SnapshotFailed,
        ] {
            assert_eq!(IntegrityStatus::from_schema_str(v.as_str()), Some(v));
        }
    }

    #[test]
    fn case_metadata_canonical() {
        let c = CaseMetadata {
            case_id: "tf-case-v1:x".into(),
            external_case_id: None,
            name: "demo".into(),
            analyst: Some("alice".into()),
            description: None,
            default_timezone: Some("Asia/Tokyo".into()),
            tags: vec!["ir".into()],
        };
        let v = c.to_canonical_value();
        assert_eq!(v["external_case_id"], Value::Null);
        assert_eq!(v["name"], "demo");
        assert_eq!(v["tags"][0], "ir");
    }

    #[test]
    fn artifact_instance_canonical() {
        let a = ArtifactInstance {
            artifact_id: "tf-artifact-v1:y".into(),
            evidence_id: "tf-evidence-v1:x".into(),
            artifact_type: ArtifactSource::Evtx,
            parser_id: "traceforge-evtx".into(),
            parser_version: "1.0.0".into(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["magic".into()],
            parse_status: ParseStatus::Complete,
        };
        let v = a.to_canonical_value();
        assert_eq!(v["artifact_type"], "evtx");
        assert_eq!(v["probe_result"], "confirmed");
        assert_eq!(v["parse_status"], "complete");
    }
}
