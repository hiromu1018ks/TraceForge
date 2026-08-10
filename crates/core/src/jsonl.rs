//! Case JSON と JSONL envelope（Schema §5.1、§6）。
//!
//! Case JSON は Schema §5.1 の固定 top-level を持つ。JSONL は各行が envelope
//! （`schema_version` + `record_type` + `record`）を持ち、出力順は固定（Schema §6）。
//!
//! Phase 1 では構築・直列化・ envelope の parse と Schema 検証を提供する。
//! Timeline 順（Schema §6 の event 順）は Phase 3 で決定するため、ここでは
//! 挿入順を保持する。

use serde_json::{Map, Value};

use crate::canonical::to_canonical_string;
use crate::case::{ArtifactInstance, CaseMetadata, EvidenceItem};
use crate::event::Event;
use crate::finding::Finding;
use crate::issue::Issue;
use crate::manifest::Manifest;
use crate::r#match::Match;
use crate::schema::{validate_case_bundle, validate_jsonl_envelope};

/// Schema §1 の Schema version 文字列。
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Case JSON 1件の top-level 全体（Schema §5.1）。
#[derive(Clone, Debug, Default)]
pub struct CaseBundle {
    pub case: CaseMetadata,
    pub evidence: Vec<EvidenceItem>,
    pub artifacts: Vec<ArtifactInstance>,
    pub events: Vec<Event>,
    pub issues: Vec<Issue>,
    pub matches: Vec<Match>,
    pub findings: Vec<Finding>,
    pub manifest: Manifest,
}

impl CaseBundle {
    /// Schema §5.1 の Case JSON 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "schema_version".into(),
            Value::String(SCHEMA_VERSION.into()),
        );
        map.insert("record_type".into(), Value::String("case_bundle".into()));
        map.insert("case".into(), self.case.to_canonical_value());
        map.insert(
            "evidence".into(),
            Value::Array(
                self.evidence
                    .iter()
                    .map(|e| e.to_canonical_value())
                    .collect(),
            ),
        );
        map.insert(
            "artifacts".into(),
            Value::Array(
                self.artifacts
                    .iter()
                    .map(|a| a.to_canonical_value())
                    .collect(),
            ),
        );
        map.insert(
            "events".into(),
            Value::Array(self.events.iter().map(|e| e.to_canonical_value()).collect()),
        );
        map.insert(
            "issues".into(),
            Value::Array(self.issues.iter().map(|i| i.to_canonical_value()).collect()),
        );
        map.insert(
            "matches".into(),
            Value::Array(
                self.matches
                    .iter()
                    .map(|m| m.to_canonical_value())
                    .collect(),
            ),
        );
        map.insert(
            "findings".into(),
            Value::Array(
                self.findings
                    .iter()
                    .map(|f| f.to_canonical_value())
                    .collect(),
            ),
        );
        map.insert("manifest".into(), self.manifest.to_canonical_value());
        Value::Object(map)
    }

    /// [`to_canonical_value`] の canonical JSON 文字列。
    ///
    /// [`to_canonical_value`]: CaseBundle::to_canonical_value
    pub fn to_canonical_json(&self) -> String {
        to_canonical_string(&self.to_canonical_value()).expect("CaseBundle の canonical JSON 変換")
    }

    /// Schema §5.1 の検証を行う。
    pub fn validate(&self) -> Result<(), crate::schema::SchemaError> {
        let value = self.to_canonical_value();
        validate_case_bundle(&value)
    }

    /// Schema §6 の出力順で JSONL record 列へ展開する。
    ///
    /// 出力順（Schema §6）:
    /// 1. `case`
    /// 2. `evidence`（`evidence_id` 昇順）
    /// 3. `artifact`（`artifact_id` 昇順）
    /// 4. `event`（Timeline 順。Phase 1 では挿入順を保持）
    /// 5. `issue`（規範 §9.3 順）
    /// 6. `match`（`match_id` 昇順）
    /// 7. `finding`（Severity 降順、`finding_id` 昇順）
    /// 8. `manifest`（最終行）
    pub fn to_jsonl_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();

        // 1. case
        lines.push(self.envelope_line("case", self.case.to_canonical_value()));

        // 2. evidence: evidence_id 昇順。
        let mut ev = self.evidence.clone();
        ev.sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
        for e in &ev {
            lines.push(self.envelope_line("evidence", e.to_canonical_value()));
        }

        // 3. artifact: artifact_id 昇順。
        let mut arts = self.artifacts.clone();
        arts.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
        for a in &arts {
            lines.push(self.envelope_line("artifact", a.to_canonical_value()));
        }

        // 4. event: 挿入順を保持（Timeline 順は Phase 3 で決定）。
        for e in &self.events {
            lines.push(self.envelope_line("event", e.to_canonical_value()));
        }

        // 5. issue: 規範 §9.3 順（evidence_id, artifact_id, source_ordinal, code）。
        let mut issues = self.issues.clone();
        issues.sort_by(|a, b| {
            a.evidence_id
                .cmp(&b.evidence_id)
                .then_with(|| a.artifact_id.cmp(&b.artifact_id))
                .then_with(|| a.source_ordinal.cmp(&b.source_ordinal))
                .then_with(|| a.issue_id.cmp(&b.issue_id))
        });
        for i in &issues {
            lines.push(self.envelope_line("issue", i.to_canonical_value()));
        }

        // 6. match: match_id 昇順。
        let mut matches = self.matches.clone();
        matches.sort_by(|a, b| a.match_id.cmp(&b.match_id));
        for m in &matches {
            lines.push(self.envelope_line("match", m.to_canonical_value()));
        }

        // 7. finding: Severity 降順、finding_id 昇順。
        let mut findings = self.findings.clone();
        findings.sort_by(|a, b| {
            // Severity 降順: critical > high > medium > low > informational。
            severity_rank(b.severity)
                .cmp(&severity_rank(a.severity))
                .then_with(|| a.finding_id.cmp(&b.finding_id))
        });
        for f in &findings {
            lines.push(self.envelope_line("finding", f.to_canonical_value()));
        }

        // 8. manifest: 必ず最終行（Schema §6）。
        lines.push(self.envelope_line("manifest", self.manifest.to_canonical_value()));

        lines
    }

    fn envelope_line(&self, record_type: &str, record: Value) -> String {
        let envelope = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "record_type": record_type,
            "record": record,
        });
        to_canonical_string(&envelope).expect("JSONL envelope canonical JSON 変換")
    }
}

/// Severity の順位（降順用）。critical=5, high=4, medium=3, low=2, informational=1。
fn severity_rank(s: crate::case::Severity) -> u8 {
    use crate::case::Severity;
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Informational => 1,
    }
}

/// Schema §6 の JSONL envelope 1行分。
#[derive(Clone, Debug)]
pub struct JsonlRecord {
    pub schema_version: String,
    pub record_type: String,
    pub record: Value,
}

impl JsonlRecord {
    /// 1物理行（LF 終端なし）を parse する。Schema §6 の envelope 構造を検証する。
    pub fn parse(line: &str) -> Result<Self, crate::schema::SchemaError> {
        let value: Value = serde_json::from_str(line).map_err(|e| {
            crate::schema::SchemaError::Validation(format!("JSON parse error: {e}"))
        })?;
        validate_jsonl_envelope(&value)?;
        let obj = value.as_object().unwrap();
        Ok(JsonlRecord {
            schema_version: obj["schema_version"].as_str().unwrap().to_string(),
            record_type: obj["record_type"].as_str().unwrap().to_string(),
            record: obj["record"].clone(),
        })
    }

    /// canonical JSON 1行へ直列化する（LF は含まない）。
    pub fn to_line(&self) -> String {
        let envelope = serde_json::json!({
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "record": self.record,
        });
        to_canonical_string(&envelope).expect("JSONL envelope canonical JSON 変換")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::Severity;

    fn empty_bundle() -> CaseBundle {
        CaseBundle {
            case: CaseMetadata {
                case_id: "tf-case-v1:x".into(),
                external_case_id: None,
                name: "demo".into(),
                analyst: None,
                description: None,
                default_timezone: None,
                tags: vec![],
            },
            manifest: Manifest {
                traceforge_version: "0.1.0".into(),
                build_commit: "x".into(),
                target: "t".into(),
                schema_version: "1.0.0".into(),
                compatibility_profile: "tf-compat-v1".into(),
                run_started_at: "2026-08-10T00:00:00Z".into(),
                run_finished_at: "2026-08-10T00:00:01Z".into(),
                resolved_config: serde_json::json!({}),
                resolved_config_sha256: "a".repeat(64),
                case_id: "tf-case-v1:x".into(),
                counts: Default::default(),
                components: vec![],
                rules: vec![],
                attack_dataset: None,
                timezone_assumptions: vec![],
                limits: serde_json::json!({}),
                incomplete_reasons: vec![],
                complete: true,
                exit_code: 0,
            },
            ..Default::default()
        }
    }

    #[test]
    fn case_bundle_canonical_json_has_fixed_toplevel() {
        // Schema §5.1: top-level は固定。
        let b = empty_bundle();
        let v = b.to_canonical_value();
        assert_eq!(v["schema_version"], "1.0.0");
        assert_eq!(v["record_type"], "case_bundle");
        for key in [
            "case",
            "evidence",
            "artifacts",
            "events",
            "issues",
            "matches",
            "findings",
            "manifest",
        ] {
            assert!(v.as_object().unwrap().contains_key(key));
        }
    }

    #[test]
    fn case_bundle_validate_ok() {
        let b = empty_bundle();
        assert!(b.validate().is_ok());
    }

    #[test]
    fn jsonl_order_case_evidence_manifest() {
        // Schema §6: case → evidence → ... → manifest（最終）。
        let mut b = empty_bundle();
        b.evidence.push(EvidenceItem {
            evidence_id: "tf-evidence-v1:b".into(),
            source_locator: "b.evtx".into(),
            size: 1,
            sha256: "b".repeat(64),
            integrity_status: crate::case::IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        });
        b.evidence.push(EvidenceItem {
            evidence_id: "tf-evidence-v1:a".into(),
            source_locator: "a.evtx".into(),
            size: 1,
            sha256: "a".repeat(64),
            integrity_status: crate::case::IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        });
        let lines = b.to_jsonl_lines();
        // 最初は case、次が evidence a、その次が evidence b（sort 済み）、最後が manifest。
        let first = JsonlRecord::parse(&lines[0]).unwrap();
        assert_eq!(first.record_type, "case");
        let second = JsonlRecord::parse(&lines[1]).unwrap();
        assert_eq!(second.record_type, "evidence");
        assert_eq!(second.record["evidence_id"], "tf-evidence-v1:a");
        let last = JsonlRecord::parse(lines.last().unwrap()).unwrap();
        assert_eq!(last.record_type, "manifest", "manifest は必ず最終行");
    }

    #[test]
    fn jsonl_findings_sorted_by_severity_desc() {
        // Schema §6: finding は Severity 降順、finding_id 昇順。
        let mut b = empty_bundle();
        let mk = |id: &str, sev: Severity| Finding {
            finding_id: id.into(),
            title: "t".into(),
            description: "d".into(),
            severity: sev,
            confidence: crate::finding::Confidence::new(0.5, vec![]),
            event_ids: vec![],
            evidence_ids: vec![],
            match_ids: vec![],
            rule_refs: vec![],
            attack_mappings: vec![],
            observed_evidence: vec![],
            inference: vec![],
        };
        b.findings.push(mk("tf-finding-v1:low", Severity::Low));
        b.findings.push(mk("tf-finding-v1:high", Severity::High));
        b.findings.push(mk("tf-finding-v1:high2", Severity::High));
        let lines = b.to_jsonl_lines();
        // finding 行（manifest の前）を取り出す。
        let findings: Vec<_> = lines
            .iter()
            .filter_map(|l| {
                let r = JsonlRecord::parse(l).ok()?;
                (r.record_type == "finding").then(|| r.record["finding_id"].clone())
            })
            .collect();
        assert_eq!(findings[0], "tf-finding-v1:high");
        assert_eq!(findings[1], "tf-finding-v1:high2");
        assert_eq!(findings[2], "tf-finding-v1:low");
    }

    #[test]
    fn jsonl_record_parse_rejects_missing_envelope() {
        // Schema §6: envelope 必須 field 欠落は error。
        assert!(JsonlRecord::parse(r#"{"foo": 1}"#).is_err());
        assert!(
            JsonlRecord::parse(
                r#"{"schema_version":"1.0.0","record_type":"nonsense","record":{}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn jsonl_manifest_is_final_line() {
        // Schema §6: Manifest がない JSONL は未完了。
        let b = empty_bundle();
        let lines = b.to_jsonl_lines();
        assert!(!lines.is_empty());
        let last = JsonlRecord::parse(lines.last().unwrap()).unwrap();
        assert_eq!(last.record_type, "manifest");
    }
}
