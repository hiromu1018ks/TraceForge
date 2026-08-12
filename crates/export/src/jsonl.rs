//! JSONL exporter（Schema §6・T7-003）。
//!
//! 各行は envelope（`schema_version` + `record_type` + `record`）を持ち、出力順は固定。
//!
//! 1. `case`
//! 2. `evidence`（`evidence_id` 昇順）
//! 3. `artifact`（`artifact_id` 昇順）
//! 4. `event`（Timeline 順・規範 §6.3）
//! 5. `issue`（規範 §9.3 順: evidence_id, artifact_id, source_ordinal, code）
//! 6. `match`（`match_id` 昇順）
//! 7. `finding`（Severity 降順、`finding_id` 昇順）
//! 8. `manifest`（必ず最終行）
//!
//! 規範 §19.4: UTF-8・LF・string 内改行を escape・NaN/Infinity 禁止。

use std::io::Write;

use serde_json::Value;
use tf_core::canonical::to_canonical_string;
use tf_core::jsonl::SCHEMA_VERSION;

use crate::case_data::CaseData;
use crate::error::ExportError;
use crate::schema_check::check_jsonl_schema_major;

/// 1行分の envelope（LF 含まない）を構築する。
fn envelope_line(record_type: &str, record: Value) -> Result<String, ExportError> {
    let envelope = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "record_type": record_type,
        "record": record,
    });
    check_jsonl_schema_major(&envelope)?;
    Ok(to_canonical_string(&envelope)?)
}

/// CaseData を Schema §6 の出力順で JSONL へ書き出す。
///
/// Manifest 行は必ず最終行とする（Schema §6・規範 §19.4）。
pub fn write_jsonl(data: &CaseData, writer: &mut impl Write) -> Result<u64, ExportError> {
    let views = data.sorted_views();
    let mut event_count: u64 = 0;

    // 1. case
    let line = envelope_line("case", data.case.to_canonical_value())?;
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;

    // 2. evidence
    for e in &views.evidence {
        let line = envelope_line("evidence", e.to_canonical_value())?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }

    // 3. artifact
    for a in &views.artifacts {
        let line = envelope_line("artifact", a.to_canonical_value())?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }

    // 4. event (Timeline 順)
    for e in &views.events {
        let line = envelope_line("event", e.to_canonical_value())?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
        event_count += 1;
    }

    // 5. issue
    for i in &views.issues {
        let line = envelope_line("issue", i.to_canonical_value())?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }

    // 6. match
    for m in &views.matches {
        let line = envelope_line("match", m.to_canonical_value())?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }

    // 7. finding (Severity 降順)
    for f in &views.findings {
        let line = envelope_line("finding", f.to_canonical_value())?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }

    // 8. manifest (必ず最終行・Schema §6)
    let line = envelope_line("manifest", data.manifest.to_canonical_value())?;
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;

    Ok(event_count)
}

/// CaseData を JSONL 文字列へ直列化する（テスト・小規模 Case 用）。
pub fn to_jsonl_string(data: &CaseData) -> Result<String, ExportError> {
    let mut buf: Vec<u8> = Vec::new();
    write_jsonl(data, &mut buf)?;
    String::from_utf8(buf).map_err(|e| ExportError::Canonical(format!("UTF-8 変換失敗: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_core::case::{CaseMetadata, EvidenceItem, IntegrityStatus};
    use tf_core::jsonl::JsonlRecord;
    use tf_core::manifest::Manifest;

    fn empty_data() -> CaseData {
        CaseData {
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
                build_commit: "deadbeef".into(),
                target: "x86_64-pc-windows-msvc".into(),
                schema_version: SCHEMA_VERSION.into(),
                compatibility_profile: "TF-WIN-1.0".into(),
                run_started_at: "2026-08-12T00:00:00Z".into(),
                run_finished_at: "2026-08-12T00:01:00Z".into(),
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
    fn jsonl_order_is_fixed_and_manifest_is_last() {
        // Schema §6: case → evidence → ... → manifest。
        let mut data = empty_data();
        data.evidence.push(EvidenceItem {
            evidence_id: "tf-evidence-v1:b".into(),
            source_locator: "b".into(),
            size: 1,
            sha256: "b".repeat(64),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        });
        data.evidence.push(EvidenceItem {
            evidence_id: "tf-evidence-v1:a".into(),
            source_locator: "a".into(),
            size: 1,
            sha256: "a".repeat(64),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        });

        let s = to_jsonl_string(&data).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert!(!lines.is_empty());

        let first = JsonlRecord::parse(lines[0]).unwrap();
        assert_eq!(first.record_type, "case");

        let second = JsonlRecord::parse(lines[1]).unwrap();
        assert_eq!(second.record_type, "evidence");
        assert_eq!(second.record["evidence_id"], "tf-evidence-v1:a");

        let last = JsonlRecord::parse(lines.last().unwrap()).unwrap();
        assert_eq!(last.record_type, "manifest");
    }

    #[test]
    fn jsonl_lines_use_lf_only() {
        // 規範 §19.4: 改行は LF のみ。
        let data = empty_data();
        let s = to_jsonl_string(&data).unwrap();
        assert!(!s.contains("\r\n"), "CRLF が含まれないこと");
        for line in s.lines() {
            // 各行は正当な JSON であること。
            assert!(serde_json::from_str::<Value>(line).is_ok());
        }
    }

    #[test]
    fn jsonl_no_nan_or_infinity() {
        let data = empty_data();
        let s = to_jsonl_string(&data).unwrap();
        assert!(!s.contains("NaN"));
        assert!(!s.contains("Infinity"));
    }

    #[test]
    fn jsonl_each_line_is_self_contained_envelope() {
        // Schema §6: 各行は単独で schema_version + record_type + record を持つ。
        let data = empty_data();
        let s = to_jsonl_string(&data).unwrap();
        for line in s.lines() {
            let r = JsonlRecord::parse(line).unwrap();
            assert_eq!(r.schema_version, SCHEMA_VERSION);
        }
    }
}
