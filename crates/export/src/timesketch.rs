//! Timesketch exporter（互換 §8・TF-TIMESKETCH-1.0・T7-006）。
//!
//! 各 Event を Timesketch JSONL 形式（1行1 object）へ変換する。必須 field:
//!
//! ```text
//! message
//! datetime           (RFC 3339 UTC・秒以下の精度も許可)
//! timestamp_desc
//! traceforge_event_id
//! traceforge_source
//! traceforge_event_type
//! traceforge_evidence_id
//! ```
//!
//! 互換 §8 は「`datetime` へ変換できない timezone 不明 local time・Range・Unknown は
//! Timesketch Event として出力してはならない。除外件数と Event ID を export summary へ
//! 記録し、Exit Code 1 とする」と定める。本 exporter は [`TimesketchSummary`] で除外件数を返す。
//! 利用者が明示 timezone を指定して UTC へ確定変換した Event は出力できる。

use std::io::Write;

use serde_json::{Map, Value};
use tf_core::event::Event;
use tf_core::time::{EventTime, TemporalValue};

use crate::case_data::CaseData;
use crate::error::ExportError;

/// Timesketch 出力結果の summary（互換 §8: 除外件数と Event ID 記録）。
#[derive(Clone, Debug, Default)]
pub struct TimesketchSummary {
    /// Timesketch Event として出力した行数。
    pub exported: u64,
    /// UTC へ変換できず除外した Event 数（互換 §8）。
    pub excluded: u64,
    /// 除外した Event の ID 一覧（決定的順序・byte 昇順）。
    pub excluded_event_ids: Vec<String>,
    /// 除外した理由（deterministic な文字列 list・sort 済み）。
    pub exclusion_reasons: Vec<String>,
}

impl TimesketchSummary {
    /// 1件でも除外した場合は Exit Code 1 へ寄与する（互換 §8）。
    pub fn has_excluded(&self) -> bool {
        self.excluded > 0
    }
}

/// 1件の Event を Timesketch 形式の JSON object へ変換する。
///
/// UTC へ確定変換できない場合は [`None`] を返す（呼出側で除外として扱う）。
fn convert_event_to_timesketch(event: &Event) -> Result<Option<Value>, ExportError> {
    let datetime = match utc_datetime_string(&event.time) {
        Some(s) => s,
        None => return Ok(None),
    };

    let mut map = Map::new();
    map.insert("message".into(), Value::String(event.message.clone()));
    map.insert("datetime".into(), Value::String(datetime));
    map.insert(
        "timestamp_desc".into(),
        Value::String(event.time.kind.as_str().to_string()),
    );
    map.insert(
        "traceforge_event_id".into(),
        Value::String(event.id.clone()),
    );
    map.insert(
        "traceforge_source".into(),
        Value::String(event.source.as_str().into()),
    );
    map.insert(
        "traceforge_event_type".into(),
        Value::String(event.event_type.as_str().into()),
    );
    map.insert(
        "traceforge_evidence_id".into(),
        Value::String(event.provenance.evidence_id.clone()),
    );
    Ok(Some(Value::Object(map)))
}

/// EventTime から UTC datetime 文字列（RFC 3339・`Z` suffix）を取り出す。
///
/// UTC へ確定変換できない場合（timezone 不明 local time・Range・Unknown）は [`None`]。
fn utc_datetime_string(time: &EventTime) -> Option<String> {
    match &time.value {
        TemporalValue::UtcInstant { value } => Some(tf_core::time::format_utc_z(value)),
        TemporalValue::LocalTime { value, timezone } => {
            // 互換 §8: timezone 不明は出力しない。
            let tz_name = timezone.as_ref()?;
            let tz = tf_core::time::parse_iana_timezone(tz_name).ok()?;
            match tf_core::time::local_to_utc_outcome(*value, tz) {
                tf_core::time::LocalToUtcOutcome::Single(utc) => {
                    Some(tf_core::time::format_utc_z(&utc))
                }
                // DST Ambiguous / NonExistent は UTC へ確定変換不可 → 除外。
                _ => None,
            }
        }
        TemporalValue::Range { .. } => None,
        TemporalValue::Unknown => None,
    }
}

/// Case 全体を Timesketch JSONL へ変換し `writer` へ出力する。
///
/// 出力は各 Event を1行ずつ出力する。`schema_version` のような envelope は持たず、
/// Timesketch が期待する flat な JSON object とする（互換 §8）。
pub fn write_timesketch(
    data: &CaseData,
    writer: &mut impl Write,
) -> Result<TimesketchSummary, ExportError> {
    let views = data.sorted_views();
    let mut exported: u64 = 0;
    let mut excluded: u64 = 0;
    let mut excluded_event_ids: Vec<String> = Vec::new();
    let mut exclusion_reasons: Vec<String> = Vec::new();

    for ev in &views.events {
        match convert_event_to_timesketch(ev)? {
            Some(value) => {
                let line = tf_core::canonical::to_canonical_string(&value)?;
                writer.write_all(line.as_bytes())?;
                writer.write_all(b"\n")?;
                exported += 1;
            }
            None => {
                excluded += 1;
                excluded_event_ids.push(ev.id.clone());
                let reason = exclusion_reason_for(&ev.time);
                if !exclusion_reasons.contains(&reason) {
                    exclusion_reasons.push(reason);
                }
            }
        }
    }

    // 決定的順序（byte 昇順・規範 §13）。
    excluded_event_ids.sort();
    exclusion_reasons.sort();

    Ok(TimesketchSummary {
        exported,
        excluded,
        excluded_event_ids,
        exclusion_reasons,
    })
}

/// EventTime から除外理由（deterministic 文字列）を作る。
fn exclusion_reason_for(time: &EventTime) -> String {
    use tf_core::time::TemporalValue;
    match &time.value {
        TemporalValue::LocalTime { timezone: None, .. } => {
            "timezone-unknown local time cannot be converted to UTC".into()
        }
        TemporalValue::LocalTime {
            timezone: Some(_), ..
        } => "ambiguous or nonexistent local time (DST)".into(),
        TemporalValue::Range { .. } => "range time has no single UTC instant".into(),
        TemporalValue::Unknown => "unknown time".into(),
        TemporalValue::UtcInstant { .. } => "unexpectedly excluded".into(),
    }
}

/// Case 全体を Timesketch JSONL 文字列へ直列化する（テスト用）。
pub fn to_timesketch_string(data: &CaseData) -> Result<(String, TimesketchSummary), ExportError> {
    let mut buf: Vec<u8> = Vec::new();
    let summary = write_timesketch(data, &mut buf)?;
    Ok((
        String::from_utf8(buf)
            .map_err(|e| ExportError::Canonical(format!("UTF-8 変換失敗: {e}")))?,
        summary,
    ))
}

/// Timesketch summary を Manifest へ記録するための JSON 値へ変換する（互換 §8）。
pub fn timesketch_summary_field(summary: &TimesketchSummary) -> Value {
    serde_json::json!({
        "excluded": summary.excluded,
        "exported": summary.exported,
        "excluded_event_ids": summary.excluded_event_ids,
        "exclusion_reasons": summary.exclusion_reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, NaiveDateTime, Utc};
    use std::collections::BTreeMap;
    use tf_core::case::CaseMetadata;
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
    use tf_core::manifest::Manifest;
    use tf_core::path::WindowsPathValue;
    use tf_core::time::{EventTime, TemporalValue, TimePrecision, TimestampKind, TimezoneSource};

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
                schema_version: "1.0.0".into(),
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

    fn provenance() -> Provenance {
        Provenance {
            evidence_id: "tf-evidence-v1:x".into(),
            artifact_id: "tf-artifact-v1:x".into(),
            source_locator: "Security.evtx".into(),
            source_sha256: "a".repeat(64),
            parser_id: "traceforge-evtx".into(),
            parser_version: "1.0.0".into(),
            record_locator: RecordLocator::RecordId("1".into()),
            source_ordinal: 0,
        }
    }

    fn utc_event(id: &str) -> tf_core::event::Event {
        let dt: DateTime<Utc> = "2026-08-12T01:00:00Z".parse().unwrap();
        let time = EventTime::utc_instant(
            dt,
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        );
        tf_core::event::Event {
            id: id.to_string(),
            time,
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: Some("h".into()),
            user: None,
            path: Some(WindowsPathValue::new("C:\\Windows\\x.exe")),
            program: None,
            process: None,
            message: "hello".into(),
            attributes: BTreeMap::new(),
            provenance: provenance(),
        }
    }

    fn local_no_tz_event(id: &str) -> tf_core::event::Event {
        let naive: NaiveDateTime = "2026-08-12T01:00:00".parse().unwrap();
        let time = EventTime {
            value: TemporalValue::LocalTime {
                value: naive,
                timezone: None,
            },
            original: None,
            kind: TimestampKind::EventLogged,
            precision: TimePrecision::Second,
            timezone_source: TimezoneSource::Unknown,
            uncertainty_ms: None,
        };
        let mut ev = utc_event(id);
        ev.time = time;
        ev
    }

    fn tokyo_event(id: &str) -> tf_core::event::Event {
        let naive: NaiveDateTime = "2024-07-15T09:00:00".parse().unwrap();
        let time = EventTime {
            value: TemporalValue::LocalTime {
                value: naive,
                timezone: Some("Asia/Tokyo".into()),
            },
            original: None,
            kind: TimestampKind::EventLogged,
            precision: TimePrecision::Second,
            timezone_source: TimezoneSource::CaseDefault,
            uncertainty_ms: None,
        };
        let mut ev = utc_event(id);
        ev.time = time;
        ev
    }

    #[test]
    fn utc_event_is_exported() {
        let mut data = empty_data();
        data.events.push(utc_event("tf-event-v1:1"));
        let (jsonl, summary) = to_timesketch_string(&data).unwrap();
        assert_eq!(summary.exported, 1);
        assert_eq!(summary.excluded, 0);
        let line = jsonl.lines().next().unwrap();
        let value: Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["traceforge_event_id"], "tf-event-v1:1");
        assert_eq!(value["datetime"], "2026-08-12T01:00:00Z");
        assert_eq!(value["timestamp_desc"], "event_logged");
    }

    #[test]
    fn local_time_without_timezone_is_excluded() {
        // 互換 §8: timezone 不明 local time は出力しない。
        let mut data = empty_data();
        data.events.push(local_no_tz_event("tf-event-v1:notz"));
        let (jsonl, summary) = to_timesketch_string(&data).unwrap();
        assert!(jsonl.is_empty(), "Event は出力されない");
        assert_eq!(summary.excluded, 1);
        assert!(summary.has_excluded());
        assert_eq!(summary.excluded_event_ids, vec!["tf-event-v1:notz"]);
    }

    #[test]
    fn tokyo_event_is_exported_as_utc() {
        let mut data = empty_data();
        data.events.push(tokyo_event("tf-event-v1:tyo"));
        let (jsonl, summary) = to_timesketch_string(&data).unwrap();
        assert_eq!(summary.exported, 1);
        let line = jsonl.lines().next().unwrap();
        let value: Value = serde_json::from_str(line).unwrap();
        // 2024-07-15T09:00:00 Asia/Tokyo = 2024-07-15T00:00:00Z。
        assert_eq!(value["datetime"], "2024-07-15T00:00:00Z");
    }

    #[test]
    fn dst_ambiguous_event_is_excluded() {
        let naive: NaiveDateTime = "2024-11-03T01:30:00".parse().unwrap();
        let time = EventTime {
            value: TemporalValue::LocalTime {
                value: naive,
                timezone: Some("America/New_York".into()),
            },
            original: None,
            kind: TimestampKind::EventLogged,
            precision: TimePrecision::Second,
            timezone_source: TimezoneSource::CaseDefault,
            uncertainty_ms: None,
        };
        let mut ev = utc_event("tf-event-v1:amb");
        ev.time = time;

        let mut data = empty_data();
        data.events.push(ev);
        let (_jsonl, summary) = to_timesketch_string(&data).unwrap();
        assert_eq!(summary.excluded, 1);
        assert!(summary.exclusion_reasons.iter().any(|r| r.contains("DST")));
    }

    #[test]
    fn summary_records_excluded_event_ids_sorted() {
        let mut data = empty_data();
        data.events.push(local_no_tz_event("tf-event-v1:zzz"));
        data.events.push(local_no_tz_event("tf-event-v1:aaa"));
        data.events.push(utc_event("tf-event-v1:ok"));
        let (_jsonl, summary) = to_timesketch_string(&data).unwrap();
        assert_eq!(summary.exported, 1);
        assert_eq!(summary.excluded, 2);
        // byte 昇順。
        assert_eq!(
            summary.excluded_event_ids,
            vec!["tf-event-v1:aaa", "tf-event-v1:zzz"]
        );
    }

    #[test]
    fn filename_must_end_with_jsonl() {
        // 互換 §8: 出力 filename は .jsonl で終わらなければならない。
        // これは CLI 側で検証するルールだが、本テストでは定数として文書化する。
        let valid = "timeline.jsonl";
        let invalid = "timeline.csv";
        assert!(valid.ends_with(".jsonl"));
        assert!(!invalid.ends_with(".jsonl"));
    }
}
