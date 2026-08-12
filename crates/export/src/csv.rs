//! CSV exporter（規範 §19.2・T7-004・Schema 互換 §10）。
//!
//! RFC 4180 形式で quoting する。cell の最初の非空白文字が `=`, `+`, `-`, `@`, TAB,
//! CR のいずれかの場合、先頭へ単一 quote（`'`）を付け、出力結果へ `csv_sanitized=true`
//! を記録する（規範 §19.2）。
//!
//! 出力は UTF-8・LF。TSV（TAB 区切り）にはしない（TAB を区切り文字として扱わない）。

use std::io::Write;

use tf_core::jsonl::SCHEMA_VERSION;

use crate::case_data::CaseData;
use crate::error::ExportError;
use crate::sanitize::sanitize_csv_cell;

/// CSV 出力結果の summary（規範 §19.2: `csv_sanitized` 記録用）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CsvSummary {
    /// CSV へ出力した行数（header 除く）。
    pub rows: u64,
    /// formula injection 対策として `'` を前置した cell 数。
    pub sanitized_cells: u64,
}

impl CsvSummary {
    /// 1件でも sanitization を行った場合に `true`。
    pub fn sanitized(&self) -> bool {
        self.sanitized_cells > 0
    }
}

/// Event を CSV 行へ変換して `out` へ書き込む。formula sanitization を施行した数を返す。
fn write_event_csv_row(out: &mut Vec<u8>, ev: &tf_core::event::Event) -> Result<u64, ExportError> {
    use tf_core::time::TemporalValue;

    let time_str = match &ev.time.value {
        TemporalValue::UtcInstant { value } => tf_core::time::format_utc_z(value),
        TemporalValue::LocalTime { value, timezone } => {
            let base = tf_core::time::naive_to_string(value);
            timezone
                .as_ref()
                .map(|tz| format!("{base} ({tz})"))
                .unwrap_or(base)
        }
        TemporalValue::Range { start, end } => {
            let s = start
                .as_ref()
                .map(tf_core::time::format_utc_z)
                .unwrap_or_else(|| "?".into());
            let e = end
                .as_ref()
                .map(tf_core::time::format_utc_z)
                .unwrap_or_else(|| "?".into());
            format!("{s}..{e}")
        }
        TemporalValue::Unknown => String::new(),
    };
    let hostname = ev.hostname.as_deref().unwrap_or("");
    let user = ev.user.as_deref().unwrap_or("");
    let path = ev.path.as_ref().map(|p| p.original.as_str()).unwrap_or("");
    let program = ev.program.as_deref().unwrap_or("");
    let source_locator = &ev.provenance.source_locator;

    let cells: Vec<String> = vec![
        ev.id.clone(),
        time_str,
        ev.event_type.as_str().to_string(),
        ev.source.as_str().to_string(),
        ev.assertion.as_str().to_string(),
        hostname.to_string(),
        user.to_string(),
        path.to_string(),
        program.to_string(),
        source_locator.clone(),
        ev.message.clone(),
    ];

    let mut sanitized: u64 = 0;
    let mut row = String::new();
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            row.push(',');
        }
        let needs_sanitization = crate::sanitize::needs_csv_formula_sanitization(cell);
        let sanitized_cell = sanitize_csv_cell(cell);
        if needs_sanitization {
            sanitized += 1;
        }
        row.push_str(&sanitized_cell);
    }
    out.extend_from_slice(row.as_bytes());
    out.push(b'\n');
    Ok(sanitized)
}

/// Case 全体を CSV 形式で `writer` へ出力する（Event 一覧表）。
///
/// header 行 + Event 行（Timeline 順）。各 cell へ RFC 4180 quoting と formula injection
/// 対策を適用する。戻り値は sanitization 件数（規範 §19.2: Manifest へ `csv_sanitized`
/// として記録することを推奨）。
pub fn write_csv(data: &CaseData, writer: &mut impl Write) -> Result<CsvSummary, ExportError> {
    let views = data.sorted_views();
    let mut out: Vec<u8> = Vec::new();
    // header
    let header = [
        "event_id",
        "time",
        "event_type",
        "source",
        "assertion",
        "hostname",
        "user",
        "path",
        "program",
        "source_locator",
        "message",
    ]
    .join(",");
    out.extend_from_slice(header.as_bytes());
    out.push(b'\n');

    let mut rows: u64 = 0;
    let mut sanitized_cells: u64 = 0;
    for ev in &views.events {
        let s = write_event_csv_row(&mut out, ev)?;
        sanitized_cells += s;
        rows += 1;
    }

    writer.write_all(&out)?;
    Ok(CsvSummary {
        rows,
        sanitized_cells,
    })
}

/// Case 全体を CSV 文字列へ直列化する（テスト用）。
pub fn to_csv_string(data: &CaseData) -> Result<(String, CsvSummary), ExportError> {
    let mut buf: Vec<u8> = Vec::new();
    let summary = write_csv(data, &mut buf)?;
    Ok((
        String::from_utf8(buf)
            .map_err(|e| ExportError::Canonical(format!("UTF-8 変換失敗: {e}")))?,
        summary,
    ))
}

/// `csv_sanitized` 記録用の Manifest 追加 field を構築する（Schema §5.9 limits 等へ）。
pub fn csv_sanitized_field(summary: CsvSummary) -> serde_json::Value {
    serde_json::json!({
        "csv_sanitized": summary.sanitized(),
        "csv_sanitized_cells": summary.sanitized_cells,
        "csv_rows": summary.rows,
        "schema_version": SCHEMA_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn make_event(id: &str, message: &str, path: Option<&str>) -> tf_core::event::Event {
        let naive = "2026-08-12T01:00:00".parse().unwrap();
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
        tf_core::event::Event {
            id: id.to_string(),
            time,
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: Some("host01".into()),
            user: None,
            path: path.map(WindowsPathValue::new),
            program: None,
            process: None,
            message: message.into(),
            attributes: BTreeMap::new(),
            provenance: Provenance {
                evidence_id: "tf-evidence-v1:x".into(),
                artifact_id: "tf-artifact-v1:x".into(),
                source_locator: "Security.evtx".into(),
                source_sha256: "a".repeat(64),
                parser_id: "traceforge-evtx".into(),
                parser_version: "1.0.0".into(),
                record_locator: RecordLocator::RecordId("1".into()),
                source_ordinal: 0,
            },
        }
    }

    #[test]
    fn csv_writes_header_and_event_rows() {
        let mut data = empty_data();
        data.events.push(make_event("tf-event-v1:1", "hello", None));
        let (csv, summary) = to_csv_string(&data).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("event_id,time,event_type"));
        assert!(lines[1].contains("tf-event-v1:1"));
        assert_eq!(summary.rows, 1);
        assert!(!summary.sanitized());
    }

    #[test]
    fn csv_formula_injection_in_message_is_neutralized() {
        // 規範 §19.2 / §21-11: message が =cmd|'/C calc'!A1 を含む場合、' を前置する。
        let mut data = empty_data();
        data.events
            .push(make_event("tf-event-v1:bad", "=cmd|'/C calc'!A1", None));
        let (csv, summary) = to_csv_string(&data).unwrap();
        // 最後の cell が message。' が前置されている。
        let last_line = csv.lines().last().unwrap();
        // message セルは末尾。行末に `'=` が現れる（quote 無し）または `"'"`（quote 有り）。
        assert!(
            last_line.contains("'=cmd") || last_line.contains("\"'=cmd"),
            "formula injection 対策が適用されていること: {last_line}"
        );
        assert!(summary.sanitized());
        assert!(summary.sanitized_cells >= 1);
    }

    #[test]
    fn csv_formula_injection_in_path() {
        let mut data = empty_data();
        // path に formula を仕込む。
        data.events.push(make_event(
            "tf-event-v1:bad2",
            "ok",
            Some("=HYPERLINK(\"http://evil\")"),
        ));
        let (csv, summary) = to_csv_string(&data).unwrap();
        assert!(summary.sanitized(), "path セルも sanitization 対象: {csv}");
    }

    #[test]
    fn csv_quote_when_message_contains_comma() {
        let mut data = empty_data();
        data.events
            .push(make_event("tf-event-v1:c", "hello, world", None));
        let (csv, summary) = to_csv_string(&data).unwrap();
        assert!(
            !summary.sanitized(),
            "comma は quote 対象だが formula 対策無し"
        );
        // 最後の cell は "hello, world" のように quote される。
        let last_line = csv.lines().last().unwrap();
        assert!(last_line.contains("\"hello, world\""));
    }
}
