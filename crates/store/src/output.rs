//! 最小 JSON / JSONL / Manifest 出力（T3-030、T3-031、規範 §13.1、Schema §5.1・§6）。
//!
//! Phase 3 の縦割り用として、EventStore から Timeline 順で Event を streaming 出力する。
//! 正式な Exporter（6形式）は Phase 7 へ引き継ぐ。
//!
//! 規範 §13.1 の run metadata 分離:
//! - 分析レコード（Events・Issues・Matches 等）は同一性比較へ含む
//! - run metadata（開始/終了時刻・PID・temp dir 等）は Manifest へ分離し、比較から除外する
//!
//! 出力順（Schema §6）:
//! 1. case → 2. evidence（evidence_id 昇順） → 3. artifact（artifact_id 昇順）
//!    → 4. event（Timeline 順・EventStore から streaming） → 5. issue（規範 §9.3 順）
//!    → 6. match（match_id 昇順） → 7. finding（Severity 降順・finding_id 昇順）
//!    → 8. manifest（必ず最終行）

use std::io::Write;

use serde_json::Value;
use tf_core::canonical::to_canonical_string;
use tf_core::case::{ArtifactInstance, CaseMetadata, EvidenceItem, Severity};
use tf_core::finding::Finding;
use tf_core::issue::Issue;
use tf_core::manifest::{Manifest, ManifestCounts};
use tf_core::r#match::Match;
use tf_core::schema::SCHEMA_VERSION;

use crate::error::OutputError;
use crate::store::EventStore;
use crate::timeline::{TimelineFilter, TimelineKey, TimelineSummary};

/// Event 以外の構成要素（Case 全体の metadata 的な部分）。
///
/// Event は [`EventStore`] から streaming するため、ここには含めない。
/// これらの slice は整列済みであることを呼出側が保証する（あるいは本関数内で整列する）。
#[derive(Clone, Debug)]
pub struct CaseStream<'a> {
    pub case: &'a CaseMetadata,
    pub evidence: &'a [EvidenceItem],
    pub artifacts: &'a [ArtifactInstance],
    pub issues: &'a [Issue],
    pub matches: &'a [Match],
    pub findings: &'a [Finding],
    pub manifest: &'a Manifest,
}

/// Schema §6 の出力順で JSONL を streaming 出力する（T3-030）。
///
/// Event 行は [`EventStore::iter_sorted`] から Timeline 順で1件ずつ読み出し、
/// 逐次 writer へ書き出す。全 Event を `Vec` へ保持しない（規範 §21-6）。
///
/// `memory_budget_bytes` は Timeline sort の memory 上限（規範 §10）。
/// `filter` は [`None`] で全件出力、[`Some`] で条件絞り込み（F-009）。
pub fn write_jsonl(
    store: &EventStore,
    stream: &CaseStream,
    memory_budget_bytes: usize,
    filter: Option<&TimelineFilter>,
    writer: &mut impl Write,
) -> Result<WriteOutcome, OutputError> {
    // 1. case 行。
    writer.write_all(b"{")?;
    write_kv_str(writer, "schema_version", SCHEMA_VERSION)?;
    writer.write_all(b",")?;
    write_kv_str(writer, "record_type", "case")?;
    writer.write_all(b",")?;
    write_kv_raw(writer, "record", &stream.case.to_canonical_value())?;
    writer.write_all(b"}\n")?;

    // 2. evidence 行（evidence_id 昇順）。
    let mut ev: Vec<&EvidenceItem> = stream.evidence.iter().collect();
    ev.sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
    for e in &ev {
        writer.write_all(b"{")?;
        write_kv_str(writer, "schema_version", SCHEMA_VERSION)?;
        writer.write_all(b",")?;
        write_kv_str(writer, "record_type", "evidence")?;
        writer.write_all(b",")?;
        write_kv_raw(writer, "record", &e.to_canonical_value())?;
        writer.write_all(b"}\n")?;
    }

    // 3. artifact 行（artifact_id 昇順）。
    let mut arts: Vec<&ArtifactInstance> = stream.artifacts.iter().collect();
    arts.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
    for a in &arts {
        writer.write_all(b"{")?;
        write_kv_str(writer, "schema_version", SCHEMA_VERSION)?;
        writer.write_all(b",")?;
        write_kv_str(writer, "record_type", "artifact")?;
        writer.write_all(b",")?;
        write_kv_raw(writer, "record", &a.to_canonical_value())?;
        writer.write_all(b"}\n")?;
    }

    // 4. event 行（Timeline 順・EventStore から streaming）。
    let mut summary = TimelineSummary::default();
    let mut events_output: u64 = 0;
    let sorted = store.iter_sorted(memory_budget_bytes)?;
    for result in sorted {
        let event = result?;
        let key = TimelineKey::from_event(&event);
        summary.add_group(key.group());
        if let Some(f) = filter
            && !f.matches(&key, &event)
        {
            continue;
        }
        writer.write_all(b"{")?;
        write_kv_str(writer, "schema_version", SCHEMA_VERSION)?;
        writer.write_all(b",")?;
        write_kv_str(writer, "record_type", "event")?;
        writer.write_all(b",")?;
        write_kv_raw(writer, "record", &event.to_canonical_value())?;
        writer.write_all(b"}\n")?;
        events_output += 1;
    }

    // 5. issue 行（規範 §9.3 順: evidence_id, artifact_id, source_ordinal, code）。
    let mut issues: Vec<&Issue> = stream.issues.iter().collect();
    issues.sort_by(|a, b| {
        a.evidence_id
            .cmp(&b.evidence_id)
            .then_with(|| a.artifact_id.cmp(&b.artifact_id))
            .then_with(|| a.source_ordinal.cmp(&b.source_ordinal))
            .then_with(|| a.issue_id.cmp(&b.issue_id))
    });
    for i in &issues {
        writer.write_all(b"{")?;
        write_kv_str(writer, "schema_version", SCHEMA_VERSION)?;
        writer.write_all(b",")?;
        write_kv_str(writer, "record_type", "issue")?;
        writer.write_all(b",")?;
        write_kv_raw(writer, "record", &i.to_canonical_value())?;
        writer.write_all(b"}\n")?;
    }

    // 6. match 行（match_id 昇順）。
    let mut matches: Vec<&Match> = stream.matches.iter().collect();
    matches.sort_by(|a, b| a.match_id.cmp(&b.match_id));
    for m in &matches {
        writer.write_all(b"{")?;
        write_kv_str(writer, "schema_version", SCHEMA_VERSION)?;
        writer.write_all(b",")?;
        write_kv_str(writer, "record_type", "match")?;
        writer.write_all(b",")?;
        write_kv_raw(writer, "record", &m.to_canonical_value())?;
        writer.write_all(b"}\n")?;
    }

    // 7. finding 行（Severity 降順、finding_id 昇順）。
    let mut findings: Vec<&Finding> = stream.findings.iter().collect();
    findings.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
    for f in &findings {
        writer.write_all(b"{")?;
        write_kv_str(writer, "schema_version", SCHEMA_VERSION)?;
        writer.write_all(b",")?;
        write_kv_str(writer, "record_type", "finding")?;
        writer.write_all(b",")?;
        write_kv_raw(writer, "record", &f.to_canonical_value())?;
        writer.write_all(b"}\n")?;
    }

    // 8. manifest 行（必ず最終行）。
    writer.write_all(b"{")?;
    write_kv_str(writer, "schema_version", SCHEMA_VERSION)?;
    writer.write_all(b",")?;
    write_kv_str(writer, "record_type", "manifest")?;
    writer.write_all(b",")?;
    write_kv_raw(writer, "record", &stream.manifest.to_canonical_value())?;
    writer.write_all(b"}\n")?;

    Ok(WriteOutcome {
        events_output,
        timeline_summary: summary,
    })
}

/// 最小 Manifest を構築する（T3-031）。
///
/// 規範 §13.1: run metadata（開始/終了時刻・PID 等）は Manifest へ分離し、
/// 分析レコードの同一性比較から除外する。本関数は EventStore の件数を event count へ
/// 反映し、run metadata は呼出側が与えた値をそのまま使う。
pub fn build_manifest_counts(store: &EventStore, others: &OtherCounts) -> ManifestCounts {
    ManifestCounts {
        evidence: others.evidence,
        artifact: others.artifact,
        event: store.len(),
        issue: others.issue,
        r#match: others.match_,
        finding: others.finding,
    }
}

/// Event 以外の record 件数（Manifest 構築用）。
#[derive(Clone, Copy, Debug, Default)]
pub struct OtherCounts {
    pub evidence: u64,
    pub artifact: u64,
    pub issue: u64,
    pub match_: u64,
    pub finding: u64,
}

/// 出力の集計結果。
#[derive(Clone, Copy, Debug, Default)]
pub struct WriteOutcome {
    /// 実際に出力した Event 件数（filter で絞り込んだ場合は store.len() より少ない）。
    pub events_output: u64,
    /// Timeline group 毎の件数（filter 適用前の store 内全集）。
    pub timeline_summary: TimelineSummary,
}

/// Severity の順位（降順用）。critical=5, high=4, medium=3, low=2, informational=1。
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Informational => 1,
    }
}

/// `"key":"escaped string"` を書き込む。
fn write_kv_str(writer: &mut impl Write, key: &str, value: &str) -> std::io::Result<()> {
    // 値は JSON string へ escape する。
    let escaped = serde_json::to_string(value)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "string escape 失敗"))?;
    write!(writer, "\"{key}\":{escaped}")
}

/// `"key":<canonical json>` を書き込む。
fn write_kv_raw(writer: &mut impl Write, key: &str, value: &Value) -> Result<(), OutputError> {
    let canonical =
        to_canonical_string(value).map_err(|e| OutputError::Canonical(e.to_string()))?;
    write!(writer, "\"{key}\":{canonical}").map_err(OutputError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use tf_core::WindowsPathValue;
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
    use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

    fn sample_event(id: &str, dt: DateTime<Utc>) -> tf_core::Event {
        let time = EventTime::utc_instant(
            dt,
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        );
        tf_core::Event {
            id: id.to_string(),
            time,
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: None,
            user: None,
            path: Some(WindowsPathValue::new("C:\\Windows\\notepad.exe")),
            program: None,
            process: None,
            message: String::new(),
            attributes: BTreeMap::new(),
            provenance: Provenance {
                evidence_id: "tf-evidence-v1:t".to_string(),
                artifact_id: "tf-artifact-v1:t".to_string(),
                source_locator: "x.evtx".to_string(),
                source_sha256: "ab".repeat(32),
                parser_id: "p".to_string(),
                parser_version: "1".to_string(),
                record_locator: RecordLocator::SourceOrdinal,
                source_ordinal: 0,
            },
        }
    }

    fn empty_manifest(case_id: &str) -> Manifest {
        Manifest {
            traceforge_version: "0.1.0".to_string(),
            build_commit: "deadbeef".to_string(),
            target: "test".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            compatibility_profile: "tf-compat-v1".to_string(),
            run_started_at: "2026-08-10T00:00:00Z".to_string(),
            run_finished_at: "2026-08-10T00:00:01Z".to_string(),
            resolved_config: serde_json::json!({}),
            resolved_config_sha256: "a".repeat(64),
            case_id: case_id.to_string(),
            counts: ManifestCounts::default(),
            components: vec![],
            rules: vec![],
            attack_dataset: None,
            timezone_assumptions: vec![],
            limits: serde_json::json!({}),
            incomplete_reasons: vec![],
            complete: true,
            exit_code: 0,
        }
    }

    #[test]
    fn write_jsonl_streams_events_in_timeline_order() {
        // Schema §6: event は Timeline 順。store へ逆順で入れても sort されて出る。
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        // 3,2,1 の順で格納（時刻降順）。
        for hour in [3, 2, 1] {
            let dt: DateTime<Utc> = format!("2026-08-10T0{hour}:00:00Z").parse().unwrap();
            let e = sample_event(&format!("tf-event-v1:000{hour}"), dt);
            store.store_event(&e).unwrap();
        }

        let case = CaseMetadata {
            case_id: "tf-case-v1:t".to_string(),
            external_case_id: None,
            name: "test".to_string(),
            analyst: None,
            description: None,
            default_timezone: None,
            tags: vec![],
        };
        let manifest = empty_manifest("tf-case-v1:t");
        let stream = CaseStream {
            case: &case,
            evidence: &[],
            artifacts: &[],
            issues: &[],
            matches: &[],
            findings: &[],
            manifest: &manifest,
        };

        let mut buf: Vec<u8> = Vec::new();
        let outcome = write_jsonl(&store, &stream, 1024 * 1024, None, &mut buf).unwrap();
        assert_eq!(outcome.events_output, 3);

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        // case が先頭、manifest が最終。
        assert!(lines[0].contains("\"record_type\":\"case\""));
        assert!(
            lines
                .last()
                .unwrap()
                .contains("\"record_type\":\"manifest\"")
        );
        // event 行が Timeline 順（時刻昇順 = hour 1, 2, 3）。
        let event_lines: Vec<&str> = lines
            .iter()
            .filter(|l| l.contains("\"record_type\":\"event\""))
            .copied()
            .collect();
        assert_eq!(event_lines.len(), 3);
        assert!(event_lines[0].contains("0001"));
        assert!(event_lines[1].contains("0002"));
        assert!(event_lines[2].contains("0003"));
    }

    #[test]
    fn write_jsonl_filter_reduces_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        for hour in [1, 2, 3] {
            let dt: DateTime<Utc> = format!("2026-08-10T0{hour}:00:00Z").parse().unwrap();
            let mut e = sample_event(&format!("tf-event-v1:000{hour}"), dt);
            if hour == 2 {
                e.event_type = EventType::new("registry_observation");
            } else {
                e.event_type = EventType::new("event_logged");
            }
            store.store_event(&e).unwrap();
        }
        let case = CaseMetadata {
            case_id: "tf-case-v1:t".to_string(),
            name: "t".to_string(),
            ..Default::default()
        };
        let manifest = empty_manifest("tf-case-v1:t");
        let stream = CaseStream {
            case: &case,
            evidence: &[],
            artifacts: &[],
            issues: &[],
            matches: &[],
            findings: &[],
            manifest: &manifest,
        };
        let filter = TimelineFilter {
            event_types: vec!["registry_observation".to_string()],
            ..Default::default()
        };
        let mut buf: Vec<u8> = Vec::new();
        let outcome = write_jsonl(&store, &stream, 1024 * 1024, Some(&filter), &mut buf).unwrap();
        assert_eq!(outcome.events_output, 1, "filter で1件だけ出力される");
    }

    #[test]
    fn manifest_counts_reflect_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        for i in 0..5 {
            let dt: DateTime<Utc> = "2026-08-10T01:00:00Z".parse().unwrap();
            let mut e = sample_event(&format!("tf-event-v1:{i}"), dt);
            e.id = format!("tf-event-v1:{i}");
            store.store_event(&e).unwrap();
        }
        let counts = build_manifest_counts(
            &store,
            &OtherCounts {
                evidence: 2,
                artifact: 3,
                issue: 1,
                match_: 0,
                finding: 0,
            },
        );
        assert_eq!(counts.event, 5);
        assert_eq!(counts.evidence, 2);
        assert_eq!(counts.artifact, 3);
        assert_eq!(counts.issue, 1);
    }

    #[test]
    fn manifest_line_separates_run_metadata() {
        // 規範 §13.1: run metadata は Manifest へ分離。Event 行へは混入しない。
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        let e = sample_event("tf-event-v1:1", "2026-08-10T01:00:00Z".parse().unwrap());
        store.store_event(&e).unwrap();

        let case = CaseMetadata {
            case_id: "tf-case-v1:t".to_string(),
            name: "t".to_string(),
            ..Default::default()
        };
        let manifest = empty_manifest("tf-case-v1:t");
        let stream = CaseStream {
            case: &case,
            evidence: &[],
            artifacts: &[],
            issues: &[],
            matches: &[],
            findings: &[],
            manifest: &manifest,
        };
        let mut buf: Vec<u8> = Vec::new();
        let _ = write_jsonl(&store, &stream, 1024 * 1024, None, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // event 行へ run_started_at 等は出ない。
        let event_line = output
            .lines()
            .find(|l| l.contains("\"record_type\":\"event\""))
            .unwrap();
        assert!(!event_line.contains("run_started_at"));
        // manifest 行へ run_started_at がある。
        let manifest_line = output
            .lines()
            .find(|l| l.contains("\"record_type\":\"manifest\""))
            .unwrap();
        assert!(manifest_line.contains("run_started_at"));
    }
}
