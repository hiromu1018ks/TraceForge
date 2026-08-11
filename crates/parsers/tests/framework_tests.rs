//! Parser framework の統合テスト（T4-001〜T4-007、規範 §9）。
//!
//! これらのテストは framework が規範 §9 の契約を満たすことを検証する。
//! LNK Parser 固有の検証は `lnk_tests.rs`・`acceptance_tests.rs` へ。

use std::collections::BTreeMap;
use std::io::Cursor;

use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};
use tf_parsers::framework::{
    ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek, SinkError,
    run_parser_catching_panic,
};
use tf_parsers::issue::{
    MISSING_REQUIRED_FIELD_CODE, PANIC_FATAL_CODE, PARTIAL_RECORD_BOUNDARY_CODE,
    TRUNCATED_RECORD_CODE, sanitize_issue_message,
};

/// Event・Issue を蓄積するテスト用 sink。
struct CollectorSink {
    events: Vec<tf_core::event::Event>,
    issues: Vec<tf_core::issue::Issue>,
}

impl CollectorSink {
    fn new() -> Self {
        CollectorSink {
            events: Vec::new(),
            issues: Vec::new(),
        }
    }
}

impl ParseSink for CollectorSink {
    fn emit_event(&mut self, event: tf_core::event::Event) -> Result<(), SinkError> {
        self.events.push(event);
        Ok(())
    }
    fn emit_issue(&mut self, issue: tf_core::issue::Issue) -> Result<(), SinkError> {
        self.issues.push(issue);
        Ok(())
    }
}

/// テスト用 context。
fn sample_context() -> ParseContext {
    ParseContext {
        evidence: EvidenceItem {
            evidence_id: "tf-evidence-v1:framework-test".to_string(),
            source_locator: "sample.bin".to_string(),
            size: 0,
            sha256: "ab".repeat(32),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        },
        artifact: ArtifactInstance {
            artifact_id: "tf-artifact-v1:framework-test".to_string(),
            evidence_id: "tf-evidence-v1:framework-test".to_string(),
            artifact_type: ArtifactSource::Unknown,
            parser_id: "traceforge-test".to_string(),
            parser_version: "1.0.0".to_string(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["test".to_string()],
            parse_status: ParseStatus::Complete,
        },
    }
}

/// テスト用 Event を作る。
fn make_event(context: &ParseContext, ordinal: u64, source_ordinal: u64) -> tf_core::event::Event {
    let mut event = tf_core::event::Event {
        id: String::new(),
        time: EventTime::utc_instant(
            "2026-08-10T01:00:00Z".parse().unwrap(),
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        ),
        source: ArtifactSource::Unknown,
        event_type: EventType::new("test_record"),
        assertion: AssertionKind::Observed,
        hostname: None,
        user: None,
        path: None,
        program: None,
        process: None,
        message: format!("record {source_ordinal}"),
        attributes: BTreeMap::new(),
        provenance: context.make_provenance(RecordLocator::SourceOrdinal, source_ordinal),
    };
    event.id = event.compute_id(ordinal);
    event
}

// ============================================================
// T4-001: ArtifactParser trait + ParseSink（sink 型 interface）
// ============================================================

/// 1000 Event を1件ずつ stream する Parser。`Vec` で返さないことの表明。
struct ThousandEventsParser;

impl ArtifactParser for ThousandEventsParser {
    fn parser_id(&self) -> &'static str {
        "traceforge-test-thousand"
    }
    fn parser_version(&self) -> &'static str {
        "1.0.0"
    }
    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Unknown
    }
    fn probe(&self, _evidence: &EvidenceItem) -> ProbeResult {
        ProbeResult::Confirmed
    }
    fn parse(
        &self,
        _snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary {
        // 規範 §21-6: 100万 Event でも Vec を要求しない。ここでは 1000 で検証。
        for source_ordinal in 0..1000u64 {
            let event = make_event(context, source_ordinal, source_ordinal);
            if sink.emit_event(event).is_err() {
                return ParseSummary::partial(source_ordinal, source_ordinal, 0);
            }
        }
        ParseSummary::complete(1000, 1000, 0)
    }
}

#[test]
fn t4_001_sink_interface_streams_events_without_vec() {
    // 規範 §9.1・§21-6: Parser は全 Event を Vec で返さない。
    let parser = ThousandEventsParser;
    let mut cursor = Cursor::new(Vec::new());
    let context = sample_context();
    let mut sink = CollectorSink::new();

    let summary = parser.parse(&mut cursor, &context, &mut sink);

    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(summary.events_emitted, 1000);
    assert_eq!(sink.events.len(), 1000);
    // 全 Event ID が一意。
    let mut ids: Vec<&str> = sink.events.iter().map(|e| e.id.as_str()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 1000, "Event ID は全て一意であるべき");
}

// ============================================================
// T4-002: ParseSummary / ParseStatus
// ============================================================

#[test]
fn t4_002_parse_summary_status_variants() {
    // 規範 §9.2: Complete/Partial/Skipped/Failed の各 status。
    let complete = ParseSummary::complete(3, 3, 0);
    assert_eq!(complete.status, ParseStatus::Complete);

    let partial = ParseSummary::partial(5, 3, 2);
    assert_eq!(partial.status, ParseStatus::Partial);
    assert_eq!(partial.events_emitted, 3);
    assert_eq!(partial.issues_emitted, 2);

    let skipped = ParseSummary::skipped();
    assert_eq!(skipped.status, ParseStatus::Skipped);

    let failed = ParseSummary::failed();
    assert_eq!(failed.status, ParseStatus::Failed);

    // Default は Skipped。
    assert_eq!(ParseSummary::default().status, ParseStatus::Skipped);
}

// ============================================================
// T4-003: record 破損時の部分成功（生成済み Event 破棄禁止）
// ============================================================

/// record stream で中間 record が破損。前後の record の Event を生成し、破損は Issue。
struct PartialRecoveryParser {
    /// 各 record の状態。true = 正常、false = 破損。
    records: Vec<bool>,
}

impl ArtifactParser for PartialRecoveryParser {
    fn parser_id(&self) -> &'static str {
        "traceforge-test-partial"
    }
    fn parser_version(&self) -> &'static str {
        "1.0.0"
    }
    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Unknown
    }
    fn probe(&self, _evidence: &EvidenceItem) -> ProbeResult {
        ProbeResult::Confirmed
    }
    fn parse(
        &self,
        _snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary {
        let mut events_emitted = 0u64;
        let mut issues_emitted = 0u64;
        for (i, &ok) in self.records.iter().enumerate() {
            let source_ordinal = i as u64;
            if ok {
                let event = make_event(context, source_ordinal, source_ordinal);
                if sink.emit_event(event).is_err() {
                    return ParseSummary::partial(i as u64, events_emitted, issues_emitted);
                }
                events_emitted += 1;
            } else {
                // 破損 record は Issue 化。
                let issue = tf_core::issue::Issue {
                    issue_id: TRUNCATED_RECORD_CODE.to_string(),
                    severity: tf_core::issue::IssueSeverity::Warning,
                    scope: tf_core::issue::IssueScope::Record,
                    evidence_id: Some(context.evidence.evidence_id.clone()),
                    artifact_id: Some(context.artifact.artifact_id.clone()),
                    record_locator: Some(RecordLocator::SourceOrdinal),
                    source_ordinal: Some(source_ordinal),
                    message: format!("record {i} は破損"),
                };
                if sink.emit_issue(issue).is_err() {
                    return ParseSummary::partial(i as u64, events_emitted, issues_emitted);
                }
                issues_emitted += 1;
            }
        }
        // 1件でも破損があれば Partial。
        let status = if issues_emitted > 0 {
            ParseStatus::Partial
        } else {
            ParseStatus::Complete
        };
        ParseSummary {
            status,
            records_seen: self.records.len() as u64,
            events_emitted,
            issues_emitted,
            bytes_consumed: 0,
        }
    }
}

#[test]
fn t4_003_partial_success_preserves_emitted_events() {
    // 規範 §9.2: 1 record の破損は Issue として出力し、次 record の境界を安全に特定
    // できる場合だけ継続する。生成済み Event を破棄してはならない。
    let parser = PartialRecoveryParser {
        records: vec![true, false, true, true, false, true],
    };
    let mut cursor = Cursor::new(Vec::new());
    let context = sample_context();
    let mut sink = CollectorSink::new();

    let summary = parser.parse(&mut cursor, &context, &mut sink);

    // 4 Event（破損以外）と 2 Issue（破損）。
    assert_eq!(summary.status, ParseStatus::Partial);
    assert_eq!(sink.events.len(), 4);
    assert_eq!(sink.issues.len(), 2);
    // 生成済み Event は破棄されない（sink へ残る）。
    assert_eq!(summary.events_emitted, 4);
    assert_eq!(summary.issues_emitted, 2);
}

// ============================================================
// T4-004: Parse Issue 仕様（安定 code・sanitize・出力順）
// ============================================================

#[test]
fn t4_004_issue_codes_are_stable_and_documented() {
    // 規範 §9.3: 安定した code。
    assert_eq!(PANIC_FATAL_CODE, "TF-F-PARSER-PANIC");
    assert_eq!(
        MISSING_REQUIRED_FIELD_CODE,
        "TF-W-PARSER-MISSING-REQUIRED-FIELD"
    );
    assert_eq!(TRUNCATED_RECORD_CODE, "TF-W-PARSER-TRUNCATED-RECORD");
    assert_eq!(PARTIAL_RECORD_BOUNDARY_CODE, "TF-R-PARSER-PARTIAL-BOUNDARY");
}

#[test]
fn t4_004_sanitize_removes_control_chars_and_truncates() {
    // 規範 §9.3: message へ Evidence の巨大値・未 escape 制御文字を含めない。
    let with_ctrl = sanitize_issue_message("bad\x1b[2J value\n");
    assert!(!with_ctrl.contains('\x1b'));
    assert!(with_ctrl.contains("\\x1b"));

    let huge = "A".repeat(10_000);
    let truncated = sanitize_issue_message(&huge);
    assert!(truncated.len() < huge.len());
    assert!(truncated.ends_with("...(truncated)"));
}

#[test]
fn t4_004_issue_output_order_follows_spec() {
    // 規範 §9.3: 同一 Issue の出力順は evidence_id → artifact_id → source_ordinal → code の順。
    let mut issues: Vec<tf_core::issue::Issue> = vec![
        tf_core::issue::Issue {
            issue_id: "TF-W-BBB".into(),
            severity: tf_core::issue::IssueSeverity::Warning,
            scope: tf_core::issue::IssueScope::Record,
            evidence_id: Some("tf-evidence-v1:a".into()),
            artifact_id: Some("tf-artifact-v1:x".into()),
            record_locator: None,
            source_ordinal: Some(5),
            message: "z".into(),
        },
        tf_core::issue::Issue {
            issue_id: "TF-W-AAA".into(),
            severity: tf_core::issue::IssueSeverity::Warning,
            scope: tf_core::issue::IssueScope::Record,
            evidence_id: Some("tf-evidence-v1:a".into()),
            artifact_id: Some("tf-artifact-v1:x".into()),
            record_locator: None,
            source_ordinal: Some(5),
            message: "z".into(),
        },
        tf_core::issue::Issue {
            issue_id: "TF-W-AAA".into(),
            severity: tf_core::issue::IssueSeverity::Warning,
            scope: tf_core::issue::IssueScope::Record,
            evidence_id: Some("tf-evidence-v1:a".into()),
            artifact_id: Some("tf-artifact-v1:x".into()),
            record_locator: None,
            source_ordinal: Some(2),
            message: "z".into(),
        },
    ];
    issues.sort_by(|a, b| {
        a.evidence_id
            .cmp(&b.evidence_id)
            .then_with(|| a.artifact_id.cmp(&b.artifact_id))
            .then_with(|| a.source_ordinal.cmp(&b.source_ordinal))
            .then_with(|| a.issue_id.cmp(&b.issue_id))
    });
    // 期待順: source_ordinal 2 (AAA) → 5 (AAA) → 5 (BBB)。
    assert_eq!(issues[0].source_ordinal, Some(2));
    assert_eq!(issues[0].issue_id, "TF-W-AAA");
    assert_eq!(issues[1].source_ordinal, Some(5));
    assert_eq!(issues[1].issue_id, "TF-W-AAA");
    assert_eq!(issues[2].issue_id, "TF-W-BBB");
}

// ============================================================
// T4-005: panic 捕捉 → Fatal 記録 → Exit Code 10
// ============================================================

struct PanickingParser;

impl ArtifactParser for PanickingParser {
    fn parser_id(&self) -> &'static str {
        "traceforge-test-panic"
    }
    fn parser_version(&self) -> &'static str {
        "1.0.0"
    }
    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Unknown
    }
    fn probe(&self, _evidence: &EvidenceItem) -> ProbeResult {
        ProbeResult::Confirmed
    }
    fn parse(
        &self,
        _snapshot: &mut dyn ReadSeek,
        _context: &ParseContext,
        _sink: &mut dyn ParseSink,
    ) -> ParseSummary {
        panic!("意図的な panic（T4-005 テスト）");
    }
}

#[test]
fn t4_005_parser_panic_is_caught_and_becomes_fatal() {
    // 規範 §9.4: panic は Fatal issue + Failed summary。Exit Code 10 は上位が集計。
    let parser = PanickingParser;
    let mut cursor = Cursor::new(Vec::new());
    let context = sample_context();
    let mut sink = CollectorSink::new();

    let summary = run_parser_catching_panic(&parser, &mut cursor, &context, &mut sink);

    assert_eq!(summary.status, ParseStatus::Failed);
    assert_eq!(sink.issues.len(), 1);
    let issue = &sink.issues[0];
    assert_eq!(issue.issue_id, PANIC_FATAL_CODE);
    assert_eq!(issue.severity, tf_core::issue::IssueSeverity::Fatal);
    assert!(issue.message.contains("traceforge-test-panic"));
    assert!(issue.message.contains("意図的な panic"));
    // Fatal issue の Exit Code は 10（規範 §17.2）。severity から推論可能。
    assert_eq!(tf_core::ExitCode::FatalInternalError.as_process_code(), 10);
}

// ============================================================
// T4-006: 破損中間 record 前後の部分 Event 保持（規範 §21-5）
// ============================================================

#[test]
fn t4_006_partial_events_preserved_around_corrupt_record() {
    // 規範 §21-5: 破損した中間 record の前後で、安全な境界がある場合に部分 Event を保持する。
    let parser = PartialRecoveryParser {
        records: vec![true, true, false, true, true],
    };
    let mut cursor = Cursor::new(Vec::new());
    let context = sample_context();
    let mut sink = CollectorSink::new();

    let summary = parser.parse(&mut cursor, &context, &mut sink);

    assert_eq!(summary.status, ParseStatus::Partial);
    // 前後の4 Event が保持される。中間の破損（index 2）は Issue。
    assert_eq!(sink.events.len(), 4);
    assert_eq!(sink.issues.len(), 1);
    assert_eq!(sink.issues[0].source_ordinal, Some(2));
    // Event の source_ordinal は 0, 1, 3, 4。
    let mut ords: Vec<u64> = sink
        .events
        .iter()
        .map(|e| e.provenance.source_ordinal)
        .collect();
    ords.sort();
    assert_eq!(ords, vec![0, 1, 3, 4]);
}

// ============================================================
// T4-007: 必須 field 欠落 record は Event 化せず Issue 化（互換 §5）
// ============================================================

/// record が必須 field を持つか。`missing_field` が true の record は Event 化せず Issue 化。
struct RequiredFieldParser {
    missing_field: Vec<bool>,
}

impl ArtifactParser for RequiredFieldParser {
    fn parser_id(&self) -> &'static str {
        "traceforge-test-required"
    }
    fn parser_version(&self) -> &'static str {
        "1.0.0"
    }
    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Unknown
    }
    fn probe(&self, _evidence: &EvidenceItem) -> ProbeResult {
        ProbeResult::Confirmed
    }
    fn parse(
        &self,
        _snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary {
        let mut events_emitted = 0u64;
        let mut issues_emitted = 0u64;
        for (i, &missing) in self.missing_field.iter().enumerate() {
            let source_ordinal = i as u64;
            if missing {
                // 必須 field 欠落: Event 化せず Issue 化（互換 §5）。
                let issue = tf_core::issue::Issue {
                    issue_id: MISSING_REQUIRED_FIELD_CODE.to_string(),
                    severity: tf_core::issue::IssueSeverity::Warning,
                    scope: tf_core::issue::IssueScope::Record,
                    evidence_id: Some(context.evidence.evidence_id.clone()),
                    artifact_id: Some(context.artifact.artifact_id.clone()),
                    record_locator: Some(RecordLocator::SourceOrdinal),
                    source_ordinal: Some(source_ordinal),
                    message: format!("record {i} は必須 field 欠落"),
                };
                if sink.emit_issue(issue).is_err() {
                    return ParseSummary::partial(i as u64, events_emitted, issues_emitted);
                }
                issues_emitted += 1;
            } else {
                let event = make_event(context, source_ordinal, source_ordinal);
                if sink.emit_event(event).is_err() {
                    return ParseSummary::partial(i as u64, events_emitted, issues_emitted);
                }
                events_emitted += 1;
            }
        }
        let status = if issues_emitted > 0 {
            ParseStatus::Partial
        } else {
            ParseStatus::Complete
        };
        ParseSummary {
            status,
            records_seen: self.missing_field.len() as u64,
            events_emitted,
            issues_emitted,
            bytes_consumed: 0,
        }
    }
}

#[test]
fn t4_007_missing_required_field_becomes_issue_not_event() {
    // 互換 §5: 必須 field を形式上取得できない record は Event 化せず、Parse Issue を生成する。
    let parser = RequiredFieldParser {
        missing_field: vec![false, true, false],
    };
    let mut cursor = Cursor::new(Vec::new());
    let context = sample_context();
    let mut sink = CollectorSink::new();

    let summary = parser.parse(&mut cursor, &context, &mut sink);

    assert_eq!(summary.status, ParseStatus::Partial);
    // record 1（必須 field 欠落）は Event にならず Issue。
    assert_eq!(sink.events.len(), 2);
    assert_eq!(sink.issues.len(), 1);
    assert_eq!(sink.issues[0].issue_id, MISSING_REQUIRED_FIELD_CODE);
    assert_eq!(sink.issues[0].source_ordinal, Some(1));
    // Event の source_ordinal は 0, 2。
    let mut ords: Vec<u64> = sink
        .events
        .iter()
        .map(|e| e.provenance.source_ordinal)
        .collect();
    ords.sort();
    assert_eq!(ords, vec![0, 2]);
}
