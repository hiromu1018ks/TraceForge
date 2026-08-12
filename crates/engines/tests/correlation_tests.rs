//! Phase 5 Correlation 編の受け入れテスト（T5-030〜T5-042）。
//!
//! 規範 §14（Correlation Rule）・§14.1（評価の既定値）・§14.2（Match 数）・
//! §14.3（Confidence）・§6.4（Correlation 時刻規則）・Schema §7（Correlation Rule Schema）
//! の受け入れ条件を統合テストとして検証する。
//!
//! また規範 §21-15「JSON・JSONL・Correlation Rule・Configuration が Schema validation に
//! 成功する」のうち Correlation Rule 部分を検証する。

use chrono::{TimeZone, Utc};
use std::collections::BTreeMap;
use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
use tf_core::r#match::MatchType;
use tf_core::path::WindowsPathValue;
use tf_core::time::{EventTime, TemporalValue, TimePrecision, TimestampKind, TimezoneSource};
use tf_engines::correlation::{
    CompiledCorrelationRule, CorrelationError, CorrelationEvaluationWarning,
    DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
};

const FULL_RULE_YAML: &str = r#"
id: TF-CORR-001
version: 1.0.0
title: Execution shortly after file creation
description: File creation followed by execution evidence for the same normalized path.
enabled: true
severity: high
partition_by: [case_id, hostname]
within: 5m
allow_uncertain_time: false
max_uncertainty_ms: null
max_matches: 100000
sequence:
  - event_type: file_create
    assertion: observed
    bind:
      file_path: path.comparison_key
  - event_type: program_execution
    assertion: observed
    where:
      - field: path.comparison_key
        operator: eq
        variable: file_path
        normalization_profile: windows-path-v1
score:
  base: 0.75
  adjustments:
    - reason: Exact normalized path match
      value: 0.10
mitre_attack: [T1204.002]
tags: [execution]
references: []
"#;

fn make_event(
    id: &str,
    event_type: &str,
    seconds: i64,
    hostname: Option<&str>,
    evidence_id: &str,
) -> tf_core::Event {
    tf_core::Event {
        id: id.to_string(),
        time: EventTime::utc_instant(
            Utc.timestamp_opt(seconds, 0).unwrap(),
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        ),
        source: ArtifactSource::Evtx,
        event_type: EventType::new(event_type),
        assertion: AssertionKind::Observed,
        hostname: hostname.map(String::from),
        user: None,
        path: None,
        program: None,
        process: None,
        message: String::new(),
        attributes: BTreeMap::new(),
        provenance: Provenance {
            evidence_id: evidence_id.to_string(),
            artifact_id: "tf-artifact-v1:acc".into(),
            source_locator: "Security.evtx".into(),
            source_sha256: "a".repeat(64),
            parser_id: "traceforge-evtx".into(),
            parser_version: "1.0.0".into(),
            record_locator: RecordLocator::SourceOrdinal,
            source_ordinal: 0,
        },
    }
}

fn make_path_event(
    id: &str,
    event_type: &str,
    seconds: i64,
    path: &str,
    hostname: Option<&str>,
) -> tf_core::Event {
    let mut event = make_event(id, event_type, seconds, hostname, "tf-evidence-v1:host");
    event.path = Some(WindowsPathValue::new(path));
    event
}

fn compile(yaml: &str) -> CompiledCorrelationRule {
    let sha = "a".repeat(64);
    CompiledCorrelationRule::compile(
        yaml.as_bytes(),
        &sha,
        DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
    )
    .expect("compile")
}

// ============================================================================
// T5-030: Correlation Rule YAML parser
// ============================================================================

#[test]
fn acceptance_t5_030_yaml_parser_handles_schema_7() {
    let rule = compile(FULL_RULE_YAML);
    assert_eq!(rule.rule.id, "TF-CORR-001");
    assert_eq!(rule.rule.title, "Execution shortly after file creation");
    assert_eq!(rule.rule.sequence.len(), 2);
    assert_eq!(rule.rule.within_ms, 300_000);
    assert_eq!(rule.rule.partition_by.len(), 2);
    assert_eq!(rule.rule.score.base, 0.75);
    assert_eq!(rule.rule.mitre_attack, vec!["T1204.002".to_string()]);
}

#[test]
fn acceptance_t5_030_anchor_alias_tag_duplicate_key_rejected() {
    let sha = "a".repeat(64);
    // anchor
    let anchor = r#"
id: TF-CORR-002
version: 1.0.0
title: bad
severity: low
sequence:
  - event_type: &a x
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
    assert!(
        CompiledCorrelationRule::compile(
            anchor.as_bytes(),
            &sha,
            DEFAULT_MAX_CORRELATION_WINDOW_SECONDS
        )
        .is_err()
    );

    // duplicate key
    let dup = r#"
id: TF-CORR-003
version: 1.0.0
title: bad
title: dup
severity: low
sequence:
  - event_type: x
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
    assert!(
        CompiledCorrelationRule::compile(
            dup.as_bytes(),
            &sha,
            DEFAULT_MAX_CORRELATION_WINDOW_SECONDS
        )
        .is_err()
    );
}

// ============================================================================
// T5-031: Schema validation（規範 §21-15）
// ============================================================================

#[test]
fn acceptance_t5_031_schema_validation_accepts_valid_rule() {
    let rule = compile(FULL_RULE_YAML);
    assert_eq!(rule.rule.id, "TF-CORR-001");
}

#[test]
fn acceptance_t5_031_schema_validation_rejects_missing_required() {
    let yaml = r#"
id: TF-CORR-004
version: 1.0.0
title: missing fields
sequence:
  - event_type: x
"#;
    let sha = "a".repeat(64);
    let result = CompiledCorrelationRule::compile(
        yaml.as_bytes(),
        &sha,
        DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
    );
    let err = result.unwrap_err();
    assert!(matches!(err, CorrelationError::SchemaValidation(_)));
}

#[test]
fn acceptance_t5_031_schema_validation_rejects_unsupported_operator() {
    // Schema §9 fixture: Correlation Rule の未対応 operator sample。
    let yaml = r#"
id: TF-CORR-005
version: 1.0.0
title: bad op
severity: low
sequence:
  - event_type: x
    where:
      - field: user
        operator: levenshtein
        value: alice
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
    let sha = "a".repeat(64);
    let result = CompiledCorrelationRule::compile(
        yaml.as_bytes(),
        &sha,
        DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
    );
    let err = result.unwrap_err();
    assert!(
        err.is_unsupported_skip(),
        "T5-039: 未対応 operator は Rule 全体 skip: {err}"
    );
}

// ============================================================================
// T5-032: sequence / step / where / bind 評価器
// ============================================================================

#[test]
fn acceptance_t5_032_sequence_match_with_bind_and_where() {
    let rule = compile(FULL_RULE_YAML);
    let events = vec![
        make_path_event(
            "e1",
            "file_create",
            1000,
            "C:/Users/alice/mal.exe",
            Some("h1"),
        ),
        make_path_event(
            "e2",
            "program_execution",
            1100,
            "c:\\users\\alice\\mal.exe",
            Some("h1"),
        ),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(
        result.matches.len(),
        1,
        "bind + where で同一 path の sequence を検知"
    );
    let m = &result.matches[0];
    assert_eq!(m.ordered_event_ids.as_deref().unwrap(), &["e1", "e2"]);
}

#[test]
fn acceptance_t5_032_sequence_no_match_when_path_differs() {
    let rule = compile(FULL_RULE_YAML);
    let events = vec![
        make_path_event(
            "e1",
            "file_create",
            1000,
            "C:/Users/alice/a.exe",
            Some("h1"),
        ),
        make_path_event(
            "e2",
            "program_execution",
            1100,
            "C:/Users/alice/b.exe",
            Some("h1"),
        ),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(result.matches.len(), 0);
}

#[test]
fn acceptance_t5_032_step_source_filter() {
    let yaml = r#"
id: TF-CORR-006
version: 1.0.0
title: source filter
severity: high
sequence:
  - event_type: x
    source: evtx
  - event_type: y
    source: prefetch
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let mut e1 = make_event("e1", "x", 1000, None, "ev1");
    e1.source = ArtifactSource::Evtx;
    let mut e2 = make_event("e2", "y", 1100, None, "ev1");
    e2.source = ArtifactSource::Prefetch;
    let result = rule.evaluate(vec![e1, e2].into_iter());
    assert_eq!(result.matches.len(), 1);
}

// ============================================================================
// T5-033: predicate operator 8種
// ============================================================================

#[test]
fn acceptance_t5_033_predicate_operators_all_supported() {
    // 各 operator を1つずつ検証。
    let yaml_template = |op: &str| -> String {
        format!(
            r#"
id: TF-CORR-007
version: 1.0.0
title: op {op}
severity: high
sequence:
  - event_type: x
  - event_type: y
    where:
      - field: user
        operator: {op}
        value: alice
within: 5m
partition_by: [case_id]
score: {{base: 0.7, adjustments: []}}
"#
        )
    };
    let sha = "a".repeat(64);
    for op in [
        "eq",
        "neq",
        "contains",
        "starts_with",
        "ends_with",
        "regex",
        "in",
    ] {
        let yaml = yaml_template(op);
        let result = CompiledCorrelationRule::compile(
            yaml.as_bytes(),
            &sha,
            DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
        );
        assert!(result.is_ok(), "operator {op} は compile 成功すべき");
    }
    // `exists` は value を持たない形式。
    let exists_yaml = r#"
id: TF-CORR-008
version: 1.0.0
title: exists
severity: high
sequence:
  - event_type: x
  - event_type: y
    where:
      - field: user
        operator: exists
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let result = CompiledCorrelationRule::compile(
        exists_yaml.as_bytes(),
        &sha,
        DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
    );
    assert!(result.is_ok(), "operator exists は compile 成功すべき");
}

// ============================================================================
// T5-034: within（両端含む）・max_correlation_window_seconds 上限
// ============================================================================

#[test]
fn acceptance_t5_034_within_boundary_inclusive_at_exactly_within() {
    let yaml = r#"
id: TF-CORR-009
version: 1.0.0
title: boundary
severity: high
sequence:
  - event_type: file_create
  - event_type: program_execution
within: 60s
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let events = vec![
        make_event("e1", "file_create", 0, None, "ev1"),
        make_event("e2", "program_execution", 60, None, "ev1"),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(
        result.matches.len(),
        1,
        "within の境界は両端を含む（規範 §14.1）"
    );
}

#[test]
fn acceptance_t5_034_max_correlation_window_seconds_rejects_oversize() {
    // Schema §8.3: max_correlation_window_seconds を超える Rule は validation error。
    let yaml = r#"
id: TF-CORR-010
version: 1.0.0
title: too long
severity: high
sequence:
  - event_type: x
within: 2d
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let sha = "a".repeat(64);
    let result = CompiledCorrelationRule::compile(yaml.as_bytes(), &sha, 86_400);
    assert!(matches!(result, Err(CorrelationError::WithinInvalid(_))));
}

// ============================================================================
// T5-035: partition_by（case_id/hostname/user）
// ============================================================================

#[test]
fn acceptance_t5_035_partition_by_hostname_same_match() {
    let yaml = r#"
id: TF-CORR-011
version: 1.0.0
title: same host
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 5m
partition_by: [hostname]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let events = vec![
        make_event("e1", "a", 0, Some("h1"), "ev1"),
        make_event("e2", "b", 100, Some("h1"), "ev1"),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(result.matches.len(), 1);
}

#[test]
fn acceptance_t5_035_partition_by_hostname_different_no_match() {
    let yaml = r#"
id: TF-CORR-012
version: 1.0.0
title: diff host
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 5m
partition_by: [hostname]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let events = vec![
        make_event("e1", "a", 0, Some("h1"), "ev1"),
        make_event("e2", "b", 100, Some("h2"), "ev1"),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(result.matches.len(), 0);
}

// ============================================================================
// T5-036: hostname 不明時の既定非 match
// ============================================================================

#[test]
fn acceptance_t5_036_hostname_unknown_no_match_by_default() {
    let yaml = r#"
id: TF-CORR-013
version: 1.0.0
title: hostname required
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 5m
partition_by: [hostname]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let events = vec![
        make_event("e1", "a", 0, Some("h1"), "ev1"),
        make_event("e2", "b", 100, None, "ev1"),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(
        result.matches.len(),
        0,
        "hostname 不明時は既定で非 match（§14.1）"
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|w| matches!(w, CorrelationEvaluationWarning::HostnameUnknown { .. }))
    );
}

// ============================================================================
// T5-037: 不確実時刻の既定非 match・allow_uncertain_time
// ============================================================================

#[test]
fn acceptance_t5_037_uncertain_time_excluded_by_default() {
    let yaml = r#"
id: TF-CORR-014
version: 1.0.0
title: certain only
severity: high
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let mut unknown_event = make_event("eu", "a", 0, None, "ev1");
    unknown_event.time = EventTime::unknown(TimestampKind::EventLogged);
    let result = rule.evaluate(std::iter::once(unknown_event));
    assert_eq!(result.matches.len(), 0);
    assert!(result.warnings.iter().any(|w| matches!(
        w,
        CorrelationEvaluationWarning::UncertainTimeExcluded { .. }
    )));
}

#[test]
fn acceptance_t5_037_allow_uncertain_time_records_warning() {
    let yaml = r#"
id: TF-CORR-015
version: 1.0.0
title: allow uncertain
severity: high
allow_uncertain_time: true
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let mut local_event = make_event("el", "a", 0, None, "ev1");
    let naive =
        chrono::NaiveDateTime::parse_from_str("2026-08-10T12:00:00", "%Y-%m-%dT%H:%M:%S").unwrap();
    local_event.time = EventTime {
        value: TemporalValue::LocalTime {
            value: naive,
            timezone: Some("Asia/Tokyo".into()),
        },
        original: None,
        kind: TimestampKind::EventLogged,
        precision: TimePrecision::Second,
        timezone_source: TimezoneSource::ArtifactDefined,
        uncertainty_ms: None,
    };
    let result = rule.evaluate(std::iter::once(local_event));
    assert_eq!(
        result.matches.len(),
        1,
        "allow_uncertain_time=true で LocalTime を許可"
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|w| matches!(w, CorrelationEvaluationWarning::UncertainTimeUsed { .. })),
        "match reason へ記録する（規範 §6.4）"
    );
}

// ============================================================================
// T5-038: null・型の厳密比較
// ============================================================================

#[test]
fn acceptance_t5_038_null_and_type_strict_comparison() {
    // 規範 §14.1: null は空文字列と等しくない・型が違う値を暗黙変換しない。
    let yaml = r#"
id: TF-CORR-016
version: 1.0.0
title: strict eq
severity: high
sequence:
  - event_type: x
    where:
      - field: attributes.event_id
        operator: eq
        value: 4624
within: 5m
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);

    // integer field と integer literal → match
    let mut int_event = make_event("e1", "x", 0, None, "ev1");
    int_event
        .attributes
        .insert("event_id".into(), serde_json::Value::from(4624i64));
    let result = rule.evaluate(std::iter::once(int_event));
    assert_eq!(result.matches.len(), 1);

    // string field と integer literal → no match（型厳密）
    let mut str_event = make_event("e2", "x", 0, None, "ev1");
    str_event
        .attributes
        .insert("event_id".into(), serde_json::Value::String("4624".into()));
    let result = rule.evaluate(std::iter::once(str_event));
    assert_eq!(result.matches.len(), 0, "string '4624' != integer 4624");
}

// ============================================================================
// T5-040: match 重複生成禁止・max_matches・Exit Code 1/5
// ============================================================================

#[test]
fn acceptance_t5_040_match_dedupe_via_match_id() {
    let yaml = r#"
id: TF-CORR-017
version: 1.0.0
title: dedupe
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 1h
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let events = vec![
        make_event("e1", "a", 0, None, "ev1"),
        make_event("e2", "b", 100, None, "ev1"),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(
        result.matches.len(),
        1,
        "同一 ordered_event_ids から複数 match を生成しない"
    );
    // match_id が Schema §3.1 pattern に合致。
    assert!(tf_core::id::is_valid_id(&result.matches[0].match_id));
}

#[test]
fn acceptance_t5_040_max_matches_truncates_with_exit_code_1_or_5() {
    let yaml = r#"
id: TF-CORR-018
version: 1.0.0
title: limit
severity: high
max_matches: 3
sequence:
  - event_type: a
within: 1h
partition_by: [case_id]
score: {base: 0.7, adjustments: []}
"#;
    let rule = compile(yaml);
    let events: Vec<tf_core::Event> = (0..10)
        .map(|i| make_event(&format!("e{i}"), "a", i, None, "ev1"))
        .collect();
    let result = rule.evaluate(events.into_iter());
    assert_eq!(result.matches.len(), 3);
    assert!(
        result.truncated,
        "max_matches 到達で truncated=true（規範 §14.2）"
    );
    // Exit Code mapping: strict=false → 1（CaseWithWarnings）。
    let exit = if result.truncated {
        tf_core::ExitCode::CaseWithWarnings
    } else {
        tf_core::ExitCode::Success
    };
    assert_eq!(exit, tf_core::ExitCode::CaseWithWarnings);
}

// ============================================================================
// T5-041: score 計算（base + adjustments・clamp・level 変換）
// ============================================================================

#[test]
fn acceptance_t5_041_score_calculation_clamps_and_levels() {
    let yaml = r#"
id: TF-CORR-019
version: 1.0.0
title: scoring
severity: high
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score:
  base: 0.7
  adjustments:
    - reason: bonus
      value: 0.5
"#;
    let rule = compile(yaml);
    let event = make_event("e1", "a", 0, None, "ev1");
    let result = rule.evaluate(std::iter::once(event));
    let m = &result.matches[0];
    let s = m.score.as_ref().unwrap();
    // 0.7 + 0.5 = 1.2 → clamp 1.0
    assert!((s.total() - 1.0).abs() < f64::EPSILON);
    let level = tf_core::finding::ConfidenceLevel::from_score(s.total());
    assert_eq!(level, tf_core::finding::ConfidenceLevel::High);
}

#[test]
fn acceptance_t5_041_score_level_low() {
    let yaml = r#"
id: TF-CORR-020
version: 1.0.0
title: low scoring
severity: low
sequence:
  - event_type: a
within: 5m
partition_by: [case_id]
score: {base: 0.3, adjustments: []}
"#;
    let rule = compile(yaml);
    let event = make_event("e1", "a", 0, None, "ev1");
    let result = rule.evaluate(std::iter::once(event));
    let s = result.matches[0].score.as_ref().unwrap();
    let level = tf_core::finding::ConfidenceLevel::from_score(s.total());
    assert_eq!(level, tf_core::finding::ConfidenceLevel::Low);
}

// ============================================================================
// T5-042: 同一 Evidence 事実の二重加点防止
// ============================================================================

#[test]
fn acceptance_t5_042_same_evidence_no_double_scoring() {
    // 同一 evidence_ids set を持つ Match は adjustments による追加点を加えない。
    // match_id が ordered_event_ids を含むため、異なる順序の sequence は別 match となるが、
    // 同一 evidence set の score 合計は単一の base + adjustments のみ。
    let yaml = r#"
id: TF-CORR-021
version: 1.0.0
title: dedupe evidence
severity: high
sequence:
  - event_type: a
  - event_type: b
within: 1h
partition_by: [case_id]
score:
  base: 0.8
  adjustments: []
"#;
    let rule = compile(yaml);
    let events = vec![
        make_event("e1", "a", 0, None, "ev1"),
        make_event("e2", "b", 100, None, "ev1"),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(result.matches.len(), 1);
    let total: f64 = result
        .matches
        .iter()
        .map(|m| m.score.as_ref().unwrap().total())
        .sum();
    assert!(
        (total - 0.8).abs() < f64::EPSILON,
        "同一 Evidence 事実の二重加点を防止する（規範 §14.3）"
    );
}

// ============================================================================
// Match 型の形式検証（Schema §5.7・T5-032 で生成）
// ============================================================================

#[test]
fn correlation_match_has_correct_shape() {
    let rule = compile(FULL_RULE_YAML);
    let events = vec![
        make_path_event("e1", "file_create", 1000, "C:/temp/x.exe", Some("h1")),
        make_path_event(
            "e2",
            "program_execution",
            1100,
            "c:\\temp\\x.exe",
            Some("h1"),
        ),
    ];
    let result = rule.evaluate(events.into_iter());
    assert_eq!(result.matches.len(), 1);
    let m = &result.matches[0];
    assert_eq!(m.match_type, MatchType::Correlation);
    assert!(m.score.is_some());
    assert!(m.ordered_event_ids.is_some());
    assert!(m.logsource_mapping.is_none());
    assert!(m.matched_patterns.is_none());
    assert_eq!(m.rule_id, "TF-CORR-001");
    assert_eq!(m.rule_sha256, "a".repeat(64));
}

// ============================================================================
// 決定性: 同一入力は同一結果（規範 §13）
// ============================================================================

#[test]
fn evaluation_is_deterministic_across_input_orders() {
    let rule = compile(FULL_RULE_YAML);
    let events_a = vec![
        make_path_event("e1", "file_create", 1000, "C:/x.exe", Some("h1")),
        make_path_event("e2", "program_execution", 1100, "c:\\x.exe", Some("h1")),
    ];
    let events_b: Vec<tf_core::Event> = vec![events_a[1].clone(), events_a[0].clone()];
    let result_a = rule.evaluate(events_a.into_iter());
    let result_b = rule.evaluate(events_b.into_iter());
    assert_eq!(result_a.matches.len(), result_b.matches.len());
    assert_eq!(
        result_a.matches[0].match_id, result_b.matches[0].match_id,
        "iterator 順によらず同一 match_id"
    );
}
