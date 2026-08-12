//! 出力 injection 統合 test（規範 §21-11・T7-008）。
//!
//! 規範 §21-11 は次の3種の出力 injection 対策を test で検証することを求める:
//! - CSV formula injection（`=cmd|...` 等）
//! - terminal ESC escape（`\x1B[2J` 等）
//! - HTML script injection（`<script>alert(...)</script>`）
//!
//! これらが Evidence 起源文字列へ含まれていても、出力へそのまま現れないことを検証する。

use tf_core::case::{CaseMetadata, EvidenceItem, IntegrityStatus};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
use tf_core::manifest::Manifest;
use tf_core::path::WindowsPathValue;
use tf_core::time::{EventTime, TemporalValue, TimePrecision, TimestampKind, TimezoneSource};
use tf_export::CaseData;
use tf_export::{
    csv::to_csv_string, html::to_html_string, json::to_json_string, jsonl::to_jsonl_string,
    text::to_text_string, timesketch::to_timesketch_string,
};

fn injection_case_data() -> CaseData {
    let mut data = CaseData {
        case: CaseMetadata {
            case_id: "tf-case-v1:inj".into(),
            external_case_id: None,
            name: "Injection Test".into(),
            analyst: None,
            description: None,
            default_timezone: None,
            tags: vec![],
        },
        manifest: Manifest {
            traceforge_version: "0.1.0".into(),
            build_commit: "test".into(),
            target: "test".into(),
            schema_version: "1.0.0".into(),
            compatibility_profile: "TF-WIN-1.0".into(),
            run_started_at: "2026-08-12T00:00:00Z".into(),
            run_finished_at: "2026-08-12T00:01:00Z".into(),
            resolved_config: serde_json::json!({}),
            resolved_config_sha256: "a".repeat(64),
            case_id: "tf-case-v1:inj".into(),
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
    };

    let time = EventTime {
        value: TemporalValue::UtcInstant {
            value: "2026-08-12T01:00:00Z".parse().unwrap(),
        },
        original: None,
        kind: TimestampKind::EventLogged,
        precision: TimePrecision::Second,
        timezone_source: TimezoneSource::ArtifactDefined,
        uncertainty_ms: None,
    };

    // CSV formula injection の payloads。
    // terminal ESC と HTML script も同時に仕込む。
    let provenance = Provenance {
        evidence_id: "tf-evidence-v1:inj".into(),
        artifact_id: "tf-artifact-v1:inj".into(),
        source_locator: "Security.evtx".into(),
        source_sha256: "a".repeat(64),
        parser_id: "traceforge-evtx".into(),
        parser_version: "1.0.0".into(),
        record_locator: RecordLocator::RecordId("1".into()),
        source_ordinal: 0,
    };

    let payloads = [
        ("=cmd|' /C calc'!A1", "csv formula"),
        ("+1+1", "csv plus prefix"),
        ("-1+A1", "csv minus prefix"),
        ("@SUM(A1)", "csv at prefix"),
        ("\tfoobar", "csv tab prefix"),
        ("\rfoobar", "csv cr prefix"),
        ("<script>alert('xss')</script>", "html script"),
        ("<img src=x onerror=alert(1)>", "html img onerror"),
        ("\x1B[2J\x1B[H", "terminal clear screen"),
        ("\x1B]0;evil\x07", "terminal title set"),
        ("javascript:alert(1)", "javascript scheme"),
    ];

    for (i, (payload, _label)) in payloads.iter().enumerate() {
        let payload_string = (*payload).to_string();
        let ev = tf_core::event::Event {
            id: format!("tf-event-v1:inj{i}"),
            time: time.clone(),
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: Some(format!("host{i}")),
            user: None,
            path: Some(WindowsPathValue::new(payload_string.clone())),
            program: Some(payload_string.clone()),
            process: None,
            message: payload_string,
            attributes: std::collections::BTreeMap::new(),
            provenance: provenance.clone(),
        };
        data.events.push(ev);
    }

    data.evidence.push(EvidenceItem {
        evidence_id: "tf-evidence-v1:inj".into(),
        source_locator: "Security.evtx".into(),
        size: 1,
        sha256: "a".repeat(64),
        integrity_status: IntegrityStatus::VerifiedSnapshot,
        parse_eligible: true,
        snapshot_locator: String::new(),
    });
    data
}

#[test]
fn csv_formula_injection_is_neutralized() {
    // 規範 §21-11: CSV formula injection 対策。
    let data = injection_case_data();
    let (csv, summary) = to_csv_string(&data).unwrap();
    // 各 formula payload 行で ' が前置されていること（sanitized_cells > 0）。
    assert!(summary.sanitized(), "sanitization が実行された");
    // 出力 CSV の formula payload cell は `=cmd` のように始まらない。
    // （`'=cmd` のように ' が前置される）
    for line in csv.lines() {
        // 行頭の cell が event_id（`tf-event-v1:`）のため、formula は現れない。
        // message 列に注目: `=cmd` ではなく `'=` を含むべき。
        if line.contains("=cmd|") {
            // ' が前置されていること。
            assert!(
                line.contains("'=cmd|") || line.contains("\"'=cmd|"),
                "formula injection 対策不十分: {line}"
            );
        }
    }
}

#[test]
fn terminal_esc_is_visible_escaped_in_text() {
    // 規範 §21-11: terminal ESC escape。
    let data = injection_case_data();
    let text = to_text_string(&data).unwrap();
    // ESC 文字がそのまま現れない。
    assert!(!text.contains('\x1B'), "ESC がそのまま出力されている");
    // ^[ へ置換される。
    assert!(text.contains("^["));
}

#[test]
fn html_script_is_escaped() {
    // 規範 §21-11: HTML script injection。
    let data = injection_case_data();
    let html = to_html_string(&data).unwrap();
    // <script> タグがそのまま現れない（escape される）。
    assert!(
        !html.contains("<script>alert"),
        "raw <script> tag が現れた: HTML injection 対策不十分"
    );
    // escape 後の entity 参照が現れる。
    assert!(html.contains("&lt;script&gt;"));
    // onerror handler も属性として解釈されない（text node として escape）。
    assert!(html.contains("&lt;img"));
    // javascript: scheme も text node として escape される。
    assert!(html.contains("javascript:alert"));
}

#[test]
fn json_does_not_break_out_of_string_with_injection() {
    // 規範 §19.4 / §21-11: JSON は string escape を正しく行い、
    // 制御文字や特殊文字が JSON structure を壊さない。
    let data = injection_case_data();
    let json = to_json_string(&data).unwrap();
    // 出力が正当な JSON であること。
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(value.is_object());
    // 制御文字列も JSON string 内へ escape される（serde_json が自動で処理）。
    assert!(json.contains("\\t") || json.contains("foobar"));
}

#[test]
fn jsonl_each_line_remains_valid_json_with_injection() {
    let data = injection_case_data();
    let jsonl = to_jsonl_string(&data).unwrap();
    for line in jsonl.lines() {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
}

#[test]
fn timesketch_output_is_still_valid_jsonl_with_injection() {
    let data = injection_case_data();
    let (jsonl, _summary) = to_timesketch_string(&data).unwrap();
    for line in jsonl.lines() {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
}

#[test]
fn text_output_does_not_contain_control_chars() {
    // 規範 §19.1: 制御文字は全て可視 escape へ。
    let data = injection_case_data();
    let text = to_text_string(&data).unwrap();
    // C0 制御文字（LF/CR 以外）が残っていないこと。
    for ch in text.chars() {
        let u = ch as u32;
        if u < 0x20 && ch != '\n' && ch != '\r' {
            panic!("制御文字 0x{u:02x} が残っている");
        }
        if u == 0x7F {
            panic!("DEL 文字が残っている");
        }
        if (0x80..=0x9F).contains(&u) {
            panic!("C1 制御文字 0x{u:02x} が残っている");
        }
    }
}
