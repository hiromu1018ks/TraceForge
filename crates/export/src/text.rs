//! Text exporter（規範 §19.1・T7-001）。
//!
//! 人が CLI で確認するための Text 形式。Evidence 起源の C0/C1 制御文字と ESC を
//! 可視 escape へ変換する（規範 §19.1・terminal ESC injection 対策・規範 §21-11）。
//!
//! 出力は UTF-8・LF。解析結果は stdout、log は stderr（規範 §19.1）。
//! `quiet` は log を抑制するだけで、解析結果（本 exporter への出力）を抑制しない。

use std::io::Write;

use tf_core::case::Severity;

use crate::case_data::CaseData;
use crate::error::ExportError;
use crate::sanitize::escape_control_chars;

/// Case 全体を Text 形式で `writer` へ出力する。
///
/// 出力構成:
/// 1. Case metadata
/// 2. Evidence 一覧（evidence_id 昇順）
/// 3. Artifact 一覧（artifact_id 昇順）
/// 4. Event timeline（Timeline 順・規範 §6.3）
/// 5. Issue 一覧（規範 §9.3 順）
/// 6. Match 一覧（match_id 昇順）
/// 7. Finding 一覧（Severity 降順・finding_id 昇順）
/// 8. Manifest summary
///
/// 全ての Evidence 起源文字列へ [`escape_control_chars`] を適用する。
pub fn write_text(data: &CaseData, writer: &mut impl Write) -> Result<(), ExportError> {
    let views = data.sorted_views();
    let mut out: Vec<u8> = Vec::new();

    // header
    writeln!(out, "TraceForge Case Report")?;
    writeln!(out, "======================")?;
    writeln!(out, "case_id: {}", escape_control_chars(&data.case.case_id))?;
    writeln!(out, "name: {}", escape_control_chars(&data.case.name))?;
    if let Some(ext) = &data.case.external_case_id {
        writeln!(out, "external_case_id: {}", escape_control_chars(ext))?;
    }
    if let Some(analyst) = &data.case.analyst {
        writeln!(out, "analyst: {}", escape_control_chars(analyst))?;
    }
    if let Some(desc) = &data.case.description {
        writeln!(out, "description: {}", escape_control_chars(desc))?;
    }
    if let Some(tz) = &data.case.default_timezone {
        writeln!(out, "default_timezone: {}", escape_control_chars(tz))?;
    }
    if !data.case.tags.is_empty() {
        writeln!(
            out,
            "tags: {}",
            escape_control_chars(&data.case.tags.join(", "))
        )?;
    }
    writeln!(out)?;

    // Evidence
    writeln!(out, "Evidence ({})", views.evidence.len())?;
    writeln!(out, "--------------------")?;
    for e in &views.evidence {
        writeln!(
            out,
            "- {} ({}): size={}, sha256={}, integrity={}, parse_eligible={}",
            escape_control_chars(&e.evidence_id),
            escape_control_chars(&e.source_locator),
            e.size,
            escape_control_chars(&e.sha256),
            e.integrity_status.as_str(),
            e.parse_eligible,
        )?;
    }
    writeln!(out)?;

    // Artifacts
    writeln!(out, "Artifacts ({})", views.artifacts.len())?;
    writeln!(out, "----------------------")?;
    for a in &views.artifacts {
        writeln!(
            out,
            "- {} evidence={} type={} parser={}@{} probe={} status={}",
            escape_control_chars(&a.artifact_id),
            escape_control_chars(&a.evidence_id),
            a.artifact_type.as_str(),
            escape_control_chars(&a.parser_id),
            escape_control_chars(&a.parser_version),
            a.probe_result.as_str(),
            a.parse_status.as_str(),
        )?;
    }
    writeln!(out)?;

    // Events (Timeline 順)
    writeln!(out, "Events ({})", views.events.len())?;
    writeln!(out, "----------------")?;
    for ev in &views.events {
        write_event(&mut out, ev)?;
    }
    writeln!(out)?;

    // Issues
    writeln!(out, "Issues ({})", views.issues.len())?;
    writeln!(out, "---------------")?;
    for i in &views.issues {
        writeln!(
            out,
            "- [{}] {} (scope={}, severity={}) {}",
            escape_control_chars(&i.issue_id),
            i.scope.as_str(),
            escape_control_chars(i.evidence_id.as_deref().unwrap_or("-")),
            i.severity.as_str(),
            escape_control_chars(&i.message),
        )?;
    }
    writeln!(out)?;

    // Matches
    writeln!(out, "Matches ({})", views.matches.len())?;
    writeln!(out, "-----------------")?;
    for m in &views.matches {
        writeln!(
            out,
            "- {} type={} rule={} events={} reasons={}",
            escape_control_chars(&m.match_id),
            m.match_type.as_str(),
            escape_control_chars(&m.rule_id),
            m.event_ids.len(),
            escape_control_chars(&m.reasons.join("; ")),
        )?;
    }
    writeln!(out)?;

    // Findings
    writeln!(out, "Findings ({})", views.findings.len())?;
    writeln!(out, "------------------")?;
    for f in &views.findings {
        writeln!(
            out,
            "- [{}] {} (severity={}, confidence={:.2} {})",
            escape_control_chars(&f.finding_id),
            escape_control_chars(&f.title),
            f.severity.as_str(),
            f.confidence.score,
            f.confidence.level.as_str(),
        )?;
        if !f.event_ids.is_empty() {
            writeln!(out, "  events: {}", f.event_ids.join(", "))?;
        }
        if !f.attack_mappings.is_empty() {
            let techniques: Vec<String> = f
                .attack_mappings
                .iter()
                .map(|m| {
                    let name = m
                        .technique_name
                        .as_deref()
                        .map(|n| format!(":{n}"))
                        .unwrap_or_default();
                    format!("{}{}", m.technique_id, name)
                })
                .collect();
            writeln!(out, "  ATT&CK: {}", techniques.join(", "))?;
        }
    }
    writeln!(out)?;

    // Manifest summary
    writeln!(out, "Manifest Summary")?;
    writeln!(out, "----------------")?;
    writeln!(
        out,
        "traceforge_version: {}",
        escape_control_chars(&data.manifest.traceforge_version)
    )?;
    writeln!(out, "schema_version: {}", data.manifest.schema_version)?;
    writeln!(
        out,
        "compatibility_profile: {}",
        escape_control_chars(&data.manifest.compatibility_profile)
    )?;
    writeln!(
        out,
        "run_started_at: {}",
        escape_control_chars(&data.manifest.run_started_at)
    )?;
    writeln!(
        out,
        "run_finished_at: {}",
        escape_control_chars(&data.manifest.run_finished_at)
    )?;
    writeln!(
        out,
        "case_id: {}",
        escape_control_chars(&data.manifest.case_id)
    )?;
    writeln!(
        out,
        "counts: evidence={} artifact={} event={} issue={} match={} finding={}",
        data.manifest.counts.evidence,
        data.manifest.counts.artifact,
        data.manifest.counts.event,
        data.manifest.counts.issue,
        data.manifest.counts.r#match,
        data.manifest.counts.finding,
    )?;
    writeln!(out, "complete: {}", data.manifest.complete)?;
    writeln!(out, "exit_code: {}", data.manifest.exit_code)?;
    if !data.manifest.incomplete_reasons.is_empty() {
        writeln!(
            out,
            "incomplete_reasons: {}",
            data.manifest.incomplete_reasons.join(", ")
        )?;
    }

    writer.write_all(&out)?;
    Ok(())
}

/// 1件の Event を Text 形式へ出力する（規範 §19.1: 制御文字 escape 適用済み）。
fn write_event(out: &mut Vec<u8>, ev: &tf_core::event::Event) -> Result<(), ExportError> {
    let time_str = format_event_time(&ev.time);
    writeln!(
        out,
        "- [{}] {} type={} source={} assertion={}",
        escape_control_chars(&ev.id),
        time_str,
        escape_control_chars(ev.event_type.as_str()),
        ev.source.as_str(),
        ev.assertion.as_str(),
    )?;
    if let Some(host) = &ev.hostname {
        writeln!(out, "  hostname: {}", escape_control_chars(host))?;
    }
    if let Some(user) = &ev.user {
        writeln!(out, "  user: {}", escape_control_chars(user))?;
    }
    if let Some(path) = &ev.path {
        writeln!(out, "  path: {}", escape_control_chars(&path.original))?;
    }
    if let Some(prog) = &ev.program {
        writeln!(out, "  program: {}", escape_control_chars(prog))?;
    }
    if !ev.message.is_empty() {
        writeln!(out, "  message: {}", escape_control_chars(&ev.message))?;
    }
    Ok(())
}

/// EventTime を Text 出力用の文字列へ変換する。
fn format_event_time(time: &tf_core::time::EventTime) -> String {
    use tf_core::time::TemporalValue;
    match &time.value {
        TemporalValue::UtcInstant { value } => tf_core::time::format_utc_z(value),
        TemporalValue::LocalTime { value, timezone } => {
            let base = tf_core::time::naive_to_string(value);
            match timezone {
                Some(tz) => format!("{base} ({tz})"),
                None => format!("{base} (timezone unknown)"),
            }
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
            format!("range {s} .. {e}")
        }
        TemporalValue::Unknown => "unknown time".to_string(),
    }
}

/// Case 全体を Text 文字列へ直列化する（テスト・小規模 Case 用）。
pub fn to_text_string(data: &CaseData) -> Result<String, ExportError> {
    let mut buf: Vec<u8> = Vec::new();
    write_text(data, &mut buf)?;
    String::from_utf8(buf).map_err(|e| ExportError::Canonical(format!("UTF-8 変換失敗: {e}")))
}

/// Finding severity を sort 用ランクへ変換する（外部 test から参照できるよう公開）。
pub fn severity_sort_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Informational => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_core::case::CaseMetadata;
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

    #[test]
    fn text_output_has_case_header() {
        let data = empty_data();
        let s = to_text_string(&data).unwrap();
        assert!(s.contains("TraceForge Case Report"));
        assert!(s.contains("case_id: tf-case-v1:x"));
    }

    #[test]
    fn text_output_has_manifest_summary() {
        let data = empty_data();
        let s = to_text_string(&data).unwrap();
        assert!(s.contains("Manifest Summary"));
        assert!(s.contains("exit_code: 0"));
    }

    #[test]
    fn text_escapes_terminal_control_chars_in_case_name() {
        // 規範 §19.1: ESC や制御文字を可視 escape へ。
        let mut data = empty_data();
        data.case.name = "injection\x1B[2Jtest".into();
        let s = to_text_string(&data).unwrap();
        // ESC 文字は直接現れない。
        assert!(!s.contains('\x1B'));
        // ^[ へ置換される。
        assert!(s.contains("^["));
    }
}
