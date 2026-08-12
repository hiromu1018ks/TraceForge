//! HTML exporter（規範 §19.3・T7-005）。
//!
//! 全ての Evidence 起源文字列を text node として escape する（規範 §19.3）。
//! Content Security Policy を埋め込み、script は static local content のみを許可する。
//! 外部通信を行わない・`innerHTML` 連結はしない・外部 CDN を使用しない。
//!
//! 出力は UTF-8・LF。完全に offline で開ける単一 HTML file とする。
//
// `write!` を `writeln!` へ置き換えると format string 中の `\n` と引数末尾の `\n` が
// 重複してしまうため、本 module では `write!` + 明示 `\n` を許容する。
#![allow(clippy::write_with_newline)]

use std::io::Write;

use tf_core::jsonl::SCHEMA_VERSION;

use crate::case_data::CaseData;
use crate::error::ExportError;
use crate::sanitize::{escape_control_chars, html_attribute_escape, html_text_escape};

/// HTML 出力へ埋め込む CSP（規範 §19.3）。
///
/// - `default-src 'none'`: 全て既定で拒否
/// - `style-src 'unsafe-inline'`: inline style のみ許可（offline で表示を整えるため）
/// - `script-src 'none'`: script は完全禁止
/// - `img-src 'none'`: 画像読込も禁止
/// - `connect-src 'none'`: 外部通信完全禁止
/// - `base-uri 'none'`: `<base>` 要素の書き換え禁止
/// - `form-action 'none'`: form 送信禁止
pub const HTML_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'";

/// Case 全体を offline HTML として `writer` へ出力する（規範 §19.3）。
///
/// 全ての Evidence 起源文字列へ [`html_text_escape`] または
/// [`html_attribute_escape`] を適用する。外部依存（CDN・画像・font・script）を一切持たない。
pub fn write_html(data: &CaseData, writer: &mut impl Write) -> Result<(), ExportError> {
    let views = data.sorted_views();
    let mut out: Vec<u8> = Vec::new();

    // DOCTYPE + html
    out.extend_from_slice(b"<!DOCTYPE html>\n");
    out.extend_from_slice(b"<html lang=\"ja\">\n");
    out.extend_from_slice(b"<head>\n");
    out.extend_from_slice(b"<meta charset=\"utf-8\">\n");
    // CSP（規範 §19.3）。CSP 値は埋め込み定数であり Evidence 起源ではないため、
    // HTML escape しない（escape すると `'none'` が `&#39;none&#39;` になり CSP が効かない）。
    write!(
        out,
        "<meta http-equiv=\"Content-Security-Policy\" content=\"{}\">\n",
        HTML_CSP
    )?;
    write!(
        out,
        "<meta name=\"generator\" content=\"traceforge {}\">\n",
        html_attribute_escape(&data.manifest.traceforge_version)
    )?;
    write!(
        out,
        "<title>TraceForge Case Report - {}</title>\n",
        html_text_escape(&data.case.name)
    )?;
    out.extend_from_slice(b"<style>\n");
    write_embedded_css(&mut out)?;
    out.extend_from_slice(b"</style>\n");
    out.extend_from_slice(b"</head>\n");
    out.extend_from_slice(b"<body>\n");

    // Case header
    out.extend_from_slice(b"<header>\n");
    write!(
        out,
        "<h1>TraceForge Case Report</h1>\n<p class=\"case-id\">case_id: <code>{}</code></p>\n",
        html_text_escape(&data.case.case_id)
    )?;
    write!(out, "<p>name: {}</p>\n", html_text_escape(&data.case.name))?;
    if let Some(analyst) = &data.case.analyst {
        write!(out, "<p>analyst: {}</p>\n", html_text_escape(analyst))?;
    }
    if let Some(desc) = &data.case.description {
        write!(out, "<p>description: {}</p>\n", html_text_escape(desc))?;
    }
    out.extend_from_slice(b"</header>\n");

    // Evidence section
    write!(
        out,
        "<section id=\"evidence\">\n<h2>Evidence ({})</h2>\n<table>\n",
        views.evidence.len()
    )?;
    out.extend_from_slice(b"<thead><tr><th>evidence_id</th><th>source_locator</th><th>size</th><th>sha256</th><th>integrity</th></tr></thead>\n");
    out.extend_from_slice(b"<tbody>\n");
    for e in &views.evidence {
        write!(
            out,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>\n",
            html_text_escape(&e.evidence_id),
            html_text_escape(&e.source_locator),
            e.size,
            html_text_escape(&e.sha256),
            html_text_escape(e.integrity_status.as_str()),
        )?;
    }
    out.extend_from_slice(b"</tbody>\n</table>\n</section>\n");

    // Events section
    write!(
        out,
        "<section id=\"events\">\n<h2>Events ({})</h2>\n<table>\n",
        views.events.len()
    )?;
    out.extend_from_slice(b"<thead><tr><th>event_id</th><th>time</th><th>event_type</th><th>hostname</th><th>path</th><th>message</th></tr></thead>\n");
    out.extend_from_slice(b"<tbody>\n");
    for ev in &views.events {
        let time_str = format_event_time(&ev.time);
        let path = ev
            .path
            .as_ref()
            .map(|p| html_text_escape(&p.original))
            .unwrap_or_default();
        let message = if ev.message.is_empty() {
            String::new()
        } else {
            html_text_escape(&escape_control_chars(&ev.message))
        };
        write!(
            out,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            html_text_escape(&ev.id),
            html_text_escape(&time_str),
            html_text_escape(ev.event_type.as_str()),
            html_text_escape(ev.hostname.as_deref().unwrap_or("")),
            path,
            message,
        )?;
    }
    out.extend_from_slice(b"</tbody>\n</table>\n</section>\n");

    // Findings section
    write!(
        out,
        "<section id=\"findings\">\n<h2>Findings ({})</h2>\n<ul>\n",
        views.findings.len()
    )?;
    for f in &views.findings {
        write!(
            out,
            "<li><strong>[{}]</strong> <span class=\"severity severity-{}\">{}</span> {}<br><small>confidence {:.2} ({})</small>\n",
            html_text_escape(&f.finding_id),
            f.severity.as_str(),
            f.severity.as_str(),
            html_text_escape(&f.title),
            f.confidence.score,
            f.confidence.level.as_str(),
        )?;
        if !f.attack_mappings.is_empty() {
            let techniques: Vec<String> = f
                .attack_mappings
                .iter()
                .map(|m| {
                    let name = m
                        .technique_name
                        .as_deref()
                        .map(|n| format!(": {}", html_text_escape(n)))
                        .unwrap_or_default();
                    format!("<code>{}</code>{}", html_text_escape(&m.technique_id), name)
                })
                .collect();
            write!(
                out,
                "<div class=\"attack\">ATT&CK: {}</div>\n",
                techniques.join(", ")
            )?;
        }
        out.extend_from_slice(b"</li>\n");
    }
    out.extend_from_slice(b"</ul>\n</section>\n");

    // Manifest section
    out.extend_from_slice(b"<section id=\"manifest\">\n<h2>Manifest Summary</h2>\n");
    write!(
        out,
        "<p>schema_version: <code>{}</code></p>\n",
        html_text_escape(&data.manifest.schema_version)
    )?;
    write!(
        out,
        "<p>compatibility_profile: <code>{}</code></p>\n",
        html_text_escape(&data.manifest.compatibility_profile)
    )?;
    write!(
        out,
        "<p>case_id: <code>{}</code></p>\n",
        html_text_escape(&data.manifest.case_id)
    )?;
    write!(
        out,
        "<p>counts: evidence={}, artifact={}, event={}, issue={}, match={}, finding={}</p>\n",
        data.manifest.counts.evidence,
        data.manifest.counts.artifact,
        data.manifest.counts.event,
        data.manifest.counts.issue,
        data.manifest.counts.r#match,
        data.manifest.counts.finding,
    )?;
    write!(
        out,
        "<p>complete: <strong>{}</strong> exit_code: {}</p>\n",
        data.manifest.complete, data.manifest.exit_code,
    )?;
    if !data.manifest.incomplete_reasons.is_empty() {
        let reasons: Vec<String> = data
            .manifest
            .incomplete_reasons
            .iter()
            .map(|r| html_text_escape(r))
            .collect();
        write!(out, "<p>incomplete_reasons: {}</p>\n", reasons.join(", "))?;
    }
    out.extend_from_slice(b"</section>\n");

    out.extend_from_slice(b"<footer>\n<p>Generated by TraceForge</p>\n</footer>\n");
    out.extend_from_slice(b"</body>\n</html>\n");

    writer.write_all(&out)?;
    Ok(())
}

/// 埋め込み CSS を書き込む（offline・外部 CDN 不使用・規範 §19.3）。
fn write_embedded_css(out: &mut Vec<u8>) -> Result<(), ExportError> {
    let css = r#"body { font-family: sans-serif; margin: 1em; color: #111; background: #fff; }
h1 { font-size: 1.4em; border-bottom: 2px solid #333; padding-bottom: 0.2em; }
h2 { font-size: 1.1em; margin-top: 1.5em; border-left: 4px solid #2a6; padding-left: 0.4em; }
table { border-collapse: collapse; width: 100%; margin: 0.5em 0; }
th, td { border: 1px solid #999; padding: 0.2em 0.4em; text-align: left; vertical-align: top; }
th { background: #eee; }
code { background: #f4f4f4; padding: 0.05em 0.2em; font-family: monospace; word-break: break-all; }
.severity-critical { color: #b00; font-weight: bold; }
.severity-high { color: #c33; }
.severity-medium { color: #c70; }
.severity-low { color: #369; }
.severity-informational { color: #777; }
.attack { margin-top: 0.2em; font-size: 0.9em; }
footer { margin-top: 2em; border-top: 1px solid #ccc; padding-top: 0.4em; color: #666; font-size: 0.85em; }
"#;
    out.extend_from_slice(css.as_bytes());
    Ok(())
}

/// EventTime を HTML text node 用文字列へ変換する。
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
            format!("{s} .. {e}")
        }
        TemporalValue::Unknown => "unknown".to_string(),
    }
}

/// Case 全体を HTML 文字列へ直列化する（テスト用）。
pub fn to_html_string(data: &CaseData) -> Result<String, ExportError> {
    let mut buf: Vec<u8> = Vec::new();
    write_html(data, &mut buf)?;
    String::from_utf8(buf).map_err(|e| ExportError::Canonical(format!("UTF-8 変換失敗: {e}")))
}

/// HTML が CSP header を持つか（テスト用 helper）。
pub fn has_csp(html: &str) -> bool {
    html.contains("Content-Security-Policy") && html.contains(HTML_CSP)
}

/// 現行の Schema version。
pub fn schema_version() -> &'static str {
    SCHEMA_VERSION
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
    fn html_has_csp_meta_tag() {
        let data = empty_data();
        let html = to_html_string(&data).unwrap();
        assert!(has_csp(&html));
        assert!(html.contains("script-src 'none'"));
    }

    #[test]
    fn html_escapes_script_tag_in_case_name() {
        // 規範 §19.3 / §21-11: <script> を text node として escape。
        let mut data = empty_data();
        data.case.name = "<script>alert('xss')</script>".into();
        let html = to_html_string(&data).unwrap();
        assert!(!html.contains("<script>alert"), "raw script tag が無いこと");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_has_no_external_resource_references() {
        let data = empty_data();
        let html = to_html_string(&data).unwrap();
        assert!(!html.contains("https://"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("src=\""));
        assert!(!html.contains("<link"));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn html_uses_lf_only() {
        let data = empty_data();
        let html = to_html_string(&data).unwrap();
        assert!(!html.contains("\r\n"));
    }
}
