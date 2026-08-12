//! CLI の runtime 共通 helper（規範 §19.1・§20）。
//!
//! - [`RunContext`] は log を蓄積し、`--quiet` の有無で出力を制御する
//! - [`read_case_from_path`] は Case JSON / JSONL file から [`tf_export::CaseData`] を読み込む
//! - [`write_output`] は stdout と file への書き分けと入出力分離を担う

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tf_core::case::CaseMetadata;
use tf_core::error::ExitCode;
use tf_core::event::Event;
use tf_core::finding::Finding;
use tf_core::issue::Issue;
use tf_core::r#match::Match;
use tf_export::CaseData;

use crate::args::GlobalArgs;

/// 1つの command 実行の runtime context。
///
/// log は [`RunContext::log`] で蓄積し、最終的に stderr へ出力する。
/// `--quiet` が設定されている場合でも、解析結果（stdout）は抑制しない（規範 §19.1）。
pub struct RunContext {
    /// 蓄積された log 出力（stderr 行）。
    pub stderr: String,
    pub quiet: bool,
}

impl RunContext {
    pub fn new(global: GlobalArgs) -> Self {
        RunContext {
            stderr: String::new(),
            quiet: global.quiet,
        }
    }

    /// log を1行追加する。`--quiet` の場合でも蓄積する（最終出力時に抑制するだけ）。
    pub fn log(&mut self, message: impl AsRef<str>) {
        if !self.stderr.is_empty() {
            self.stderr.push('\n');
        }
        self.stderr.push_str(message.as_ref());
    }

    /// warning を追加し、[`ExitCode::CaseWithWarnings`] を返す（規範 §17.2）。
    pub fn warn(&mut self, message: impl AsRef<str>) -> ExitCode {
        self.log(format!("warning: {}", message.as_ref()));
        ExitCode::CaseWithWarnings
    }
}
/// Case JSON または JSONL file から [`CaseData`] を読み込む。
///
/// 拡張子または内容から自動判別する。`.json` は Case JSON（Schema §5.1）、
/// `.jsonl` は JSONL envelope（Schema §6）として扱う。
pub fn read_case_from_path(path: &Path) -> Result<CaseData, CaseReadError> {
    let bytes =
        fs::read(path).map_err(|e| CaseReadError::Io(format!("{}: {e}", path.display())))?;
    let content = String::from_utf8(bytes)
        .map_err(|e| CaseReadError::Io(format!("UTF-8 では無い: {}: {e}", path.display())))?;

    if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
        parse_jsonl_case(&content)
    } else {
        parse_case_json(&content)
    }
}

/// Case JSON（Schema §5.1）を parse する。
pub fn parse_case_json(content: &str) -> Result<CaseData, CaseReadError> {
    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| CaseReadError::InvalidJson(format!("Case JSON parse: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| CaseReadError::InvalidJson("top-level が object ではない".into()))?;

    // Schema major version 検証（互換 §10）。
    let schema_version = obj
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or(CaseReadError::MissingField("schema_version"))?;
    tf_core::schema::check_major_version(schema_version, tf_core::schema::SCHEMA_MAJOR)
        .map_err(|e| CaseReadError::Schema(e.to_string()))?;

    let case = parse_case_metadata(obj.get("case"))?;
    let evidence = parse_evidence_list(obj.get("evidence"))?;
    let artifacts = parse_artifact_list(obj.get("artifacts"))?;
    let events = parse_event_list(obj.get("events"))?;
    let issues = parse_issue_list(obj.get("issues"))?;
    let matches = parse_match_list(obj.get("matches"))?;
    let findings = parse_finding_list(obj.get("findings"))?;
    let manifest = parse_manifest(obj.get("manifest"))?;

    Ok(CaseData {
        case,
        evidence,
        artifacts,
        events,
        issues,
        matches,
        findings,
        manifest,
    })
}

/// JSONL（Schema §6）を parse して CaseData を再構築する。
pub fn parse_jsonl_case(content: &str) -> Result<CaseData, CaseReadError> {
    let mut data = CaseData::default();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = tf_core::jsonl::JsonlRecord::parse(line)
            .map_err(|e| CaseReadError::InvalidJson(format!("line {}: {e}", i + 1)))?;
        match record.record_type.as_str() {
            "case" => data.case = parse_case_metadata(Some(&record.record))?,
            "evidence" => data.evidence.push(parse_evidence_value(&record.record)?),
            "artifact" => data.artifacts.push(parse_artifact_value(&record.record)?),
            "event" => data.events.push(parse_event_value(&record.record)?),
            "issue" => data.issues.push(parse_issue_value(&record.record)?),
            "match" => data.matches.push(parse_match_value(&record.record)?),
            "finding" => data.findings.push(parse_finding_value(&record.record)?),
            "manifest" => data.manifest = parse_manifest_value(&record.record)?,
            other => {
                return Err(CaseReadError::InvalidJson(format!(
                    "未知の record_type: {other}"
                )));
            }
        }
    }
    Ok(data)
}

/// Case file 読込 error。
#[derive(Debug, thiserror::Error)]
pub enum CaseReadError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("無効な JSON: {0}")]
    InvalidJson(String),
    #[error("必須 field 欠落: {0}")]
    MissingField(&'static str),
    #[error("Schema error: {0}")]
    Schema(String),
    #[error("parse error: {0}")]
    Parse(String),
}

impl CaseReadError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            CaseReadError::Io(_) => ExitCode::InputOrDiscoveryError,
            CaseReadError::Schema(_) => ExitCode::OutputOrSafetyError,
            _ => ExitCode::CliOrConfigError,
        }
    }
}

/// 出力先へ bytes を書き込む。`output` が [`None`] の場合は stdout への書き出しを行わない。
///
/// stdout 出力は呼出側が [`CliResult::stdout`](crate::CliResult::stdout) へ内容を設定し、
/// [`main`](crate)#stdout への書き出しは `main.rs` で1回だけ行う（規範 §19.1）。
/// ここで stdout へ直接書き出すと `main.rs` での再出力により二重出力となるため、
/// `None` の場合は何もしない（呼出側が別途 `bytes` から stdout 文字列を構築する）。
///
/// 規範 §5.4: 既定で上書き禁止。`output` が既存 file の場合は error とする。
pub fn write_output(
    output: Option<&Path>,
    overwrite: bool,
    bytes: &[u8],
) -> Result<(), OutputWriteError> {
    match output {
        None => {
            let _ = (bytes, overwrite);
            Ok(())
        }
        Some(path) => {
            if path.exists() && !overwrite {
                return Err(OutputWriteError::AlreadyExists(path.to_path_buf()));
            }
            // 親 directory の存在確認。
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && !parent.exists()
            {
                return Err(OutputWriteError::ParentMissing(parent.to_path_buf()));
            }
            fs::write(path, bytes)?;
            Ok(())
        }
    }
}

/// 出力書き込み error。
#[derive(Debug, thiserror::Error)]
pub enum OutputWriteError {
    #[error("出力 file が既に存在する（--overwrite が必要）: {0}")]
    AlreadyExists(PathBuf),
    #[error("親 directory が存在しない: {0}")]
    ParentMissing(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl OutputWriteError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            OutputWriteError::AlreadyExists(_) | OutputWriteError::ParentMissing(_) => {
                ExitCode::OutputOrSafetyError
            }
            OutputWriteError::Io(_) => ExitCode::OutputOrSafetyError,
        }
    }
}

// ============================================================================
// JSON → 強型 復元 helper（最小実装・必要な field のみ）
// ============================================================================

fn parse_case_metadata(value: Option<&serde_json::Value>) -> Result<CaseMetadata, CaseReadError> {
    let v = value.ok_or(CaseReadError::MissingField("case"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("case が object ではない".into()))?;
    Ok(CaseMetadata {
        case_id: get_str(obj, "case_id")?,
        external_case_id: get_opt_str(obj, "external_case_id"),
        name: get_str(obj, "name")?,
        analyst: get_opt_str(obj, "analyst"),
        description: get_opt_str(obj, "description"),
        default_timezone: get_opt_str(obj, "default_timezone"),
        tags: get_str_list(obj, "tags"),
    })
}

fn parse_evidence_list(
    value: Option<&serde_json::Value>,
) -> Result<Vec<tf_core::case::EvidenceItem>, CaseReadError> {
    let arr = value
        .and_then(|v| v.as_array())
        .ok_or(CaseReadError::MissingField("evidence"))?;
    arr.iter().map(parse_evidence_value).collect()
}

fn parse_evidence_value(
    v: &serde_json::Value,
) -> Result<tf_core::case::EvidenceItem, CaseReadError> {
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("evidence が object ではない".into()))?;
    let integrity_str = get_str(obj, "integrity_status")?;
    let integrity = tf_core::case::IntegrityStatus::from_schema_str(&integrity_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の integrity_status: {integrity_str}")))?;
    Ok(tf_core::case::EvidenceItem {
        evidence_id: get_str(obj, "evidence_id")?,
        source_locator: get_str(obj, "source_locator")?,
        size: get_u64(obj, "size")?,
        sha256: get_str(obj, "sha256")?,
        integrity_status: integrity,
        parse_eligible: get_bool(obj, "parse_eligible")?,
        snapshot_locator: String::new(),
    })
}

fn parse_artifact_list(
    value: Option<&serde_json::Value>,
) -> Result<Vec<tf_core::case::ArtifactInstance>, CaseReadError> {
    let arr = value
        .and_then(|v| v.as_array())
        .ok_or(CaseReadError::MissingField("artifacts"))?;
    arr.iter().map(parse_artifact_value).collect()
}

fn parse_artifact_value(
    v: &serde_json::Value,
) -> Result<tf_core::case::ArtifactInstance, CaseReadError> {
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("artifact が object ではない".into()))?;
    let type_str = get_str(obj, "artifact_type")?;
    let artifact_type = tf_core::event::ArtifactSource::from_schema_str(&type_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の artifact_type: {type_str}")))?;
    let probe_str = get_str(obj, "probe_result")?;
    let probe = tf_core::case::ProbeResult::from_schema_str(&probe_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の probe_result: {probe_str}")))?;
    let parse_str = get_str(obj, "parse_status")?;
    let parse_status = tf_core::case::ParseStatus::from_schema_str(&parse_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の parse_status: {parse_str}")))?;
    Ok(tf_core::case::ArtifactInstance {
        artifact_id: get_str(obj, "artifact_id")?,
        evidence_id: get_str(obj, "evidence_id")?,
        artifact_type,
        parser_id: get_str(obj, "parser_id")?,
        parser_version: get_str(obj, "parser_version")?,
        probe_result: probe,
        detection_reasons: get_str_list(obj, "detection_reasons"),
        parse_status,
    })
}

fn parse_event_list(value: Option<&serde_json::Value>) -> Result<Vec<Event>, CaseReadError> {
    let arr = value
        .and_then(|v| v.as_array())
        .ok_or(CaseReadError::MissingField("events"))?;
    arr.iter().map(parse_event_value).collect()
}

fn parse_event_value(v: &serde_json::Value) -> Result<Event, CaseReadError> {
    // Event の完全復元は tf-store の decoder と同等の処理が必要。
    // Phase 7 では最小限の field を復元する（完全復元は Phase 8 で再利用する）。
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("event が object ではない".into()))?;
    let id = get_str(obj, "event_id")?;
    let time = parse_event_time(obj.get("time"))?;
    let source_str = get_str(obj, "source")?;
    let source = tf_core::event::ArtifactSource::from_schema_str(&source_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の source: {source_str}")))?;
    let event_type = tf_core::event::EventType::new(get_str(obj, "event_type")?);
    let assertion_str = get_str(obj, "assertion")?;
    let assertion = tf_core::event::AssertionKind::from_schema_str(&assertion_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の assertion: {assertion_str}")))?;
    let hostname = get_opt_str(obj, "hostname");
    let user = get_opt_str(obj, "user");
    let path = obj
        .get("path")
        .filter(|v| v.is_object())
        .map(parse_windows_path);
    let program = get_opt_str(obj, "program");
    let process = obj
        .get("process")
        .filter(|v| v.is_object())
        .map(parse_process_ref);
    let message = get_str(obj, "message").unwrap_or_default();
    let attributes = parse_attributes(obj.get("attributes"));
    let provenance = parse_provenance(obj.get("provenance"))?;

    Ok(Event {
        id,
        time,
        source,
        event_type,
        assertion,
        hostname,
        user,
        path,
        program,
        process,
        message,
        attributes,
        provenance,
    })
}

fn parse_event_time(
    value: Option<&serde_json::Value>,
) -> Result<tf_core::time::EventTime, CaseReadError> {
    let v = value.ok_or(CaseReadError::MissingField("time"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("time が object ではない".into()))?;
    let type_str = get_str(obj, "type")?;
    let kind_str = get_str(obj, "kind")?;
    let kind = tf_core::time::TimestampKind::from_schema_str(&kind_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の kind: {kind_str}")))?;
    let precision_str = get_str(obj, "precision")?;
    let precision = tf_core::time::TimePrecision::from_schema_str(&precision_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の precision: {precision_str}")))?;
    let tz_source_str = get_str(obj, "timezone_source")?;
    let timezone_source = tf_core::time::TimezoneSource::from_schema_str(&tz_source_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の timezone_source: {tz_source_str}")))?;
    let original = get_opt_str(obj, "original");
    let uncertainty_ms = obj.get("uncertainty_ms").and_then(|v| v.as_u64());

    let value = match type_str.as_str() {
        "utc_instant" => {
            let s = obj
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CaseReadError::Parse("utc_instant に value が無い".into()))?;
            let dt: chrono::DateTime<chrono::Utc> = s
                .parse()
                .map_err(|e| CaseReadError::Parse(format!("UTC timestamp parse: {e}")))?;
            tf_core::time::TemporalValue::UtcInstant { value: dt }
        }
        "local_time" => {
            let s = obj
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CaseReadError::Parse("local_time に value が無い".into()))?;
            let tz = get_opt_str(obj, "timezone");
            let naive: chrono::NaiveDateTime = s
                .parse()
                .map_err(|e| CaseReadError::Parse(format!("NaiveDateTime parse: {e}")))?;
            tf_core::time::TemporalValue::LocalTime {
                value: naive,
                timezone: tz,
            }
        }
        "range" => {
            let parse_opt =
                |key: &str| -> Result<Option<chrono::DateTime<chrono::Utc>>, CaseReadError> {
                    match obj.get(key).and_then(|v| v.as_str()) {
                        Some(s) => {
                            let dt: chrono::DateTime<chrono::Utc> = s.parse().map_err(|e| {
                                CaseReadError::Parse(format!("range {key} parse: {e}"))
                            })?;
                            Ok(Some(dt))
                        }
                        None => Ok(None),
                    }
                };
            let start = parse_opt("start")?;
            let end = parse_opt("end")?;
            tf_core::time::TemporalValue::Range { start, end }
        }
        "unknown" => tf_core::time::TemporalValue::Unknown,
        other => return Err(CaseReadError::Parse(format!("未知の time type: {other}"))),
    };

    Ok(tf_core::time::EventTime {
        value,
        original,
        kind,
        precision,
        timezone_source,
        uncertainty_ms,
    })
}

fn parse_windows_path(v: &serde_json::Value) -> tf_core::WindowsPathValue {
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            return tf_core::WindowsPathValue::new("");
        }
    };
    let original = obj
        .get("original")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let comparison_key = obj
        .get("comparison_key")
        .and_then(|v| v.as_str())
        .map(String::from);
    let normalization_profile = obj
        .get("normalization_profile")
        .and_then(|v| v.as_str())
        .unwrap_or("windows-path-v1")
        .to_string();
    let normalization_notes = obj
        .get("normalization_notes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    tf_core::WindowsPathValue {
        original,
        comparison_key,
        normalization_profile,
        normalization_notes,
    }
}

fn parse_process_ref(v: &serde_json::Value) -> tf_core::event::ProcessRef {
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            return tf_core::event::ProcessRef {
                pid: None,
                ppid: None,
                process_guid: None,
                parent_process_guid: None,
                image_path: None,
                command_line: None,
            };
        }
    };
    tf_core::event::ProcessRef {
        pid: obj.get("pid").and_then(|v| v.as_u64()),
        ppid: obj.get("ppid").and_then(|v| v.as_u64()),
        process_guid: get_opt_str(obj, "process_guid"),
        parent_process_guid: get_opt_str(obj, "parent_process_guid"),
        image_path: obj
            .get("image_path")
            .filter(|v| v.is_object())
            .map(parse_windows_path),
        command_line: get_opt_str(obj, "command_line"),
    }
}

fn parse_attributes(
    value: Option<&serde_json::Value>,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut map = std::collections::BTreeMap::new();
    if let Some(serde_json::Value::Object(obj)) = value {
        for (k, v) in obj {
            map.insert(k.clone(), v.clone());
        }
    }
    map
}

fn parse_provenance(
    value: Option<&serde_json::Value>,
) -> Result<tf_core::event::Provenance, CaseReadError> {
    let v = value.ok_or(CaseReadError::MissingField("provenance"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("provenance が object ではない".into()))?;
    let record_locator = parse_record_locator(obj.get("record_locator"))?;
    Ok(tf_core::event::Provenance {
        evidence_id: get_str(obj, "evidence_id")?,
        artifact_id: get_str(obj, "artifact_id")?,
        source_locator: get_str(obj, "source_locator")?,
        source_sha256: get_str(obj, "source_sha256")?,
        parser_id: get_str(obj, "parser_id")?,
        parser_version: get_str(obj, "parser_version")?,
        record_locator,
        source_ordinal: get_u64(obj, "source_ordinal").unwrap_or(0),
    })
}

fn parse_record_locator(
    value: Option<&serde_json::Value>,
) -> Result<tf_core::event::RecordLocator, CaseReadError> {
    let v = value.ok_or(CaseReadError::MissingField("record_locator"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("record_locator が object ではない".into()))?;
    let type_str = get_str(obj, "type")?;
    let loc = match type_str.as_str() {
        "record_id" => tf_core::event::RecordLocator::RecordId(get_str(obj, "value")?),
        "byte_offset" => tf_core::event::RecordLocator::ByteOffset(get_u64(obj, "value")?),
        "byte_range" => tf_core::event::RecordLocator::ByteRange {
            start: get_u64(obj, "start")?,
            end: get_u64(obj, "end")?,
        },
        "logical_path" => {
            let parts: Vec<String> = obj
                .get("value")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            tf_core::event::RecordLocator::LogicalPath(parts)
        }
        "source_ordinal" => tf_core::event::RecordLocator::SourceOrdinal,
        other => {
            return Err(CaseReadError::Parse(format!(
                "未知の record_locator type: {other}"
            )));
        }
    };
    Ok(loc)
}

fn parse_issue_list(value: Option<&serde_json::Value>) -> Result<Vec<Issue>, CaseReadError> {
    let arr = value
        .and_then(|v| v.as_array())
        .ok_or(CaseReadError::MissingField("issues"))?;
    arr.iter().map(parse_issue_value).collect()
}

fn parse_issue_value(v: &serde_json::Value) -> Result<Issue, CaseReadError> {
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("issue が object ではない".into()))?;
    let severity_str = get_str(obj, "severity")?;
    let severity = tf_core::issue::IssueSeverity::from_schema_str(&severity_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の severity: {severity_str}")))?;
    let scope_str = get_str(obj, "scope")?;
    let scope = tf_core::issue::IssueScope::from_schema_str(&scope_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の scope: {scope_str}")))?;
    let record_locator = obj
        .get("record_locator")
        .filter(|v| v.is_object())
        .map(|v| parse_record_locator(Some(v)))
        .transpose()?;
    Ok(Issue {
        issue_id: get_str(obj, "issue_id")?,
        severity,
        scope,
        evidence_id: get_opt_str(obj, "evidence_id"),
        artifact_id: get_opt_str(obj, "artifact_id"),
        record_locator,
        source_ordinal: obj.get("source_ordinal").and_then(|v| v.as_u64()),
        message: get_str(obj, "message").unwrap_or_default(),
    })
}

fn parse_match_list(value: Option<&serde_json::Value>) -> Result<Vec<Match>, CaseReadError> {
    let arr = value
        .and_then(|v| v.as_array())
        .ok_or(CaseReadError::MissingField("matches"))?;
    arr.iter().map(parse_match_value).collect()
}

fn parse_match_value(v: &serde_json::Value) -> Result<Match, CaseReadError> {
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("match が object ではない".into()))?;
    let type_str = get_str(obj, "match_type")?;
    let match_type = tf_core::r#match::MatchType::from_schema_str(&type_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の match_type: {type_str}")))?;
    Ok(Match {
        match_id: get_str(obj, "match_id")?,
        match_type,
        rule_id: get_str(obj, "rule_id")?,
        rule_sha256: get_str(obj, "rule_sha256")?,
        event_ids: get_str_list(obj, "event_ids"),
        evidence_ids: get_str_list(obj, "evidence_ids"),
        reasons: get_str_list(obj, "reasons"),
        score: None,
        ordered_event_ids: None,
        logsource_mapping: obj.get("logsource_mapping").cloned(),
        matched_patterns: obj.get("matched_patterns").cloned(),
    })
}

fn parse_finding_list(value: Option<&serde_json::Value>) -> Result<Vec<Finding>, CaseReadError> {
    let arr = value
        .and_then(|v| v.as_array())
        .ok_or(CaseReadError::MissingField("findings"))?;
    arr.iter().map(parse_finding_value).collect()
}

fn parse_finding_value(v: &serde_json::Value) -> Result<Finding, CaseReadError> {
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("finding が object ではない".into()))?;
    let severity_str = get_str(obj, "severity")?;
    let severity = tf_core::case::Severity::from_schema_str(&severity_str)
        .ok_or_else(|| CaseReadError::Parse(format!("未知の severity: {severity_str}")))?;
    let confidence = parse_confidence(obj.get("confidence"))?;
    let rule_refs = obj
        .get("rule_refs")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| {
                    let o = v.as_object()?;
                    Some(tf_core::finding::RuleRef {
                        rule_id: o.get("rule_id")?.as_str()?.to_string(),
                        rule_sha256: o.get("rule_sha256")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let attack_mappings = obj
        .get("attack_mappings")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(parse_attack_mapping).collect())
        .unwrap_or_default();

    Ok(Finding {
        finding_id: get_str(obj, "finding_id")?,
        title: get_str(obj, "title")?,
        description: get_str(obj, "description")?,
        severity,
        confidence,
        event_ids: get_str_list(obj, "event_ids"),
        evidence_ids: get_str_list(obj, "evidence_ids"),
        match_ids: get_str_list(obj, "match_ids"),
        rule_refs,
        attack_mappings,
        observed_evidence: get_str_list(obj, "observed_evidence"),
        inference: get_str_list(obj, "inference"),
    })
}

fn parse_confidence(
    value: Option<&serde_json::Value>,
) -> Result<tf_core::finding::Confidence, CaseReadError> {
    let v = value.ok_or(CaseReadError::MissingField("confidence"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("confidence が object ではない".into()))?;
    let score = obj
        .get("score")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| CaseReadError::Parse("confidence.score が無い".into()))?;
    let reasons = get_str_list(obj, "reasons");
    Ok(tf_core::finding::Confidence::new(score, reasons))
}

fn parse_attack_mapping(v: &serde_json::Value) -> Option<tf_core::finding::AttackMapping> {
    let obj = v.as_object()?;
    let source_str = obj.get("source")?.as_str()?;
    let source = tf_core::finding::AttackMappingSource::from_schema_str(source_str)?;
    Some(tf_core::finding::AttackMapping {
        technique_id: obj.get("technique_id")?.as_str()?.to_string(),
        technique_name: get_opt_str(obj, "technique_name"),
        tactic: get_opt_str(obj, "tactic"),
        source,
        dataset_version: get_opt_str(obj, "dataset_version"),
        dataset_sha256: get_opt_str(obj, "dataset_sha256"),
    })
}

fn parse_manifest(
    value: Option<&serde_json::Value>,
) -> Result<tf_core::manifest::Manifest, CaseReadError> {
    let v = value.ok_or(CaseReadError::MissingField("manifest"))?;
    parse_manifest_value(v)
}

fn parse_manifest_value(
    v: &serde_json::Value,
) -> Result<tf_core::manifest::Manifest, CaseReadError> {
    let obj = v
        .as_object()
        .ok_or_else(|| CaseReadError::Parse("manifest が object ではない".into()))?;
    let counts_value = obj.get("counts").unwrap_or(&serde_json::Value::Null);
    let counts_obj = counts_value.as_object();
    let counts = tf_core::manifest::ManifestCounts {
        evidence: counts_obj
            .and_then(|o| o.get("evidence"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        artifact: counts_obj
            .and_then(|o| o.get("artifact"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        event: counts_obj
            .and_then(|o| o.get("event"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        issue: counts_obj
            .and_then(|o| o.get("issue"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        r#match: counts_obj
            .and_then(|o| o.get("match"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        finding: counts_obj
            .and_then(|o| o.get("finding"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    };
    Ok(tf_core::manifest::Manifest {
        traceforge_version: get_str(obj, "traceforge_version").unwrap_or_default(),
        build_commit: get_str(obj, "build_commit").unwrap_or_default(),
        target: get_str(obj, "target").unwrap_or_default(),
        schema_version: get_str(obj, "schema_version").unwrap_or_default(),
        compatibility_profile: get_str(obj, "compatibility_profile").unwrap_or_default(),
        run_started_at: get_str(obj, "run_started_at").unwrap_or_default(),
        run_finished_at: get_str(obj, "run_finished_at").unwrap_or_default(),
        resolved_config: obj
            .get("resolved_config")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        resolved_config_sha256: get_str(obj, "resolved_config_sha256").unwrap_or_default(),
        case_id: get_str(obj, "case_id").unwrap_or_default(),
        counts,
        components: obj
            .get("components")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        rules: obj
            .get("rules")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        attack_dataset: obj.get("attack_dataset").filter(|v| !v.is_null()).cloned(),
        timezone_assumptions: obj
            .get("timezone_assumptions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        limits: obj
            .get("limits")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        incomplete_reasons: get_str_list(obj, "incomplete_reasons"),
        complete: obj
            .get("complete")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        exit_code: obj.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
    })
}

// JSON helper
fn get_str(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, CaseReadError> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or(CaseReadError::MissingField("key が見つからない"))
        .map_err(|_| CaseReadError::Parse(format!("必須 field が見つからない: {key}")))
}

fn get_opt_str(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn get_u64(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, CaseReadError> {
    obj.get(key).and_then(|v| v.as_u64()).ok_or_else(|| {
        CaseReadError::Parse(format!(
            "必須 field が見つからない、または数値ではない: {key}"
        ))
    })
}

fn get_bool(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, CaseReadError> {
    obj.get(key).and_then(|v| v.as_bool()).ok_or_else(|| {
        CaseReadError::Parse(format!(
            "必須 field が見つからない、または boolean ではない: {key}"
        ))
    })
}

fn get_str_list(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Vec<String> {
    obj.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
