//! `traceforge analyze <input>` command（規範 §2・§3・§20・製品 §12・T7-021・T7-031・T7-032）。
//!
//! 既定の安全プロファイル（規範 §2）:
//! - Evidence open: read-only
//! - snapshot: always
//! - SHA-256: mandatory（`--no-hash` は提供しない）
//! - traversal: recursive
//! - symlink: skip + Warning
//! - external network access: disabled
//! - output overwrite: disabled

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use tempfile::tempdir;
use tf_core::Config;
use tf_core::case::{ArtifactInstance, CaseMetadata, EvidenceItem, ParseStatus};
use tf_core::error::ExitCode;
use tf_core::event::{ArtifactSource, Event};
use tf_core::id;
use tf_core::issue::{Issue, IssueScope, IssueSeverity};
use tf_core::manifest::ManifestCounts;
use tf_evidence::{DiscoveryOptions, discover, probe, snapshot};
use tf_export::manifest::{ManifestFinalizationInput, finalize_manifest, missing_manifest_fields};
use tf_export::{CaseData, csv, html, json, jsonl, text, timesketch};
use tf_parsers::sink::EventStoreSink;
use tf_parsers::{
    AmcacheParser, ArtifactParser, EvtxParser, JumpListParser, LnkParser, PrefetchParser,
    RegistryParser, UsnParser, run_parser_catching_panic,
};
use tf_store::EventStore;

use crate::args::{AnalyzeArgs, OutputFormatArg};
use crate::commands::CommandResult;
use crate::runtime::{RunContext, write_output};
use crate::version_info::{
    BUILD_COMMIT, COMPATIBILITY_PROFILE, SCHEMA_VERSION_STR, TARGET, TRACEFORGE_VERSION,
};

/// `analyze` command の実行。
pub fn run(args: &AnalyzeArgs, ctx: &mut RunContext) -> CommandResult {
    let input_path = Path::new(&args.input);
    if !input_path.exists() {
        return CommandResult::err(
            ExitCode::InputOrDiscoveryError,
            format!("入力 path が存在しない: {}", input_path.display()),
        );
    }

    // 入出力分離検証（規範 §5.4）。
    if let Some(output) = &args.output
        && let Err(e) = verify_io_separation(input_path, Path::new(output))
    {
        return CommandResult::err(ExitCode::OutputOrSafetyError, e);
    }

    // Config 構築。Phase 7 では defaults を基準に CLI override を適用。
    let mut config = Config::defaults();
    if let Some(tz) = &args.timezone {
        config.analysis.timezone = tz.clone();
    }
    if let Some(t) = args.threads {
        config.analysis.threads = t;
    }
    if let Err(e) = config.validate() {
        return CommandResult::err(
            ExitCode::CliOrConfigError,
            format!("設定 validation 失敗: {e}"),
        );
    }
    let resolved_config = serde_json::to_value(&config).unwrap_or(serde_json::Value::Null);
    let run_started_at = utc_now_rfc3339();

    let outcome = match run_pipeline(args, &config, input_path, ctx) {
        Ok(o) => o,
        Err(e) => {
            return CommandResult::err(ExitCode::FatalInternalError, e);
        }
    };

    let run_finished_at = utc_now_rfc3339();
    let manifest_input = ManifestFinalizationInput {
        traceforge_version: TRACEFORGE_VERSION.into(),
        build_commit: BUILD_COMMIT.into(),
        target: TARGET.into(),
        schema_version: SCHEMA_VERSION_STR.into(),
        compatibility_profile: COMPATIBILITY_PROFILE.into(),
        run_started_at,
        run_finished_at,
        resolved_config,
        case_id: outcome.case.case_id.clone(),
        counts: ManifestCounts {
            evidence: outcome.case_evidence_count,
            artifact: outcome.case_artifacts.len() as u64,
            event: outcome.event_count,
            issue: outcome.issues.len() as u64,
            r#match: 0,
            finding: 0,
        },
        components: tf_export::manifest::default_components(SCHEMA_VERSION_STR, None, None),
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: timezone_assumptions(&config),
        limits: serde_json::json!({}),
        incomplete_reasons: outcome.incomplete_reasons.clone(),
        complete: outcome.incomplete_reasons.is_empty(),
        exit_code: if outcome.incomplete_reasons.is_empty() {
            0
        } else {
            1
        },
    };
    let manifest = finalize_manifest(&manifest_input);

    // Manifest 必須 field 検証（規範 §20・T7-032）。
    let missing = missing_manifest_fields(&manifest);
    if !missing.is_empty() {
        ctx.log(format!("warning: Manifest の必須 field 欠落: {missing:?}"));
    }

    let mut data = CaseData {
        case: outcome.case,
        evidence: outcome.evidence,
        artifacts: outcome.case_artifacts,
        events: outcome.events,
        issues: outcome.issues,
        matches: vec![],
        findings: vec![],
        manifest,
    };

    // 出力形式の決定。
    let format = args
        .format
        .or_else(|| {
            args.output
                .as_ref()
                .and_then(|p| Path::new(p).extension())
                .and_then(|e| e.to_str())
                .and_then(OutputFormatArg::from_extension)
        })
        .unwrap_or(OutputFormatArg::Text);

    let bytes = match format {
        OutputFormatArg::Text => {
            let mut buf: Vec<u8> = Vec::new();
            if let Err(e) = text::write_text(&data, &mut buf) {
                return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string());
            }
            buf
        }
        OutputFormatArg::Json => {
            let mut buf: Vec<u8> = Vec::new();
            if let Err(e) = json::write_json(&data, &mut buf) {
                return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string());
            }
            buf
        }
        OutputFormatArg::Jsonl => {
            let mut buf: Vec<u8> = Vec::new();
            if let Err(e) = jsonl::write_jsonl(&data, &mut buf) {
                return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string());
            }
            buf
        }
        OutputFormatArg::Csv => {
            let mut buf: Vec<u8> = Vec::new();
            let summary = match csv::write_csv(&data, &mut buf) {
                Ok(s) => s,
                Err(e) => return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string()),
            };
            if summary.sanitized() {
                ctx.log(format!(
                    "warning: CSV formula injection 対策として {} cell へ ' を前置した（規範 §19.2）",
                    summary.sanitized_cells
                ));
                // csv_sanitized を Manifest limits へ記録（規範 §19.2）。
                let sanitized_field = csv::csv_sanitized_field(summary);
                if let Some(obj) = data.manifest.limits.as_object_mut() {
                    obj.insert("csv_output".into(), sanitized_field);
                }
            }
            buf
        }
        OutputFormatArg::Html => {
            let mut buf: Vec<u8> = Vec::new();
            if let Err(e) = html::write_html(&data, &mut buf) {
                return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string());
            }
            buf
        }
        OutputFormatArg::Timesketch => {
            // 互換 §8: 出力 file は .jsonl で終わる必要がある。
            if let Some(output) = &args.output
                && !output.ends_with(".jsonl")
            {
                return CommandResult::err(
                    ExitCode::OutputOrSafetyError,
                    "Timesketch 出力の file 名は .jsonl で終わる必要がある（互換 §8）".to_string(),
                );
            }
            let mut buf: Vec<u8> = Vec::new();
            let summary = match timesketch::write_timesketch(&data, &mut buf) {
                Ok(s) => s,
                Err(e) => return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string()),
            };
            if summary.has_excluded() {
                ctx.log(format!(
                    "warning: Timesketch へ変換不可の Event {} 件を除外した（互換 §8）",
                    summary.excluded
                ));
                let ts_field = timesketch::timesketch_summary_field(&summary);
                if let Some(obj) = data.manifest.limits.as_object_mut() {
                    obj.insert("timesketch_export".into(), ts_field);
                }
                // 互換 §8: 除外件数 > 0 は Exit Code 1。
                let mut result =
                    CommandResult::warnings_with_stdout(String::from_utf8_lossy(&buf).into_owned());
                if let Some(output) = &args.output {
                    if let Err(e) = write_output(Some(Path::new(output)), false, &buf) {
                        return CommandResult::err(e.exit_code(), e.to_string());
                    }
                    result.stdout = format!("timesketch output: {}\n", output);
                }
                return result;
            }
            buf
        }
    };

    // 出力（stdout または file）。
    let stdout_str = match write_output(args.output.as_deref().map(Path::new), false, &bytes) {
        Ok(()) => {
            if let Some(output) = &args.output {
                format!("output: {}\n", output)
            } else {
                String::from_utf8_lossy(&bytes).into_owned()
            }
        }
        Err(e) => return CommandResult::err(e.exit_code(), e.to_string()),
    };

    // T7-031: 危険 option の Manifest 記録。
    // 現状は危険 option が無いため、記録項目は空。将来 `--follow-symlinks` 等を追加した
    // 際にここで Manifest.incomplete_reasons へ追記する。

    let exit_code = if data.manifest.complete {
        ExitCode::Success
    } else {
        ExitCode::CaseWithWarnings
    };

    CommandResult {
        exit_code,
        stdout: stdout_str,
        stderr: String::new(),
    }
}

/// analyze pipeline の中間成果物。
struct PipelineOutcome {
    case: CaseMetadata,
    evidence: Vec<EvidenceItem>,
    case_artifacts: Vec<ArtifactInstance>,
    events: Vec<Event>,
    issues: Vec<Issue>,
    event_count: u64,
    case_evidence_count: u64,
    incomplete_reasons: Vec<String>,
}

/// analyze pipeline 本体（discovery → snapshot → probe → parse）。
fn run_pipeline(
    args: &AnalyzeArgs,
    config: &Config,
    input_path: &Path,
    _ctx: &RunContext,
) -> Result<PipelineOutcome, String> {
    let discovery_opts = DiscoveryOptions {
        recursive: config.analysis.recursive,
        max_recursion_depth: config.limits.max_recursion_depth,
        max_files: config.limits.max_files,
    };
    let discovery = discover(input_path, &discovery_opts).map_err(|e| e.to_string())?;

    let temp_dir = tempdir().map_err(|e| format!("temp dir 作成失敗: {e}"))?;

    let parsers = make_parser_set();
    let mut evidence_list: Vec<EvidenceItem> = Vec::new();
    let mut artifacts: Vec<ArtifactInstance> = Vec::new();
    let mut issues: Vec<Issue> = Vec::new();

    // symlink skip を Issue 化。
    for symlink in &discovery.symlink_skipped {
        issues.push(Issue {
            issue_id: "TF-W-DISCOVERY-SYMLINK".into(),
            severity: IssueSeverity::Warning,
            scope: IssueScope::Evidence,
            evidence_id: None,
            artifact_id: None,
            record_locator: None,
            source_ordinal: None,
            message: format!("symlink を skip した: {symlink}"),
        });
    }
    if discovery.truncated {
        issues.push(Issue {
            issue_id: "TF-W-LIMIT-MAX-FILES".into(),
            severity: IssueSeverity::Warning,
            scope: IssueScope::Case,
            evidence_id: None,
            artifact_id: None,
            record_locator: None,
            source_ordinal: None,
            message: format!(
                "max_files limit ({}) 到達のため discovery を打ち切った",
                config.limits.max_files
            ),
        });
    }

    // EventStore を一時 file へ作成（規範 §10）。
    let spool_path = temp_dir.path().join("events.spool");
    let mut store = EventStore::create(&spool_path).map_err(|e| e.to_string())?;
    let mut sink_issues: Vec<Issue> = Vec::new();

    let mut evidence_ids: BTreeSet<String> = BTreeSet::new();

    for file in &discovery.files {
        // snapshot + SHA-256（規範 §5.5）。
        let snap = match snapshot(&file.source_locator, &file.host_path, temp_dir.path()) {
            Ok(s) => s,
            Err(e) => {
                // snapshot 失敗は Evidence を Failed 扱いとするが継続する。
                issues.push(Issue {
                    issue_id: "TF-W-SNAPSHOT-FAILED".into(),
                    severity: IssueSeverity::Warning,
                    scope: IssueScope::Evidence,
                    evidence_id: None,
                    artifact_id: None,
                    record_locator: None,
                    source_ordinal: None,
                    message: format!("snapshot 作成失敗 ({}): {e}", file.host_path.display()),
                });
                continue;
            }
        };
        let mut evidence = snap.evidence.clone();
        evidence.snapshot_locator = snap.snapshot_path.to_string_lossy().into_owned();
        evidence_ids.insert(evidence.evidence_id.clone());

        // artifact 識別（規範 §11）。
        let header = probe::read_header_bytes(&snap.snapshot_path)
            .map_err(|e| format!("header bytes 読取失敗: {e}"))?;
        let _probe_input = probe::ProbeInput {
            source_locator: &evidence.source_locator,
            host_path: &snap.snapshot_path,
            header_bytes: &header,
            file_size: evidence.size,
        };

        let mut probe_outcomes: Vec<probe::ProbeOutcome> = Vec::new();
        for p in &parsers {
            let result = p.probe(&evidence);
            if result == tf_core::case::ProbeResult::NotThisFormat {
                continue;
            }
            probe_outcomes.push(probe::ProbeOutcome {
                result,
                detection_reasons: vec![format!("probe-by-{}", p.parser_id())],
                parser_id: p.parser_id().to_string(),
                parser_version: p.parser_version().to_string(),
                artifact_type: p.artifact_type(),
            });
        }
        let resolution = probe::resolve_probes(probe_outcomes, &evidence.evidence_id);
        issues.extend(resolution.issues);

        for selected in &resolution.selected {
            // ArtifactInstance を構築（Schema §5.4）。
            let artifact = ArtifactInstance {
                artifact_id: id::artifact_id(
                    &evidence.evidence_id,
                    selected.artifact_type.as_str(),
                    &selected.parser_id,
                    &selected.parser_version,
                ),
                evidence_id: evidence.evidence_id.clone(),
                artifact_type: selected.artifact_type,
                parser_id: selected.parser_id.clone(),
                parser_version: selected.parser_version.clone(),
                probe_result: selected.result,
                detection_reasons: selected.detection_reasons.clone(),
                parse_status: ParseStatus::Skipped,
            };
            artifacts.push(artifact.clone());
            evidence.parse_eligible = true;

            // 該当 Parser を取り出して解析（規範 §9.1: sink 型）。
            let parser = parsers
                .iter()
                .find(|p| p.parser_id() == selected.parser_id)
                .expect("probe 結果の parser_id に対応する Parser が見つからない");
            let snapshot_path = snap.snapshot_path.clone();
            let parse_context = tf_parsers::ParseContext {
                evidence: evidence.clone(),
                artifact: artifact.clone(),
            };
            let mut snapshot_file = match fs::OpenOptions::new().read(true).open(&snapshot_path) {
                Ok(f) => f,
                Err(e) => {
                    issues.push(Issue {
                        issue_id: "TF-W-PARSER-SNAPSHOT-OPEN-FAILED".into(),
                        severity: IssueSeverity::Warning,
                        scope: IssueScope::Artifact,
                        evidence_id: Some(evidence.evidence_id.clone()),
                        artifact_id: Some(artifact.artifact_id.clone()),
                        record_locator: None,
                        source_ordinal: None,
                        message: format!("snapshot file open 失敗: {e}"),
                    });
                    continue;
                }
            };
            let mut sink = EventStoreSink::new(&mut store, &mut sink_issues);
            let summary = run_parser_catching_panic(
                parser.as_ref(),
                &mut snapshot_file,
                &parse_context,
                &mut sink,
            );
            // 最終的な parse_status を反映。
            if let Some(last) = artifacts.last_mut() {
                last.parse_status = summary.status;
            }
        }

        evidence_list.push(evidence);
    }

    // store へ commit して完了（規範 §10）。
    store.commit().map_err(|e| e.to_string())?;
    issues.extend(sink_issues);

    // EventStore から Timeline 順で Event を読み出す。
    let event_count = store.len();
    let mut events: Vec<Event> = Vec::new();
    let iter = store.iter_sorted(1024 * 1024).map_err(|e| e.to_string())?;
    for res in iter {
        let ev = res.map_err(|e| e.to_string())?;
        events.push(ev);
    }

    // Case ID（規範 §4.1: evidence_id の byte 順 sort + length-prefixed 連結の SHA-256）。
    let evidence_id_list: Vec<&str> = evidence_ids.iter().map(String::as_str).collect();
    let case_id = id::case_id(&evidence_id_list);

    let case = CaseMetadata {
        case_id,
        external_case_id: None,
        name: args
            .input
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&args.input)
            .to_string(),
        analyst: None,
        description: None,
        default_timezone: if config.analysis.timezone.is_empty() {
            None
        } else {
            Some(config.analysis.timezone.clone())
        },
        tags: vec![],
    };

    let mut incomplete_reasons: Vec<String> = Vec::new();
    if discovery.truncated {
        incomplete_reasons.push("max_files limit 到達".into());
    }
    if issues.iter().any(|i| i.severity == IssueSeverity::Warning) {
        incomplete_reasons.push("warning issues".into());
    }

    Ok(PipelineOutcome {
        case,
        evidence: evidence_list,
        case_artifacts: artifacts,
        events,
        issues,
        event_count,
        case_evidence_count: evidence_ids.len() as u64,
        incomplete_reasons,
    })
}

/// 使用する Parser の一覧を構築する（Phase 4 の全7種）。
fn make_parser_set() -> Vec<Box<dyn ArtifactParser>> {
    vec![
        Box::new(LnkParser::new()),
        Box::new(PrefetchParser::new()),
        Box::new(UsnParser::new()),
        Box::new(EvtxParser::new()),
        Box::new(RegistryParser::new()),
        Box::new(AmcacheParser::new()),
        Box::new(JumpListParser::new()),
    ]
}

/// 入出力分離検証（規範 §5.4）。
///
/// 出力 path が入力 directory 配下にある場合は拒否する。
fn verify_io_separation(input: &Path, output: &Path) -> Result<(), String> {
    let input_abs = input
        .canonicalize()
        .map_err(|e| format!("入力 path 解決失敗: {e}"))?;
    let output_abs = output
        .parent()
        .map(|p| {
            p.canonicalize()
                .map_err(|e| format!("出力 親 directory 解決失敗: {e}"))
        })
        .transpose()?;
    if let Some(out_parent) = output_abs
        && out_parent.starts_with(&input_abs)
    {
        return Err(format!(
            "出力 directory ({}) が入力 directory ({}) 配下にある（規範 §5.4）",
            out_parent.display(),
            input_abs.display()
        ));
    }
    Ok(())
}

/// timezone assumptions を構築する。
fn timezone_assumptions(config: &Config) -> Vec<serde_json::Value> {
    let mut list = Vec::new();
    if config.analysis.timezone.is_empty() {
        list.push(serde_json::json!({
            "assumption": "timezone 指定無し。local time は UTC へ変換しない（規範 §6.2）"
        }));
    } else {
        list.push(serde_json::json!({
            "assumption": format!("Case 既定 timezone: {}", config.analysis.timezone),
            "timezone": config.analysis.timezone,
        }));
    }
    list
}

/// 現在時刻を RFC 3339 UTC 文字列へ（run metadata 用・規範 §13.1）。
fn utc_now_rfc3339() -> String {
    use chrono::{SecondsFormat, Utc};
    Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

#[allow(dead_code)]
fn artifact_source_str(s: ArtifactSource) -> &'static str {
    s.as_str()
}
