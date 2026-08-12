//! `traceforge export <case>` command（製品 §12・T7-027・互換 §10）。
//!
//! Case JSON / JSONL file を読み込み、別の出力形式へ変換する。
//! 異なる Schema major version の自動変換は禁止する（互換 §10・T7-009）。

use std::path::Path;

use tf_core::error::ExitCode;
use tf_export::{csv, html, json, jsonl, text, timesketch};

use crate::args::{ExportArgs, OutputFormatArg};
use crate::commands::CommandResult;
use crate::runtime::{RunContext, read_case_from_path, write_output};

/// `export` command の実行。
pub fn run(args: &ExportArgs, ctx: &mut RunContext) -> CommandResult {
    let case_path = Path::new(&args.case);
    let data = match read_case_from_path(case_path) {
        Ok(d) => d,
        Err(e) => {
            return CommandResult::err(e.exit_code(), e.to_string());
        }
    };

    let format = args.format.unwrap_or_else(|| {
        // 出力 path 拡張子から推定、無ければ JSON。
        args.output
            .as_ref()
            .and_then(|p| Path::new(p).extension())
            .and_then(|e| e.to_str())
            .and_then(OutputFormatArg::from_extension)
            .unwrap_or(OutputFormatArg::Text)
    });

    let mut buf: Vec<u8> = Vec::new();
    let result_summary: Option<String> = match format {
        OutputFormatArg::Text => match text::write_text(&data, &mut buf) {
            Ok(()) => None,
            Err(e) => return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string()),
        },
        OutputFormatArg::Json => match json::write_json(&data, &mut buf) {
            Ok(()) => None,
            Err(e) => return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string()),
        },
        OutputFormatArg::Jsonl => match jsonl::write_jsonl(&data, &mut buf) {
            Ok(_) => None,
            Err(e) => return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string()),
        },
        OutputFormatArg::Csv => match csv::write_csv(&data, &mut buf) {
            Ok(summary) => {
                if summary.sanitized() {
                    Some(format!(
                        "csv_sanitized: {} cell（規範 §19.2）",
                        summary.sanitized_cells
                    ))
                } else {
                    None
                }
            }
            Err(e) => return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string()),
        },
        OutputFormatArg::Html => match html::write_html(&data, &mut buf) {
            Ok(()) => None,
            Err(e) => return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string()),
        },
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
            match timesketch::write_timesketch(&data, &mut buf) {
                Ok(summary) => {
                    if summary.has_excluded() {
                        Some(format!(
                            "Timesketch 変換不可のため {} 件の Event を除外した（互換 §8）",
                            summary.excluded
                        ))
                    } else {
                        None
                    }
                }
                Err(e) => return CommandResult::err(ExitCode::OutputOrSafetyError, e.to_string()),
            }
        }
    };

    let stdout_str = match write_output(args.output.as_deref().map(Path::new), false, &buf) {
        Ok(()) => {
            if let Some(output) = &args.output {
                let mut s = format!("export: {} -> {}", args.case, output);
                if let Some(summary) = result_summary.as_ref() {
                    s.push_str(&format!("\n{summary}"));
                    ctx.log(format!("warning: {summary}"));
                }
                s.push('\n');
                s
            } else {
                String::from_utf8_lossy(&buf).into_owned()
            }
        }
        Err(e) => return CommandResult::err(e.exit_code(), e.to_string()),
    };

    let exit_code = if result_summary.is_some() {
        ExitCode::CaseWithWarnings
    } else {
        ExitCode::Success
    };

    CommandResult {
        exit_code,
        stdout: stdout_str,
        stderr: String::new(),
    }
}
