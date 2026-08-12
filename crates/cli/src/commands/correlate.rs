//! `traceforge correlate <case> --rules <dir>` command（製品 §12・T7-024）。
//!
//! 保存済み Case（JSON / JSONL）から Event を読み込み、Correlation Rule を適用する。
//! Correlation 評価は Schema §7 evaluator（規範 §14）を使用する。

use std::path::Path;

use tf_core::error::ExitCode;
use tf_engines::{
    CompiledCorrelationRule, DEFAULT_MAX_CORRELATION_WINDOW_SECONDS, RuleLoadOptions, RuleRegistry,
};

use crate::args::CorrelateArgs;
use crate::commands::CommandResult;
use crate::runtime::{RunContext, read_case_from_path, write_output};

/// `correlate` command の実行。
pub fn run(args: &CorrelateArgs, ctx: &mut RunContext) -> CommandResult {
    let case_path = Path::new(&args.case);
    let data = match read_case_from_path(case_path) {
        Ok(d) => d,
        Err(e) => {
            return CommandResult::err(e.exit_code(), e.to_string());
        }
    };

    let rules_dir = Path::new(&args.rules_dir);
    if !rules_dir.exists() {
        return CommandResult::err(
            ExitCode::InputOrDiscoveryError,
            format!("rules directory が存在しない: {}", rules_dir.display()),
        );
    }

    // Rule 読込（規範 §14: 1回読み込み・SHA-256 重複検出）。
    let opts = RuleLoadOptions::default();
    let mut registry = RuleRegistry::new();
    let load_summary = match registry.load_directory(rules_dir, &opts) {
        Ok(s) => s,
        Err(e) => {
            return CommandResult::err(
                ExitCode::RuleValidationOrStrictRulesError,
                format!("Rule load 失敗: {e}"),
            );
        }
    };
    ctx.log(format!(
        "correlation rules: {} loaded, {} errors",
        load_summary.loaded.len(),
        load_summary.errors.len()
    ));

    // 各 Rule を compile（T5-030・T5-031: Schema §7 validation）。
    let mut compiled: Vec<CompiledCorrelationRule> = Vec::new();
    let mut compile_errors: Vec<String> = Vec::new();
    for loaded in registry.iter() {
        match CompiledCorrelationRule::compile(
            loaded.raw_bytes(),
            &loaded.sha256,
            DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
        ) {
            Ok(c) => compiled.push(c),
            Err(e) => compile_errors.push(format!("{}: {e}", loaded.relative_path)),
        }
    }

    // 各 Rule へ対して Event を流し込み、Match list を集める。
    let mut matches: Vec<tf_core::r#match::Match> = Vec::new();
    let mut truncated_count: u32 = 0;
    let mut skipped_count: u32 = 0;
    for c in &compiled {
        let events_iter = data.events.iter().cloned();
        let result = c.evaluate(events_iter);
        if result.truncated {
            truncated_count += 1;
            ctx.log(format!(
                "warning: correlation rule '{}' が max_matches に到達（規範 §14.2）",
                c.rule_id
            ));
        }
        if result.skipped {
            skipped_count += 1;
            ctx.log(format!(
                "warning: correlation rule '{}' を skip: {}",
                c.rule_id,
                result.skip_reason.as_deref().unwrap_or("(reason unknown)")
            ));
        }
        matches.extend(result.matches);
    }

    ctx.log(format!(
        "correlation: {} rules × {} events = {} matches (truncated={}, skipped={})",
        compiled.len(),
        data.events.len(),
        matches.len(),
        truncated_count,
        skipped_count
    ));

    let mut stdout = String::new();
    stdout.push_str("Correlation evaluation:\n");
    stdout.push_str(&format!("  rules compiled: {}\n", compiled.len()));
    stdout.push_str(&format!("  compile errors: {}\n", compile_errors.len()));
    stdout.push_str(&format!("  events: {}\n", data.events.len()));
    stdout.push_str(&format!("  matches: {}\n", matches.len()));
    stdout.push_str(&format!("  truncated rules: {}\n", truncated_count));
    stdout.push_str(&format!("  skipped rules: {}\n", skipped_count));
    if !compile_errors.is_empty() {
        stdout.push_str("compile errors:\n");
        for e in &compile_errors {
            stdout.push_str(&format!("  - {e}\n"));
        }
    }
    if !matches.is_empty() {
        stdout.push_str("matches:\n");
        for m in &matches {
            stdout.push_str(&format!(
                "  - {} (rule={}): events={}\n",
                m.match_id,
                m.rule_id,
                m.event_ids.len()
            ));
        }
    }

    if let Some(output) = &args.output {
        if let Err(e) = write_output(Some(Path::new(output)), false, stdout.as_bytes()) {
            return CommandResult::err(e.exit_code(), e.to_string());
        }
        let s = format!("correlation result written: {}\n", output);
        return CommandResult {
            exit_code: ExitCode::Success,
            stdout: s,
            stderr: String::new(),
        };
    }

    let exit_code = if !compile_errors.is_empty() || truncated_count > 0 {
        ExitCode::CaseWithWarnings
    } else {
        ExitCode::Success
    };
    CommandResult {
        exit_code,
        stdout,
        stderr: String::new(),
    }
}
