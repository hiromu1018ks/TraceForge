//! `traceforge sigma <case> --rules <dir>` command（製品 §12・T7-025）。
//!
//! 保存済み Case（JSON / JSONL）から Event を読み込み、Sigma Rule を適用する。
//! Sigma 評価は TF-SIGMA-1.0 subset evaluator（互換 §6・規範 §15.1）を使用する。

use std::path::Path;

use tf_core::error::ExitCode;
use tf_engines::{CompiledSigmaRule, RuleLoadOptions, RuleRegistry, SigmaError};

use crate::args::SigmaArgs;
use crate::commands::CommandResult;
use crate::runtime::{RunContext, read_case_from_path, write_output};

/// `sigma` command の実行。
pub fn run(args: &SigmaArgs, ctx: &mut RunContext) -> CommandResult {
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
        "sigma rules: {} loaded, {} errors",
        load_summary.loaded.len(),
        load_summary.errors.len()
    ));

    // 各 Rule file を compile（T5-010・T5-011: 未対応構文は skip）。
    let mut compiled: Vec<CompiledSigmaRule> = Vec::new();
    let mut compile_errors: Vec<String> = Vec::new();
    for loaded in registry.iter() {
        match CompiledSigmaRule::compile(loaded.raw_bytes(), &loaded.sha256) {
            Ok(c) => compiled.push(c),
            Err(e) => {
                // UnsupportedFeature は Rule 全体 skip（T5-011）。それ以外は compile error。
                let msg = format!("{}: {e}", loaded.relative_path);
                if matches!(e, SigmaError::UnsupportedFeature { .. }) {
                    ctx.log(format!("sigma rule を skip（T5-011）: {msg}"));
                } else {
                    compile_errors.push(msg);
                }
            }
        }
    }

    // 全 Event へ各 Rule を適用（規範 §15.1・T5-016）。
    let mut matches: Vec<tf_core::r#match::Match> = Vec::new();
    for ev in &data.events {
        for c in &compiled {
            if let Some(result) = c.evaluate(ev) {
                matches.push(result.match_value);
            }
        }
    }

    ctx.log(format!(
        "sigma evaluation: {} events × {} rules = {} matches",
        data.events.len(),
        compiled.len(),
        matches.len()
    ));

    // 結果を Text 形式で stdout へ。
    let mut stdout = String::new();
    stdout.push_str("Sigma evaluation:\n");
    stdout.push_str(&format!("  rules compiled: {}\n", compiled.len()));
    stdout.push_str(&format!("  rules with errors: {}\n", compile_errors.len()));
    stdout.push_str(&format!("  events: {}\n", data.events.len()));
    stdout.push_str(&format!("  matches: {}\n", matches.len()));
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
        let s = format!("sigma result written: {}\n", output);
        return CommandResult {
            exit_code: ExitCode::Success,
            stdout: s,
            stderr: String::new(),
        };
    }

    let exit_code = if !compile_errors.is_empty() {
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
