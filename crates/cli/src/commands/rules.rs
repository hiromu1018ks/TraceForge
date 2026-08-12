//! `traceforge rules <dir>` command（製品 §12・T7-028）。
//!
//! 指定した directory 配下の Rule file を読み込み、validate または一覧表示する。
//! Correlation・Sigma・YARA 全ての Rule file を [`tf_engines::RuleRegistry`] で1回読み込む
//! （規範 §14: 1回読み込み・SHA-256 重複検出）。

use std::path::Path;

use tf_core::error::ExitCode;
use tf_engines::{LoadedRuleFile, RuleLoadOptions, RuleRegistry};

use crate::args::RulesArgs;
use crate::commands::CommandResult;
use crate::runtime::RunContext;

/// `rules` command の実行。
pub fn run(args: &RulesArgs, _ctx: &mut RunContext) -> CommandResult {
    let rules_dir = Path::new(&args.rules_dir);
    if !rules_dir.exists() {
        return CommandResult::err(
            ExitCode::InputOrDiscoveryError,
            format!("rules directory が存在しない: {}", rules_dir.display()),
        );
    }

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

    let mut stdout = String::new();
    if args.validate || (!args.validate && !args.list) {
        // 既定動作または --validate: 検証結果を表示。
        stdout.push_str(&format!(
            "rules validation: {} loaded, {} duplicates skipped, {} errors\n",
            load_summary.loaded.len(),
            load_summary.skipped_duplicates.len(),
            load_summary.errors.len(),
        ));
        if !load_summary.errors.is_empty() {
            stdout.push_str("validation errors:\n");
            for e in &load_summary.errors {
                stdout.push_str(&format!("  - {}: {}\n", e.path.display(), e.error));
            }
        }
    }

    if args.list {
        // --list: 読み込んだ Rule 一覧。
        stdout.push_str(&format!("loaded rules ({}):\n", registry.len()));
        for loaded in registry.iter() {
            stdout.push_str(&format_rule_line(loaded));
        }
    }

    let exit_code = if load_summary.errors.is_empty() {
        ExitCode::Success
    } else {
        ExitCode::RuleValidationOrStrictRulesError
    };

    CommandResult {
        exit_code,
        stdout,
        stderr: String::new(),
    }
}

/// 1件の Rule を stdout 一覧用の1行へ整形。
fn format_rule_line(loaded: &LoadedRuleFile) -> String {
    format!(
        "- {} ({} bytes, sha256={})\n",
        loaded.relative_path, loaded.size, loaded.sha256,
    )
}
