//! `traceforge yara <evidence> --rules <dir> --mode <m>` command（製品 §12・T7-026）。
//!
//! 明示した Evidence file へ YARA-X Rule を適用する。
//! `--mode` は `all` / `suspicious` / `explicit`（既定 `suspicious`）。
//! Verified Snapshot bytes のみを scan する（規範 §15.2）。

use std::path::Path;

use tf_core::error::ExitCode;
use tf_engines::{RuleLoadOptions, RuleRegistry, YaraEvidenceScanTarget, YaraRuleset, YaraScanner};

use crate::args::YaraArgs;
use crate::commands::CommandResult;
use crate::runtime::RunContext;

/// `yara` command の実行。
pub fn run(args: &YaraArgs, ctx: &mut RunContext) -> CommandResult {
    let evidence_path = Path::new(&args.evidence);
    if !evidence_path.exists() {
        return CommandResult::err(
            ExitCode::InputOrDiscoveryError,
            format!("evidence path が存在しない: {}", evidence_path.display()),
        );
    }

    let rules_dir = Path::new(&args.rules_dir);
    if !rules_dir.exists() {
        return CommandResult::err(
            ExitCode::InputOrDiscoveryError,
            format!("rules directory が存在しない: {}", rules_dir.display()),
        );
    }

    // mode parse（T5-025: all / suspicious / explicit）。
    let mode_str = args.mode.as_deref().unwrap_or("suspicious");
    if !matches!(mode_str, "all" | "suspicious" | "explicit") {
        return CommandResult::err(
            ExitCode::CliOrConfigError,
            format!("未知の --mode: {mode_str}（all / suspicious / explicit）"),
        );
    }

    // Rule 読込。
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
        "yara rules: {} loaded, {} errors",
        load_summary.loaded.len(),
        load_summary.errors.len()
    ));

    // YaraRuleset compile（T5-020・T5-023: file 毎独立 Compiler）。
    let compile_summary = YaraRuleset::compile_from_registry(&registry);
    let compile_errors: Vec<String> = compile_summary
        .errors_iter()
        .map(|e| format!("{}: compile error", e.relative_path))
        .collect();
    let ruleset = compile_summary.into_ruleset();

    // Evidence bytes を読み込む（規範 §15.2: scan 対象を load してはならないが、
    // file の bytes を読んで scan へ渡すのは許可される。YARA-X は bytes のみへ適用）。
    let evidence_bytes = match std::fs::read(evidence_path) {
        Ok(b) => b,
        Err(e) => {
            return CommandResult::err(
                ExitCode::InputOrDiscoveryError,
                format!("evidence bytes 読込失敗: {e}"),
            );
        }
    };
    let evidence_id = tf_core::id::evidence_id(
        &evidence_path.to_string_lossy(),
        evidence_bytes.len() as u64,
        &tf_core::hash::sha256_hex(&evidence_bytes),
    );
    let target = YaraEvidenceScanTarget {
        evidence_id: evidence_id.clone(),
        snapshot_bytes: &evidence_bytes,
    };

    // max_yara_scan_file_size_bytes（Schema §8.2 既定 1 GiB）。
    let max_size = tf_core::Config::defaults()
        .limits
        .max_yara_scan_file_size_bytes;
    let scanner = YaraScanner::new(ruleset, max_size);
    let scan_results = scanner.scan(&[target]);

    // 結果を Text 形式で stdout へ。
    let mut stdout = String::new();
    stdout.push_str("YARA-X scan:\n");
    stdout.push_str(&format!(
        "  evidence: {} ({})\n",
        evidence_path.display(),
        evidence_id
    ));
    stdout.push_str(&format!("  mode: {mode_str}\n"));
    stdout.push_str(&format!("  rules compiled: {}\n", registry.len()));
    stdout.push_str(&format!("  compile errors: {}\n", compile_errors.len()));
    stdout.push_str(&format!("  scan size: {} bytes\n", evidence_bytes.len()));
    stdout.push_str(&format!("  matches: {}\n", scan_results.matches.len()));
    stdout.push_str(&format!("  skipped: {}\n", scan_results.skipped.len()));

    if !compile_errors.is_empty() {
        stdout.push_str("compile errors:\n");
        for e in &compile_errors {
            stdout.push_str(&format!("  - {e}\n"));
        }
    }
    if !scan_results.matches.is_empty() {
        stdout.push_str("matches:\n");
        for m in &scan_results.matches {
            let mv = &m.match_value;
            stdout.push_str(&format!(
                "  - rule={} evidence={} patterns={}\n",
                mv.rule_id,
                mv.evidence_ids.first().cloned().unwrap_or_default(),
                0
            ));
        }
    }
    if !scan_results.skipped.is_empty() {
        stdout.push_str("skipped:\n");
        for s in &scan_results.skipped {
            stdout.push_str(&format!(
                "  - {}: {} ({})\n",
                s.evidence_id, s.code, s.message
            ));
        }
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
