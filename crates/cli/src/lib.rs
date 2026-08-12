//! TraceForge CLI エントリポイント（Phase 7・製品 §12）。
//!
//! 9 つの command を提供する:
//! - `analyze`    : Evidence を解析して Case を生成する（規範 §2・規範 §3）
//! - `timeline`   : Event を Timeline として表示・filter する
//! - `correlate`  : 保存済み Event へ Correlation Rule を適用する
//! - `sigma`      : 保存済み Event へ Sigma Rule を適用する
//! - `yara`       : 明示した Evidence へ YARA-X Rule を適用する
//! - `export`     : Case を別形式へ変換する
//! - `rules`      : Rule の validate と一覧表示を行う
//! - `inspect`    : 単一 Artifact の安全な概要を表示する
//! - `version`    : Tool・Schema・Compatibility profile の version を表示する
//!
//! ## stdout / stderr 分離（規範 §19.1）
//!
//! 解析結果は stdout、log は stderr へ出力する。`--quiet` は log を抑制するだけで、
//! 解析結果（stdout）を抑制しない（T7-034・規範 §19.1）。
//!
//! ## 外部通信なし（規範 §2）
//!
//! 全ての処理は offline で行う。ATT&CK dataset は `--attack-dataset <path>` で
//! 手動与えする。`--no-hash` option は提供しない（規範 §2・AGENTS.md 禁止事項）。

pub mod args;
pub mod commands;
pub mod runtime;
pub mod version_info;

pub use args::{CliArgs, CliParseError, Command, OutputFormatArg, parse_args};
pub use commands::CommandResult;
pub use runtime::RunContext;
pub use version_info::{
    BUILD_COMMIT, COMPATIBILITY_PROFILE, SCHEMA_VERSION_STR, TARGET, TRACEFORGE_VERSION,
};

use tf_core::error::ExitCode;

/// CLI 全体の実行結果。
#[derive(Clone, Debug)]
pub struct CliResult {
    /// 規範 §17.2 の Exit Code。
    pub exit_code: ExitCode,
    /// stdout へ出力すべき解析結果。`--quiet` でも抑制しない（規範 §19.1）。
    pub stdout: String,
    /// stderr へ出力すべき log。`--quiet` の場合は呼出側が抑制してよい。
    pub stderr: String,
}

impl CliResult {
    /// 成功（Exit Code 0）・空出力。
    pub fn success() -> Self {
        CliResult {
            exit_code: ExitCode::Success,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// 指定 Exit Code と stderr message から result を作る。stdout は空。
    pub fn error(exit_code: ExitCode, message: impl Into<String>) -> Self {
        CliResult {
            exit_code,
            stdout: String::new(),
            stderr: message.into(),
        }
    }
}

/// CLI args を parse し、command を実行して結果を返す（テストから直接呼出可能）。
pub fn run(args: &[String]) -> CliResult {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            return CliResult::error(ExitCode::CliOrConfigError, format!("{e}"));
        }
    };
    let mut ctx = RunContext::new(parsed.global.clone());
    let result = commands::dispatch(&parsed.command, &mut ctx);
    let stdout = result.stdout;
    let stderr = if ctx.stderr.is_empty() {
        result.stderr
    } else {
        let mut s = ctx.stderr;
        if !result.stderr.is_empty() {
            s.push('\n');
            s.push_str(&result.stderr);
        }
        s
    };
    CliResult {
        exit_code: result.exit_code,
        stdout,
        stderr,
    }
}
