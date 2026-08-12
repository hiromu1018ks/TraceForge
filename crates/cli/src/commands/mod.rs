//! 9 種の command 実装（Phase 7・製品 §12）。
//!
//! 各 command は [`Command`] を受け取り、[`CommandResult`] を返す。stdout へ解析結果を、
//! stderr へ log を出力する（規範 §19.1）。

use tf_core::error::ExitCode;

use crate::args::Command;
use crate::runtime::RunContext;

pub mod analyze;
pub mod correlate;
pub mod export;
pub mod inspect;
pub mod rules;
pub mod sigma;
pub mod timeline;
pub mod version;
pub mod yara;

/// 1つの command の実行結果。
#[derive(Clone, Debug)]
pub struct CommandResult {
    /// 規範 §17.2 の Exit Code。
    pub exit_code: ExitCode,
    /// stdout へ出力する解析結果。`--quiet` でも抑制しない（規範 §19.1）。
    pub stdout: String,
    /// stderr へ追加で出力する log（RunContext の stderr へ追記される）。
    pub stderr: String,
}

impl Default for CommandResult {
    fn default() -> Self {
        CommandResult {
            exit_code: ExitCode::Success,
            stdout: String::new(),
            stderr: String::new(),
        }
    }
}

impl CommandResult {
    /// 成功（Exit Code 0）・stdout へ出力。
    pub fn ok_with_stdout(stdout: impl Into<String>) -> Self {
        CommandResult {
            exit_code: ExitCode::Success,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// Exit Code 1・stdout へ出力（warning 等で結果は出す）。
    pub fn warnings_with_stdout(stdout: impl Into<String>) -> Self {
        CommandResult {
            exit_code: ExitCode::CaseWithWarnings,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// error のみ（stdout 無し）。
    pub fn err(exit_code: ExitCode, message: impl Into<String>) -> Self {
        CommandResult {
            exit_code,
            stdout: String::new(),
            stderr: message.into(),
        }
    }
}

/// [`Command`] を dispatch する。
pub fn dispatch(command: &Command, ctx: &mut RunContext) -> CommandResult {
    match command {
        Command::Analyze(a) => analyze::run(a, ctx),
        Command::Timeline(a) => timeline::run(a, ctx),
        Command::Correlate(a) => correlate::run(a, ctx),
        Command::Sigma(a) => sigma::run(a, ctx),
        Command::Yara(a) => yara::run(a, ctx),
        Command::Export(a) => export::run(a, ctx),
        Command::Rules(a) => rules::run(a, ctx),
        Command::Inspect(a) => inspect::run(a, ctx),
        Command::Version => version::run(),
    }
}
