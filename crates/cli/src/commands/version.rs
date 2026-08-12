//! `traceforge version` command（製品 §12・T7-030）。
//!
//! tool・Schema・compatibility profile の version を stdout へ出力する。

use crate::commands::CommandResult;
use crate::version_info::version_string;

pub fn run() -> CommandResult {
    // 規範 §19.1: 解析結果（version 情報）は stdout。
    CommandResult::ok_with_stdout(version_string())
}
