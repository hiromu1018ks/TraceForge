//! TraceForge CLI エントリポイント（Phase 7・製品 §12）。
//!
//! `traceforge <COMMAND> [OPTIONS]` を dispatch する。
//! - stdout = 解析結果（規範 §19.1）
//! - stderr = log（`--quiet` で抑制可。ただし解析結果は抑制しない）
//!
//! 戻り値の process exit code は規範 §17.2 に従う。

use std::io::{self, Write};
use std::process;

use tf_cli::{CliResult, run};
use tf_core::error::ExitCode;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result: CliResult = run(&args);

    // 規範 §19.1: stdout = 解析結果、stderr = log。
    if !result.stdout.is_empty() {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let _ = handle.write_all(result.stdout.as_bytes());
        let _ = handle.flush();
    }
    if !result.stderr.is_empty() {
        let stderr = io::stderr();
        let mut handle = stderr.lock();
        let _ = handle.write_all(result.stderr.as_bytes());
        let _ = handle.write_all(b"\n");
        let _ = handle.flush();
    }

    process::exit(result.exit_code.as_process_code());
}

/// ExitCode 値を取り出すための helper（テストから直接使えるよう公開）。
#[allow(dead_code)]
fn _exit_code_value() -> i32 {
    ExitCode::Success.as_process_code()
}
