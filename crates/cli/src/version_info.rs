//! TraceForge の version 情報（製品 §12・互換 §11）。
//!
//! 全ての値は build 時に固定される。run 時刻等の run metadata は含まない（規範 §13.1）。

/// TraceForge 自体の製品 version（Cargo.toml と同一）。
pub const TRACEFORGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Schema version（Schema §1・Phase 7 では `1.0.0` 固定）。
pub const SCHEMA_VERSION_STR: &str = "1.0.0";

/// compatibility profile version（互換 §3・`TF-WIN-1.0`）。
pub const COMPATIBILITY_PROFILE: &str = "TF-WIN-1.0";

/// build commit hash。`TRACEFORGE_BUILD_COMMIT` 環境変数で上書き可能。未設定時は空。
pub const BUILD_COMMIT: &str = match option_env!("TRACEFORGE_BUILD_COMMIT") {
    Some(s) => s,
    None => "",
};

/// build target triple。`TRACEFORGE_BUILD_TARGET` 環境変数で上書き可能。
/// 未設定時は host target（`cfg!` マクロから推定）。
pub const TARGET: &str = match option_env!("TRACEFORGE_BUILD_TARGET") {
    Some(s) => s,
    None => HOST_TARGET,
};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const HOST_TARGET: &str = "x86_64-pc-windows-msvc";
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
const HOST_TARGET: &str = "aarch64-pc-windows-msvc";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HOST_TARGET: &str = "x86_64-unknown-linux-gnu";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const HOST_TARGET: &str = "aarch64-unknown-linux-gnu";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const HOST_TARGET: &str = "x86_64-apple-darwin";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const HOST_TARGET: &str = "aarch64-apple-darwin";
#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
)))]
const HOST_TARGET: &str = "unknown";

/// Sigma・Correlation engine の version（TF-SIGMA-1.0 subset・自前実装）。
pub const SIGMA_ENGINE_VERSION: &str = "TF-SIGMA-1.0";

/// Correlation engine の version（自前実装・Schema §7）。
pub const CORRELATION_ENGINE_VERSION: &str = "TF-CORR-1.0";

/// YARA-X engine の version（互換 §7・`yara-x` crate）。
pub const YARA_X_ENGINE_VERSION: &str = "yara-x-1.19";

/// version 情報を1つの文字列へまとめる（`version` command の stdout 用）。
pub fn version_string() -> String {
    format!(
        "traceforge {}\n  schema: {}\n  compatibility profile: {}\n  build commit: {}\n  target: {}\n  sigma engine: {}\n  correlation engine: {}\n  yara-x engine: {}",
        TRACEFORGE_VERSION,
        SCHEMA_VERSION_STR,
        COMPATIBILITY_PROFILE,
        if BUILD_COMMIT.is_empty() {
            "(dev)"
        } else {
            BUILD_COMMIT
        },
        TARGET,
        SIGMA_ENGINE_VERSION,
        CORRELATION_ENGINE_VERSION,
        YARA_X_ENGINE_VERSION,
    )
}
