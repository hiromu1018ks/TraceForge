//! TraceForge CLI エントリポイント。
//!
//! Phase 7 で 9 command を実装する:
//! `analyze` / `timeline` / `correlate` / `sigma` / `yara` /
//! `export` / `rules` / `inspect` / `version`（製品 §12）。

fn main() {
    // 規範 §19.1: stdout は解析結果、stderr は log。
    // Phase 0 のメッセージは stderr へ出力する（結果ではないため）。
    eprintln!("traceforge: 未実装です（Phase 0）。Phase 7 で 9 command を実装します。");
}
