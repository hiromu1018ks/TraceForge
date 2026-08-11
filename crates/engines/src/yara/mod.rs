//! YARA-X file pattern scan engine（Phase 5 YARA-X 編・T5-020〜T5-027）。
//!
//! 共通編（T5-001〜T5-003）の [`crate::RuleRegistry`] が読み込んだ raw bytes を
//! `yara-x` crate の [`Compiler`](https://docs.rs/yara-x/latest/yara_x/struct.Compiler.html)
//! へ渡し、compiled [`Rules`](https://docs.rs/yara-x/latest/yara_x/struct.Rules.html)
//! へ変換する（規範 §14: 同じ bytes を使う）。
//!
//! ## 対象タスク
//!
//! - **T5-020**: `yara-x` crate pin + Cargo.lock checksum 記録（互換 §7）
//! - **T5-021**: `.yar` / `.yara` file・directory 再帰 load（互換 §7）
//! - **T5-022**: tags / meta / namespace / matched pattern identifier 保持
//!   （互換 §7・Schema §5.7）
//! - **T5-023**: compile error 時の file 全体無効化・他 file 継続（規範 §15.2）
//! - **T5-024**: Verified Snapshot のみ scan・実行時 load 禁止（規範 §15.2）
//! - **T5-025**: `all` / `suspicious` / `explicit` mode（Schema §8.3・規範 §15.2）
//! - **T5-026**: suspicious mode の Evidence ID 解決・host path 推測 scan 禁止
//!   （規範 §15.2・§21-13）
//! - **T5-027**: `max_yara_scan_file_size_bytes` 適用（Schema §8.2）
//!
//! ## 設計上の制約
//!
//! - `yara-x` crate の完全 version と Cargo.lock checksum を Manifest へ記録する
//!   （互換 §7: `latest` 使用禁止）。engine version は [`yara_x_engine_version`] へ公開する。
//! - 各 [`crate::LoadedRuleFile`] の raw bytes を1回だけ `Compiler::add_source` へ渡す
//!   （規範 §14）。`include` 文は解析 host の file system へアクセスするため無効化する。
//! - compile error が1件でもある Rule file は全体を無効とし、他 file は継続する
//!   （規範 §15.2・T5-023）。このため file 毎に独立した `Compiler` を構築する。
//! - scan 対象は Verified Snapshot のみ（規範 §15.2・T5-024）。本 engine は
//!   snapshot bytes を `&[u8]` で受け取り、実行・load・shell open は行わない。
//! - suspicious mode は Evidence ID のみで解決し、host path 推測は禁止する
//!   （規範 §15.2・§21-13・T5-026）。
//! - `max_yara_scan_file_size_bytes` 超過の Evidence は skip し Warning を出す
//!   （Schema §8.2・規範 §18・T5-027）。
//! - Match ID は決定的生成のみ（規範 §12）。YARA Rule 名・Rule file SHA-256・
//!   Evidence ID を入力とする。

pub mod compiler;
pub mod r#match;
pub mod scanner;

pub use compiler::{
    CompiledYaraFile, YaraCompileError, YaraCompileErrorDetail, YaraRuleset,
    YaraRulesetCompileSummary, yara_x_engine_version,
};
pub use r#match::{YaraMatchResult, YaraPatternInfo, build_yara_match};
pub use scanner::{
    ModeResolutionWarning, YaraEvidenceScanTarget, YaraScanMode, YaraScanResults, YaraScanner,
    select_evidence_for_mode,
};
