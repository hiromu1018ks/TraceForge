//! TraceForge Exporter crate。
//!
//! Phase 7 で 6 出力形式を実装する:
//! - Text / JSON / JSONL / CSV / HTML / Timesketch（規範 §19、互換 §8・§10）
//! - 出力安全性（制御文字 escape・CSV formula 対策・HTML CSP）
