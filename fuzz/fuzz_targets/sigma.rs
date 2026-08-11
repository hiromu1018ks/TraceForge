// Sigma evaluator fuzz target（Phase 5 Sigma 編・T5-010〜T5-017、F-025）。
//
// libFuzzer が生成した raw bytes を Sigma Rule YAML として `CompiledSigmaRule::compile`
// へ投げ、破損入力・不正 YAML・巨大入力で panic しないことを継続的 fuzzing で検証する。
//
// Sigma evaluator は内蔵 YAML parser・condition parser・selection 評価器を経由するが、
// 全て `Result` で error を返す設計であり panic しない。本 target はその保証を
// 継続的 fuzzing で担保する（規範 §9.4: 最終安全網）。

#![no_main]

use libfuzzer_sys::fuzz_target;
use tf_engines::sigma::evaluator::CompiledSigmaRule;

fuzz_target!(|data: &[u8]| {
    // raw bytes を UTF-8 文字列へ変換して Sigma Rule としてコンパイルを試みる。
    // 非 UTF-8 の場合はコンパイル error となるが、panic してはならない。
    let sha256 = "f".repeat(64);
    let _ = CompiledSigmaRule::compile(data, &sha256);
});
