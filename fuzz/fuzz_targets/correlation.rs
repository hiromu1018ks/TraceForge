// Correlation evaluator fuzz target（Phase 5 Correlation 編・T5-030〜T5-042、F-025）。
//
// libFuzzer が生成した raw bytes を Correlation Rule YAML として
// `CompiledCorrelationRule::compile` へ投げ、破損入力・不正 YAML・巨大入力で
// panic しないことを継続的 fuzzing で検証する。
//
// Correlation evaluator は内蔵 YAML parser・Schema validator・predicate evaluator・
// sequence backtracking を経由するが、全て `Result` で error を返す設計であり panic しない。
// 本 target はその保証を継続的 fuzzing で担保する（規範 §9.4: 最終安全網）。

#![no_main]

use libfuzzer_sys::fuzz_target;
use tf_engines::correlation::{CompiledCorrelationRule, DEFAULT_MAX_CORRELATION_WINDOW_SECONDS};

fuzz_target!(|data: &[u8]| {
    // raw bytes を UTF-8 へ変換して Correlation Rule として compile する試行。
    // 非 UTF-8 の場合は compile error となるが panic してはならない。
    let sha256 = "f".repeat(64);
    if let Ok(rule) =
        CompiledCorrelationRule::compile(data, &sha256, DEFAULT_MAX_CORRELATION_WINDOW_SECONDS)
    {
        // compile 成功時は空 Event iterator で evaluate し、panic しないことを確認。
        let _ = rule.evaluate(std::iter::empty());
    }
});
