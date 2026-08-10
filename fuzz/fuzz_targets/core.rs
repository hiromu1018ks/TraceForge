// cargo-fuzz 雏形 target: tf-core（T0-010、F-025、製品 §13.1）
//
// Phase 1 以降で core の各関数（決定的 ID 生成・Windows path 正規化・
// canonical JSON など）の fuzz target を追加する。
// Phase 0 では、target がビルド・実行できることのみ確認する。

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // Phase 1 で実装する関数へ _data を渡す fuzz を追加する。
});
