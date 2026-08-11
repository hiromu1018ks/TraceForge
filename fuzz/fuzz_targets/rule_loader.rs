// Rule loader fuzz target（Phase 5 共通編・T5-001、F-025、製品 §13.1）。
//
// libFuzzer が生成した raw bytes を一時 file へ書き出し、`RuleRegistry::load` へ
// 投げて、破損内容・巨大 size・境界値入力で panic しないことを継続的 fuzzing で
// 検証する。
//
// `RuleRegistry::load` は内部で file 読込・SHA-256 計算・registry 追加を行うが、
// いずれも `Result` で error を返す設計であり panic しない。本 target はその保証を
// 継続的 fuzzing で担保する（規範 §9.4: 最終安全網）。
//
// fuzzing の実行は Linux CI のみで行う（Windows MSVC では libfuzzer-sys の link が
// 失敗するため、本プロジェクトでは `cargo check --manifest-path fuzz/Cargo.toml`
// でビルド検証する）。

#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use tf_engines::{RuleLoadOptions, RuleRegistry};

fuzz_target!(|data: &[u8]| {
    // 一時 directory 上の単一 file へ raw bytes を書き出す。
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let rule_path = dir.path().join("fuzz.yml");
    {
        let mut f = match std::fs::File::create(&rule_path) {
            Ok(f) => f,
            Err(_) => return,
        };
        if f.write_all(data).is_err() {
            return;
        }
    }

    // `max_file_size_bytes` を十分大きく設定し、内容によらず読み込めるようにする。
    // これにより SHA-256 計算・registry 追加の経路が広く探索される。
    let opts = RuleLoadOptions {
        max_file_size_bytes: 16 * 1024 * 1024,
        ..RuleLoadOptions::default()
    };
    let mut registry = RuleRegistry::new();
    let _ = registry.load(&rule_path, dir.path(), &opts);

    // もう1回読み込むと重複検出経路も通る。
    let _ = registry.load(&rule_path, dir.path(), &opts);
});
