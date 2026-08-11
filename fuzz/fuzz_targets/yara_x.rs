// YARA-X compiler/scanner fuzz target（Phase 5 YARA-X 編・T5-020〜T5-027、F-025）。
//
// libFuzzer が生成した raw bytes を YARA Rule source として扱い、compile と scan の
// 両方を試みる。破損入力・不正 YARA 構文・巨大入力で panic しないことを継続的
// fuzzing で検証する。
//
// 経路:
// 1. raw bytes を一時 file へ書き出し、RuleRegistry へ読込ませる。
// 2. YaraRuleset::compile_from_registry へ投げる（compile 経路）。
// 3. compile 成功した ruleset で YaraScanner を構築し、固定 bytes を scan する
//    （scan 経路）。
//
// いずれの経路も `Result` ベースの error 処理であり panic しない設計。本 target は
// その保証を継続的 fuzzing で担保する（規範 §9.4: 最終安全網）。
//
// fuzzing の実行は Linux CI のみで行う（Windows MSVC では libfuzzer-sys の link が
// 失敗するため、本プロジェクトでは `cargo check --manifest-path fuzz/Cargo.toml`
// でビルド検証する）。

#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use tf_engines::yara::scanner::{YaraEvidenceScanTarget, YaraScanner};
use tf_engines::{RuleLoadOptions, RuleRegistry, YaraRuleset};

fuzz_target!(|data: &[u8]| {
    // 一時 directory 上の単一 file へ raw bytes を書き出す。
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let rule_path = dir.path().join("fuzz.yar");
    {
        let mut f = match std::fs::File::create(&rule_path) {
            Ok(f) => f,
            Err(_) => return,
        };
        if f.write_all(data).is_err() {
            return;
        }
    }

    // RuleRegistry へ読み込む（共通編 T5-001〜T5-003 の経路）。
    let opts = RuleLoadOptions {
        max_file_size_bytes: 16 * 1024 * 1024,
        ..RuleLoadOptions::default()
    };
    let mut registry = RuleRegistry::new();
    let _ = registry.load(&rule_path, dir.path(), &opts);

    // compile 経路: panic しないことを検証。
    let summary = YaraRuleset::compile_from_registry(&registry);

    // scan 経路: ruleset が空でなければ、固定 bytes を scan する。
    if summary.compiled_len() > 0 {
        let ruleset = summary.into_ruleset();
        let scanner = YaraScanner::new(ruleset, 1024 * 1024);
        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:fuzz".into(),
            snapshot_bytes: b"fuzz scan target",
        };
        let _ = scanner.scan(&[target]);
    }
});
