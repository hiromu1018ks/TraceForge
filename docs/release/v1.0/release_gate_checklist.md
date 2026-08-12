# TraceForge v1.0 Release Gate Checklist（T8-272・roadmap §8）

本文書は roadmap §8「完了条件（release gate）」および製品仕様書 §13.2「Release gate」の全項目に対する合否状況を記録する。TraceForge v1.0 Stable（M6）は以下の全項目を満たす。

## roadmap §8 release gate

| # | 項目 | 合否 | 根拠 |
|---|---|---|---|
| 1 | 対応対象が互換性仕様書で `Required` または `Supported` として明示されている | 合格 | 互換 §3〜§7 が Prefetch・EVTX・USN・LNK・Jump Lists・Amcache・Registry・Sigma・YARA-X を Required として明示。Phase 4〜5 で全て実装済み |
| 2 | Schema validation が成功する | 合格 | T1-056（Schema §9 全 fixture 合格）・T8-022（Golden output Schema 検証）・`crates/core/tests/schema_fixtures.rs`・`crates/export/tests/schema_tests.rs` |
| 3 | 同一 fixture を 1 thread と複数 thread で解析し、分析レコードが byte 単位で一致する | 合格 | T8-001（golden determinism test: threads 1/2/自動で canonical JSON byte 一致）・`crates/cli/tests/phase8_determinism_tests.rs` |
| 4 | 破損 fixture と fuzz corpus で input 起因 panic がない | 合格 | T8-010（破損 fixture 群で panic 非発生）・fuzz target 12種（`fuzz/fuzz_targets/`）・fuzz corpus（`fuzz/corpus/`）・`run_parser_catching_panic` 境界 |
| 5 | Parser issue、limit 到達、skip が Analysis Manifest へ残る | 合格 | T8-013（resource limit 到達時の `complete=false`）・T2-041（limit 到達時の5動作）・各 Parser の Issue 出力・Manifest `incomplete_reasons`・`limits` field |
| 6 | README 等の例が実際の fixture から生成されている | 合格 | T8-024（README 例の自動生成）・`docs/examples/`（合成 LNK fixture への analyze 出力） |
| 7 | benchmark 値は測定条件とともに実測値だけを掲載する | 合格 | T8-023（benchmark 実測）・`docs/release/v1.0/benchmark_report.md` |

## 規範 §21 受け入れ条件 15 項目

| # | 受け入れ条件 | 合否 | 対応タスク |
|---|---|---|---|
| 1 | timezone 不明 local time を UTC として出力しない | 合格 | T1-012・T1-014・T8-001 |
| 2 | timestamp 不明 Event の保持と末尾 group 出力 | 合格 | T1-014・T3-024 |
| 3 | snapshot 中の元 file 書換で Event を生成しない | 合格 | T2-015・T2-018・T8-012 |
| 4 | snapshot SHA-256 と Parser 読取 bytes の一致 | 合格 | T2-019 |
| 5 | 破損中間 record 前後の部分 Event 保持 | 合格 | T4-003・T4-006・T4-045 |
| 6 | 100万 Event で全件 Vec 不要求 | 合格 | T3-001・T3-009・T4-001 |
| 7 | threads 1/2/自動で canonical 出力 byte 一致 | 合格 | T8-001 |
| 8 | 同一 timestamp の Event ID 安定順 | 合格 | T3-021・T3-023 |
| 9 | input directory 内 output 拒否 | 合格 | T2-020・T2-021・T8-015 |
| 10 | symlink loop 非追跡 | 合格 | T2-003・T2-004・T8-015 |
| 11 | CSV formula / terminal ESC / HTML script の安全出力 | 合格 | T7-001・T7-004・T7-005・T7-008 |
| 12 | 未対応 Sigma 構文 Rule の全体 skip | 合格 | T5-011・T5-017 |
| 13 | YARA-X suspicious mode の host path 推測 scan 禁止 | 合格 | T5-026 |
| 14 | limit 到達時 `complete=false` | 合格 | T2-041・T8-013 |
| 15 | JSON / JSONL / Rule / Config の Schema validation | 合格 | T1-051・T1-056・T5-031・T8-022 |

## 互換 §12 compatibility acceptance 8 項目

| # | 項目 | 合否 | 根拠 |
|---|---|---|---|
| 1 | 正常 fixture から期待 Event を生成する | 合格 | T8-020（phase8_compat_tests.rs）・各 Parser の acceptance test |
| 2 | truncated・invalid length・unknown version で panic しない | 合格 | T8-010・T8-020・各 Parser fuzz target |
| 3 | Provenance が元 record へ到達する | 合格 | T4-091・T8-020・各 Parser の provenance_reachability_tests |
| 4 | 1 thread と複数 thread の出力が一致する | 合格 | T4-090・T8-001・T8-020 |
| 5 | fixture SHA-256・生成 OS・取得方法・期待結果を記録する | 合格 | `crates/parsers/tests/common/mod.rs` の `MS_SHLLINK_REFERENCE`・各 Parser fixture 記録・`docs/release/v1.0/external_specification_revisions.md` |
| 6 | 外部仕様を使う対象は revision を記録する | 合格 | T8-026・`docs/release/v1.0/external_specification_revisions.md` |
| 7 | 非対応 field・構文・version を黙って無視しない | 合格 | T4-007・T5-011（Sigma skip）・T4-023（Prefetch unsupported version）・各 Parser の Issue 出力 |
| 8 | Format 固有の意味を越えて Event type を断定しない | 合格 | T4-024・T4-054・T4-062・T8-020（観測型 Event の検証） |

## 品質ゲート自動化

| ゲート | 合否 | コマンド |
|---|---|---|
| フォーマット | 合格 | `cargo fmt --all --check` |
| フォーマット（fuzz crate） | 合格 | `cargo fmt --manifest-path fuzz/Cargo.toml --check` |
| Lint | 合格 | `cargo clippy --all-targets -- -D warnings` |
| テスト | 合格 | `cargo test` |
| ドキュメント | 合格 | `cargo doc --no-deps` |
| cargo-deny | 合格 | `cargo deny check` |
| fuzz ビルド | 合格 | `cargo check --manifest-path fuzz/Cargo.toml` |
| benchmark ビルド | 合格 | `cargo bench --no-run` |

## 結論

TraceForge v1.0 Stable（M6）は roadmap §8 release gate 全項目・規範 §21 受け入れ条件 15 項目・互換 §12 compatibility acceptance 8 項目の全てを満たす。
