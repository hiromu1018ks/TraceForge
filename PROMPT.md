# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 5 YARA-X 編（T5-020〜T5-027）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。
Phase 4 前半（Parser framework + LNK）は完了済み（`tf-parsers` に `ArtifactParser` / `ParseSink` / `ParseSummary`・panic 境界・sanitize Issue helper・`EventStoreSink`・LNK Parser（[MS-SHLLINK]・観測型 `lnk_timestamp` Event）・合成 fixture + acceptance test 8条件・M2 縦割り（LNK → EventStore → Timeline → Case JSON + Manifest）を実装、93 テスト合格）。
Phase 4 後半 Prefetch（T4-020〜T4-025）は完了済み（`tf-parsers` 全テスト 152 合格）。
Phase 4 後半 USN Journal（T4-030〜T4-037）は完了済み（`tf-parsers` 全テスト 223 合格）。
Phase 4 後半 EVTX（T4-040〜T4-046）は完了済み（`tf-parsers` 全テスト 280 合格）。
Phase 4 後半 Registry（T4-050〜T4-055）は完了済み（`tf-parsers` 全テスト 374 合格）。
Phase 4 後半 Amcache（T4-060〜T4-065）は完了済み（`tf-parsers` 全テスト 415 合格）。
Phase 4 後半 Jump Lists（T4-070〜T4-074）は完了済み（`tf-parsers` 全テスト 465 合格）。
Phase 4 共通検証（T4-090〜T4-092）は完了済み（`tf-parsers` 全テスト 484 合格・マイルストーン M3 到達）。
Phase 5 共通編（T5-001〜T5-003）は完了済み（`tf-engines` に Sigma・YARA-X・Correlation 全てへ共通する Rule file 取扱基盤を実装。`RuleRegistry`・SHA-256 重複検出・UTF-8 byte 順 directory 列挙・Exit Code 5 区分・`path_norm` module・fuzz target。`tf-engines` 全テスト 58 合格・workspace 全テスト 791 合格）。
Phase 5 Sigma 編（T5-010〜T5-017）は完了済み（`tf-engines` に TF-SIGMA-1.0 subset evaluator を実装。Sigma・Correlation 共有の最小 YAML parser（`src/yaml/`）を自前実装（anchor/alias/tag/duplicate key/multi-doc/block scalar 禁止・panic 安全）。Sigma YAML parser + subset validator（T5-010）・未対応要素含有 Rule の全体 skip（T5-011）・logsource routing（T5-012）・selection/condition/quantifier 評価器（T5-013）・6種 modifier（T5-014）・field mapping（T5-015）・Sigma match → Match 型変換（T5-016）・未対応構文 skip test（T5-017・§21-12）・Sigma fuzz target。`tf-engines` 全テスト 183 合格・workspace 全テスト 916 合格）。

Phase 5 Sigma 編はこれで完了した。次回は **Phase 5 YARA-X 編（T5-020〜T5-027）** を実施し、YARA-X crate を用いたファイルパターンスキャンを実装することを推奨する。YARA-X 編では共通編の `RuleRegistry` が読み込んだ raw bytes を YARA-X crate へ渡し compile する。Sigma とは異なり YARA-X は外部 crate（`yara-x`）へ依存し、compile error の file 全体無効化・Verified Snapshot のみ scan・`all/suspicious/explicit` mode・`max_yara_scan_file_size_bytes` limit を実装する（規範 §15.2）。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 5 YARA-X 編（T5-020〜T5-027）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 5 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §8.3 — 対象タスク一覧（T5-020〜T5-027）
4. docs/traceforge_normative_core_specification_v1.0.md §15.2（YARA-X）・§17.2（Exit Code）
5. docs/traceforge_compatibility_v1.0.md §7（YARA-X Compatibility Profile）
6. docs/traceforge_schemas_v1.0.md §5.7（Match）・§8.2/8.3（Config limits・yara mode）
7. crates/engines/src/loader.rs — Phase 5 共通編の RuleRegistry・LoadedRuleFile・RuleLoadOptions
8. crates/engines/src/lib.rs・path_norm.rs — 公開 API・path 正規化
9. crates/engines/src/sigma/ — Phase 5 Sigma 編の実装（YAML parser・評価器の参考）
10. crates/core/src/match_.rs・id.rs — Match 型・match_id(rule_id, rule_content_sha256, ordered_event_ids)
11. crates/core/src/config.rs — YaraConfig.mode・rule_dirs・LimitsConfig

## 対象フェーズ・タスク

- Phase 5 YARA-X 編: YARA-X crate によるファイルパターンスキャン
- タスク（今回）: T5-020 〜 T5-027
- 今回は YARA-X 編だけを実装すること。Correlation（T5-030〜T5-042）へ踏み込まない。
- 共通編（T5-001〜T5-003）の RuleRegistry・LoadedRuleFile を前提とし、raw_bytes() で借りた bytes を YARA-X compiler へ渡す設計とする（規範 §14: 同じ bytes を使う）。

## 成果物

- T5-020: YARA-X crate pin + Cargo.lock checksum 記録（互換 §7）。`yara-x` crate を workspace へ追加し、deny.toml へ許可ライセンスを反映する。
- T5-021: `.yar`/`.yara` file・directory 再帰 load（互換 §7）。RuleRegistry が読み込んだ raw bytes を YARA-X compiler へ渡す。
- T5-022: tags/meta/namespace/matched pattern identifier 保持（互換 §7、Schema §5.7）。YARA-X scan 結果から Match 型（match_type=yara_x・matched_patterns 保持）を構築する。
- T5-023: compile error 時の file 全体無効化・他 file 継続（規範 §15.2）。compile error が1件でもある Rule file は全体を無効とし、他の正常 Rule file は strict rules mode でない限り継続する。
- T5-024: Verified Snapshot のみ scan（実行・load 禁止、規範 §15.2）。snapshot 検証済みの Evidence file のみを scan 対象とする。
- T5-025: `all / suspicious / explicit` mode（Schema §8.3、規範 §15.2）。Config の yara.mode に従い scan 対象を制御する。
- T5-026: suspicious mode の Evidence ID 解決（host path 推測 scan 禁止、規範 §15.2・§21-13）。Event 内 Windows path ではなく、Finding/Correlation が参照する Evidence ID から snapshot を解決する。
- T5-027: `max_yara_scan_file_size_bytes` 適用（Schema §8.2）。scan 対象 file size が上限を超える場合は skip し Warning を記録する。

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- YARA-X crate の完全 version と Cargo.lock checksum を Manifest へ記録する（互換 §7: `latest` を使わない）
- YARA-X は Verified Snapshot だけを scan する（規範 §15.2）。scan 対象を実行・load・shell open してはならない
- 新依存 crate（yara-x 等）を追加する場合は deny.toml と workspace Cargo.toml と AGENTS.md「依存構成」節へ反映する
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 5 YARA-X 編の初学者向け解説 md を作成する（phase5c.md）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番詰め替え禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny / `cargo check --manifest-path fuzz/Cargo.toml` / `cargo bench --no-run` が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 5・規範 §15.2・§21-13・互換 §7 より）

- YARA-X crate が pin 済みで Cargo.lock checksum が記録される
- `.yar`/`.yara` file と directory が再帰 load される
- Rule compile error が file 全体を無効化し、他 file は継続する
- Verified Snapshot のみが scan される（実行・load 禁止）
- `all / suspicious / explicit` mode が動作する
- suspicious mode で Evidence ID へ解決できない host path を scan しない（§21-13）
- `max_yara_scan_file_size_bytes` が適用される
- YARA-X match が Match 型（match_type=yara_x・matched_patterns 保持）へ変換される
- 共通編の RuleRegistry・LoadedRuleFile・SHA-256 を使い回す（規範 §14: 同じ bytes を使う）
- 既存の全テストが引き続き通る（回帰無し）
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 4 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 4 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。YARA-X 編では Verified Snapshot のみ scan するため、snapshot 機構が特に重要。
- Phase 3 の成果（`tf-store`）は Phase 4 以降も前提となる。EventStore・TimelineKey・SortedEventIter・最小 JSONL / Manifest 出力を再利用すること。Parser が生成した Event は ParseSink 経由で EventStore へ逐次保存する。
- Phase 4 の成果（`tf-parsers` の framework・sink・issue helper・全7種 Parser）は以降も前提となる。YARA-X 編では Parser が生成した Event を入力とし、YARA scan は Evidence file へ対して行う。
- Phase 5 共通編の成果（`RuleRegistry`・`LoadedRuleFile`・`RuleLoadOptions`・`RuleLoadSummary`・`RuleLoadError`・`discover_rule_directory`・`load_directory`・`LoadedRuleFile::raw_bytes`・`sha256`・`relative_path`）は Sigma・YARA-X・Correlation 全てへ共通する前提となる。各 engine は `RuleRegistry::load_directory` で読み込んだ `LoadedRuleFile` の `raw_bytes()` を借りて parse/compile へ渡す（規範 §14: 同じ bytes を使う）。`LoadedRuleFile::sha256` を `match_id` の `rule_content_sha256` へ使う。`RuleLoadError::exit_code(strict_rules)` で validation error を Exit Code 5/1 へ区分する。
- Phase 5 Sigma 編の成果（`src/yaml/` 共有 YAML parser・`src/sigma/` Sigma subset evaluator）は以降も前提となる。Correlation 編（T5-030〜）は `src/yaml/` module を再利用する。Sigma fuzz target（`fuzz/fuzz_targets/sigma.rs`）と Sigma 統合テスト（`tests/sigma_tests.rs`）も引き続き通すこと。
