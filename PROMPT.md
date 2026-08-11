# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 5 Correlation 編（T5-030〜T5-042）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。
Phase 4 前半（Parser framework + LNK）は完了済み（`tf-parsers` に `ArtifactParser` / `ParseSink` / `ParseSummary`・panic 境界・sanitize Issue helper・`EventStoreSink`・LNK Parser（[MS-SHLLINK]・観測型 `lnk_timestamp` Event）・合成 fixture + acceptance test 8条件・M2 縦割き（LNK → EventStore → Timeline → Case JSON + Manifest）を実装、93 テスト合格）。
Phase 4 後半 Prefetch（T4-020〜T4-025）は完了済み（`tf-parsers` 全テスト 152 合格）。
Phase 4 後半 USN Journal（T4-030〜T4-037）は完了済み（`tf-parsers` 全テスト 223 合格）。
Phase 4 後半 EVTX（T4-040〜T4-046）は完了済み（`tf-parsers` 全テスト 280 合格）。
Phase 4 後半 Registry（T4-050〜T5-055）は完了済み（`tf-parsers` 全テスト 374 合格）。
Phase 4 後半 Amcache（T4-060〜T4-065）は完了済み（`tf-parsers` 全テスト 415 合格）。
Phase 4 後半 Jump Lists（T4-070〜T4-074）は完了済み（`tf-parsers` 全テスト 465 合格）。
Phase 4 共通検証（T4-090〜T4-092）は完了済み（`tf-parsers` 全テスト 484 合格・マイルストーン M3 到達）。
Phase 5 共通編（T5-001〜T5-003）は完了済み（`tf-engines` に Sigma・YARA-X・Correlation 全てへ共通する Rule file 取扱基盤を実装。`RuleRegistry`・SHA-256 重複検出・UTF-8 byte 順 directory 列挙・Exit Code 5 区分・`path_norm` module・fuzz target。`tf-engines` 全テスト 58 合格・workspace 全テスト 791 合格）。
Phase 5 Sigma 編（T5-010〜T5-017）は完了済み（`tf-engines` に TF-SIGMA-1.0 subset evaluator を実装。Sigma・Correlation 共有の最小 YAML parser（`src/yaml/`）を自前実装（anchor/alias/tag/duplicate key/multi-doc/block scalar 禁止・panic 安全）。Sigma YAML parser + subset validator（T5-010）・未対応要素含有 Rule の全体 skip（T5-011）・logsource routing（T5-012）・selection/condition/quantifier 評価器（T5-013）・6種 modifier（T5-014）・field mapping（T5-015）・Sigma match → Match 型変換（T5-016）・未対応構文 skip test（T5-017・§21-12）・Sigma fuzz target。`tf-engines` 全テスト 183 合格・workspace 全テスト 916 合格）。
Phase 5 YARA-X 編（T5-020〜T5-027）は完了済み（`tf-engines` に YARA-X crate（v1.19・pin + Cargo.lock checksum）を用いたファイルパターンスキャンエンジンを実装。`src/yara/` module（`compiler.rs`: file 毎独立 Compiler 構築・include 禁止・compile error 時の file 全体無効化、`scanner.rs`: Verified Snapshot bytes のみ scan・3 mode（all/suspicious/explicit）・max_yara_scan_file_size_bytes limit・host path 推測禁止、`match.rs`: tags/meta/namespace/matched pattern identifier 保持・Schema §5.7 Match 型変換）・fuzz target・統合テスト（§21-13）。`tf-engines` 全テスト 238 合格・workspace 全テスト 972 合格）。

Phase 5 YARA-X 編はこれで完了した。次回は **Phase 5 Correlation 編（T5-030〜T5-042）** を実施し、複数 Event の時系列パターン評価エンジンを実装することを推奨する。Correlation 編では共通編の `RuleRegistry` と Sigma 編の `src/yaml/` parser を再利用し、Schema §7 の Correlation Rule 形式を評価する。Sigma・YARA-X とは異なり Correlation は Event 間の関係（sequence・step・within・partition_by 等）を評価し、Phase 6 の Finding 統合で重要な役割を果たす。score 計算（base + adjustments・clamp・level 変換）と同一 Evidence 事実の二重加点防止が特に重要（規範 §14.3・§16）。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 5 Correlation 編（T5-030〜T5-042）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 5 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §8.4 — 対象タスク一覧（T5-030〜T5-042）
4. docs/traceforge_schemas_v1.0.md §7 — Correlation Rule Schema（最重要）
5. docs/traceforge_normative_core_specification_v1.0.md §14（Correlation Rule）・§14.1（評価規則）・§14.2（match 重複・max_matches・Exit Code）・§14.3（score 計算）・§17.2（Exit Code）
6. crates/engines/src/loader.rs — Phase 5 共通編の RuleRegistry・LoadedRuleFile・RuleLoadOptions
7. crates/engines/src/yaml/ — Phase 5 Sigma 編で実装した YAML parser（Correlation でも再利用）
8. crates/engines/src/sigma/ — Sigma 編の実装参考（rule 構造・evaluator 構成）
9. crates/core/src/match_.rs — Match 型（match_type=correlation・score・ordered_event_ids）
10. crates/core/src/id.rs — match_id(rule_id, rule_content_sha256, ordered_event_ids)
11. crates/core/src/finding.rs — Score・ScoreAdjustment・score 計算参考

## 対象フェーズ・タスク

- Phase 5 Correlation 編: 複数 Event の時系列パターン評価エンジン
- タスク（今回）: T5-030 〜 T5-042
- 今回は Correlation 編だけを実装すること。Phase 6（Finding 統合・T6-001〜）へ踏み込まない。
- 共通編（T5-001〜T5-003）の RuleRegistry・LoadedRuleFile と Sigma 編の `src/yaml/` parser を前提とし、raw_bytes() で借りた bytes を YAML parser へ渡す設計とする（規範 §14: 同じ bytes を使う）。
- Schema §7 の Correlation Rule 形式（sequence / step / where / bind / partition_by / within / max_correlation_window_seconds 等）を実装する。

## 成果物

- T5-030: Correlation Rule YAML parser（anchor/alias/custom tag/duplicate key 禁止・Schema §7・規範 §14）。Sigma 編の `src/yaml/` module を再利用する。
- T5-031: Correlation Rule Schema validation（Schema §7）。
- T5-032: sequence / step / where / bind 評価器（Schema §7）。複数 Event の時系列順評価。
- T5-033: predicate operator 8種（eq/neq/contains/starts_with/ends_with/regex/exists/in、Schema §7）。
- T5-034: `within` 両端含む・`max_correlation_window_seconds` 上限（規範 §14.1・Schema §8.3）。
- T5-035: `partition_by`（case_id/hostname/user、規範 §14.1）。
- T5-036: hostname 不明時の既定非 match（規範 §14.1）。
- T5-037: 不確実時刻の既定非 match・`allow_uncertain_time` 明示時のみ許可 + 記録（規範 §6.4）。
- T5-038: null・型の厳密比較（暗黙変換禁止、規範 §14.1）。
- T5-039: 未対応 operator の Rule 全体 skip（規範 §14.1）。
- T5-040: match 重複生成禁止・`max_matches` 打ち切り・Exit Code 1/5（規範 §14.2）。
- T5-041: score 計算（base + adjustments、clamp、level 変換、規範 §14.3）。
- T5-042: 同一 Evidence 事実の二重加点防止（規範 §14.3）。

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Correlation Rule は Schema §7 の形式へ厳密に従う。anchor/alias/tag/duplicate key/multi-doc/block scalar/tab を検出次第 error とする（規範 §14・Schema §7）
- Correlation 評価は EventStore（`tf-store`）の Event を入力とするが、本 engine は Event の iterator（`impl Iterator<Item = Event>`）を受け取る設計とし、`tf-store` への依存は追加しない（依存方向: tf-engines → tf-core のみ）
- 決定性（規範 §13）。match 順序・score 計算・attribute 順序は安定
- ID 決定的生成のみ（規範 §12）。`match_id` は `ordered_event_ids` を反映する
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 5 Correlation 編の初学者向け解説 md を作成する（phase5d.md）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番詰め替え禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny / `cargo check --manifest-path fuzz/Cargo.toml` / `cargo bench --no-run` が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 5・規範 §14・§14.1〜§14.3・Schema §7 より）

- Correlation Rule YAML parser が Schema §7 へ従い parse する
- Schema validation が Correlation Rule の必須 field・型を検証する
- sequence / step / where / bind 評価器が複数 Event の時系列パターンを検知する
- 8種 predicate operator が正しく評価される
- `within` が両端を含み、`max_correlation_window_seconds` を超える Rule は validation error
- `partition_by`（case_id/hostname/user）が正しく動作する
- hostname 不明時は既定で非 match
- 不確実時刻は既定で非 match、`allow_uncertain_time` 明示時のみ許可 + 記録
- null・型の厳密比較（暗黙変換禁止）
- 未対応 operator を含む Rule は全体 skip
- match 重複生成禁止・`max_matches` 打ち切り・Exit Code 1/5 が動作する
- score 計算（base + adjustments・clamp・level 変換）が正しい
- 同一 Evidence 事実の二重加点が防止される
- Correlation match が Match 型（match_type=correlation・score・ordered_event_ids 保持）へ変換される
- 共通編の RuleRegistry・LoadedRuleFile・SHA-256・Sigma 編の `src/yaml/` parser を使い回す（規範 §14: 同じ bytes を使う）
- 既存の全テストが引き続き通る（回帰無し）
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 4 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 4 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。Correlation 編では Score 計算で Evidence ID 参照が重要となる（§14.3: 同一 Evidence 二重加点防止）。
- Phase 3 の成果（`tf-store`）は Phase 4 以降も前提となる。EventStore・TimelineKey・SortedEventIter・最小 JSONL / Manifest 出力を再利用すること。Correlation 編では EventStore の Event を評価対象とする。
- Phase 4 の成果（`tf-parsers` の framework・sink・issue helper・全7種 Parser）は以降も前提となる。Correlation 編では Parser が生成した Event を時系列評価の入力とする。
- Phase 5 共通編の成果（`RuleRegistry`・`LoadedRuleFile`・`RuleLoadOptions`・`RuleLoadSummary`・`RuleLoadError`・`discover_rule_directory`・`load_directory`・`LoadedRuleFile::raw_bytes`・`sha256`・`relative_path`）は Sigma・YARA-X・Correlation 全てへ共通する前提となる。各 engine は `RuleRegistry::load_directory` で読み込んだ `LoadedRuleFile` の `raw_bytes()` を借りて parse/compile へ渡す（規範 §14: 同じ bytes を使う）。`LoadedRuleFile::sha256` を `match_id` の `rule_content_sha256` へ使う。`RuleLoadError::exit_code(strict_rules)` で validation error を Exit Code 5/1 へ区分する。
- Phase 5 Sigma 編の成果（`src/yaml/` 共有 YAML parser・`src/sigma/` Sigma subset evaluator）は Correlation 編で再利用する。Correlation Rule も YAML 形式のため `src/yaml/` module をそのまま使う。Sigma fuzz target・統合テストも引き続き通すこと。
- Phase 5 YARA-X 編の成果（`src/yara/` YARA-X scan engine・`yara-x` crate pin・advisory 例外登録）は以降も前提となる。Correlation 編でも Match 型の `match_type=correlation` へ変換する設計は Sigma・YARA-X 編と一貫する。YARA-X fuzz target・統合テストも引き続き通すこと。
