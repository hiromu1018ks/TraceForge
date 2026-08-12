# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトのひな形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 6 Finding 統合と ATT&CK 編（T6-001〜T6-009）＝ 次回実装開始** 用に記入済み。
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
Phase 5 Correlation 編（T5-030〜T5-042）は完了済み（`tf-engines` に複数 Event の時系列パターン評価エンジンを実装。`src/correlation/` module（`rule.rs`: Schema §7 CorrelationRule 構造体・YAML parser・Schema validation・`within` 上限検査、`predicate.rs`: 8種 operator（eq/neq/contains/starts_with/ends_with/regex/exists/in）・厳密比較（null・型の暗黙変換禁止）・case_sensitive flag、`fieldresolver.rs`: dot path → Event field 解決、`evaluator.rs`: sequence / step / where / bind 評価器・backtracking 探索・partition_by（hostname 不明時は非 match）・不確実時刻の既定非 match（allow_uncertain_time=true 時のみ許可 + 記録）・match 重複生成禁止・max_matches 打ち切り・score 計算（base + adjustments・clamp・level 変換）・同一 Evidence 二重加点防止・Match 型（match_type=correlation・score・ordered_event_ids）変換）・fuzz target・統合テスト 26件。Phase 5 完了・マイルストーン M4 前半到達。`tf-engines` 全テスト 318 合格・workspace 全テスト 1,067 合格）。

Phase 5 Correlation 編はこれで完了した。Phase 5 全体（共通編 + Sigma + YARA-X + Correlation）が完了し、3検知エンジンが揃った。次回は **Phase 6 Finding 統合と ATT&CK（T6-001〜T6-009）** を実施し、Sigma・YARA-X・Correlation の Match を人間が説明できる Finding へ統合することを推奨する。Phase 6 では Finding merger が「同じ Event/Evidence を参照するという理由だけで自動統合しない」（規範 §16）を担保しつつ、決定的 Finding ID（規範 §12.4）・Confidence score → level 変換（規範 §14.3）・ATT&CK STIX dataset の version pin と SHA-256 記録（互換 §9）・Technique ID 検証（不在 ID は Rule validation error）・mapping 生成（Rule / Sigma tag / built-in / manual のみ・規範 §15.3）を実装する。Correlation が持つ `score`・`ordered_event_ids` と Sigma の `logsource_mapping`・YARA-X の `matched_patterns` が Finding の説明可能性へどう活きるかが鍵となる。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 6 Finding 統合と ATT&CK 編（T6-001〜T6-009）を実装してください。

## プロジェクト基本情報
- 作業ディレクトリ: C:\Users\hirom\project\TraceForge
- Windows PowerShell (5.1) 環境。Shell: powershell。
- Rust 1.97.1（rust-toolchain.toml 固定）。mise 管理の場合は .mise.toml を参照。
- git リポジトリ。前フェーズまでコミット済み（Phase 5 Correlation 編含む）。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項・コマンド節
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 6 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §9 — 対象タスク一覧（T6-001〜T6-009）
4. docs/traceforge_normative_core_specification_v1.0.md §16（Finding）・§14.3（Confidence）・§15.3（ATT&CK mapping）・§12.4（Finding ID）・§17.2（Exit Code）
5. docs/traceforge_product_specification_v1.0.md §10（Finding の説明可能性要件）
6. docs/traceforge_compatibility_v1.0.md §9（ATT&CK 対応・dataset pin）・§11（依存 pin）
7. crates/core/src/finding.rs — Finding・Score・Confidence・AttackMapping・RuleRef 型（Phase 1 実装済み）
8. crates/core/src/id.rs — match_id・finding_id（rule_content_sha256_list・sorted_event_ids・sorted_evidence_ids）
9. crates/core/src/match_.rs — Match 型（3経路の match_type・拡張 field）
10. crates/engines/src/ — Phase 5 の3検知エンジン（Sigma・YARA-X・Correlation）と RuleRegistry
11. crates/findings/ — Phase 0 で空実装の crate（本フェーズで本格実装）

## 対象フェーズ・タスク

- Phase 6 Finding 統合と ATT&CK: 3検知結果を説明可能な Finding へ統合する
- タスク（今回）: T6-001 〜 T6-009
- 今回は Finding 統合と ATT&CK だけを実装すること。Phase 7（Exporter と CLI・T7-001〜）へ踏み込まない。
- Phase 5 で実装した3エンジン（Sigma・YARA-X・Correlation）の Match を入力とする設計とする。
- ATT&CK dataset は互換 §9 に従い STIX 形式を想定するが、本フェーズでは dataset file の SHA-256 と version 記録・Technique ID 検証が主眼。外部通信は禁止（規範 §2）。

## 成果物

- T6-001: Finding merger（Sigma・YARA-X・Correlation の Match を統合。match 喪失なし・規範 §16）
- T6-002: 自動統合禁止（明示統合 rule のみ許可・規範 §16）
- T6-003: Finding 必須 field 実装（severity / confidence / 参照 ID 群・規範 §16）
- T6-004: `Observed evidence` と `Inference` の分離記述（規範 §16・製品 §10）
- T6-005: Finding から全元 Event・Evidence・Rule hash への参照検証 test（製品 §10）
- T6-006: ATT&CK STIX dataset の version pin・SHA-256・取得元記録（互換 §9・§11）
- T6-007: Technique ID の dataset 存在検証（不在 ID は Rule validation error・互換 §9）
- T6-008: ATT&CK mapping 生成（Rule / Sigma tag / built-in / manual のみ・規範 §15.3）
- T6-009: ATT&CK mapping への dataset version + hash 記録（規範 §15.3）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Finding は `created_at` を持ってはならない（Schema §5.8・Phase 1 で実装済み）
- Finding merger は「同じ Event/Evidence を参照するという理由だけで異なる Finding を自動統合してはならない。統合 rule が明示されている場合だけ統合する」（規範 §16）
- Finding ID は決定的生成のみ（規範 §12.4）。UUID・乱数・実行時刻由来を禁止
- ATT&CK dataset の取得は手動（外部通信禁止・規範 §2）。取得元 URL・version・SHA-256 を Manifest へ記録するが、本フェーズでは dataset を同梱しての配布はしない
- 決定性（規範 §13）。Finding 順序・attribute 順序は安定。iterator 順に依存しない
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 6 の初学者向け解説 md を作成する（phase6.md）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番詰め替え禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節・モジュール構成節へ追記する（新依存を追加した場合のみ）
  4. ローカルで fmt / clippy / test / doc / deny / `cargo check --manifest-path fuzz/Cargo.toml` / `cargo bench --no-run` が通ることを確認
  5. 上記が全て通ったらコミットする（ユーザーへの個別確認は不要・本プロジェクトの既定）。push はしない。コミットメッセージは `feat(findings): Phase 6 Finding 統合と ATT&CK - ...` の形式で直近コミットのスタイルに合わせる。
  6. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 6・規範 §16・§15.3・製品 §10・互換 §9 より）

- Finding merger が3経路（Sigma・YARA-X・Correlation）の Match を喪失なく統合する
- 自動統合が禁止され、明示統合 rule のみ統合を許可する
- Finding が必須 field（severity / confidence / event_ids / evidence_ids / match_ids / rule_refs 等）を持つ
- `observed_evidence` と `inference` が分離して記述される（推測を含まない観測事実と推論の分離）
- Finding から全元 Event・Evidence・Rule hash へ参照が到達できる（製品 §10）
- ATT&CK STIX dataset の version と SHA-256 が Manifest へ記録される（互換 §9）
- 不在の Technique ID が Rule validation error として扱われる
- ATT&CK mapping が Rule / Sigma tag / built-in / manual のみから生成される
- ATT&CK mapping へ dataset version + hash が記録される
- 既存の全テストが引き続き通る（回帰無し）
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 4 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 4 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。
- Phase 3 の成果（`tf-store`）は Phase 4 以降も前提となる。EventStore・TimelineKey・SortedEventIter・最小 JSONL / Manifest 出力を再利用すること。
- Phase 4 の成果（`tf-parsers` の framework・sink・issue helper・全7種 Parser）は以降も前提となる。
- Phase 5 共通編の成果（`RuleRegistry`・`LoadedRuleFile`・`RuleLoadOptions`・`RuleLoadSummary`・`RuleLoadError`・`discover_rule_directory`・`load_directory`・`LoadedRuleFile::raw_bytes`・`sha256`・`relative_path`）は Sigma・YARA-X・Correlation 全てへ共通する前提となる。各 engine は `RuleRegistry::load_directory` で読み込んだ `LoadedRuleFile` の `raw_bytes()` を借りて parse/compile へ渡す（規範 §14: 同じ bytes を使う）。`LoadedRuleFile::sha256` を `match_id` の `rule_content_sha256` へ使う。`RuleLoadError::exit_code(strict_rules)` で validation error を Exit Code 5/1 へ区分する。
- Phase 5 Sigma 編の成果（`src/yaml/` 共有 YAML parser・`src/sigma/` Sigma subset evaluator・`CompiledSigmaRule`・`SigmaMatchResult`）は Phase 6 以降も前提となる。Finding 統合では Sigma Match の `logsource_mapping` 拡張 field を Finding の説明情報へ活用できる。
- Phase 5 YARA-X 編の成果（`src/yara/` YARA-X scan engine・`yara-x` crate pin・advisory 例外登録・`CompiledYaraFile`・`YaraScanner`・`YaraMatchResult`）は Phase 6 以降も前提となる。Finding 統合では YARA-X Match の `matched_patterns` 拡張 field を Finding の説明情報へ活用できる。
- Phase 5 Correlation 編の成果（`src/correlation/` Correlation evaluator・`CompiledCorrelationRule`・`CorrelationEvaluationResult`・regex/chrono workspace 依存・`src/yaml/` の `Float(f64)` 拡張）は Phase 6 以降も前提となる。Finding 統合では Correlation Match の `score` と `ordered_event_ids` 拡張 field が Finding の confidence 計算・時系列説明へ直結する。Phase 6 では Phase 5 の3エンジンが生成した Match list を入力とする merger を `tf-findings` crate へ実装する。
