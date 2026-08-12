# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトのひな形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 7 Exporter と CLI 編（T7-001〜T7-034）＝ 次回実装開始** 用に記入済み。
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
Phase 6 Finding 統合と ATT&CK（T6-001〜T6-009）は完了済み（`tf-findings` に Finding merger・ATT&CK dataset 読込・Technique ID 検証・mapping 生成を実装。`src/merger.rs`: Match list → Finding list への1:1 変換・明示統合 rule（`FindingMergeRule`）のみで統合を許可（自動統合禁止・規範 §16）・observed_evidence / inference 分離（製品 §10）・Schema §6 出力順（Severity 降順・finding_id 昇順）・match 喪失なし検証（`FindingMergeSummary::all_matches_referenced`）・決定的 Finding ID（規範 §12.4）、`src/attack/` module（`dataset.rs`: STIX bundle bytes から SHA-256 計算と technique 抽出・version pin・取得元記録（互換 §9）、`technique.rs`: Technique ID 形式検証（`T<4桁>(.<3桁>)?`）と dataset 存在検証（不在 ID は `UnknownTechniqueError`・Rule validation error）、`mapping.rs`: 4経路（Rule / Sigma tag / built-in / manual）のみ ATT&CK mapping 生成（規範 §15.3）・dataset version + hash 記録）・統合テスト 20件・マイルストーン M4 到達。`tf-core` の `AttackMapping` 型を拡張（`tactic` / `source` / `dataset_version` / `dataset_sha256` 追加）・`AttackMappingSource` enum 新設。`tf-findings` 全テスト 63 合格・workspace 全テスト 1,130 合格）。

Phase 6 Finding 統合と ATT&CK 編はこれで完了した。M4 マイルストーン（検知・統合完成）に到達した。次回は **Phase 7 Exporter と CLI（T7-001〜T7-034）** を実施し、6種の出力形式（Text / JSON / JSONL / CSV / HTML / Timesketch）と9種の CLI command（`analyze` / `timeline` / `correlate` / `sigma` / `yara` / `export` / `rules` / `inspect` / `version`）を完成させることを推奨する。Phase 7 では出力安全性（CSV formula injection・terminal ESC escape・HTML CSP・規範 §19）の実装・Manifest 確定処理（規範 §20・全必須 field の集約）・ATT&CK dataset への path を受け取る CLI option・run metadata が分析 determinism へ影響しないことの検証（規範 §13.1・§20）が鍵となる。Phase 6 で作った `FindingBuilder`・`AttackDataset`・`AttackDatasetManifest` が CLI から直接呼び出される。Timesketch exporter（T7-006）は必須 field を満たし、変換不可 Event の除外 + summary 記録 + Exit Code 1 を実装する点に注意。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 7 Exporter と CLI 編（T7-001〜T7-034）を実装してください。

## プロジェクト基本情報
- 作業ディレクトリ: C:\Users\hirom\project\TraceForge
- Windows PowerShell (5.1) 環境。Shell: powershell。
- Rust 1.97.1（rust-toolchain.toml 固定）。mise 管理の場合は .mise.toml を参照。
- git リポジトリ。Phase 6 Finding 統合と ATT&CK 編までコミット済み。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項・コマンド節
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 7 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §10 — 対象タスク一覧（T7-001〜T7-034）
4. docs/traceforge_normative_core_specification_v1.0.md §19（Output safety）・§17（Exit Code）・§20（Analysis Manifest）・§13.1（determinism 分離）
5. docs/traceforge_product_specification_v1.0.md §11（出力）・§12（CLI）・§13.2（品質要件）
6. docs/traceforge_compatibility_v1.0.md §8（Timesketch）・§10（Output Compatibility）・§11（Dependency と License）
7. docs/traceforge_schemas_v1.0.md §5（Case JSON Schema）・§6（JSONL Schema・出力順）
8. crates/core/src/jsonl.rs — Phase 3 の最小 JSONL 出力（正式版は Phase 7 へ引き継ぐ）
9. crates/core/src/manifest.rs — Manifest 型（Phase 7 で集約処理を実装）
10. crates/core/src/case.rs — CaseMetadata・EvidenceItem・ArtifactInstance
11. crates/findings/src/ — Phase 6 の FindingBuilder・AttackDataset
12. crates/engines/src/ — Phase 5 の3検知エンジンと RuleRegistry
13. crates/export/ と crates/cli/ — Phase 0 で空実装の2 crate（本フェーズで本格実装）

## 対象フェーズ・タスク

- Phase 7 Exporter と CLI 完成: 全出力形式と全 command を完成させ、製品として使える状態にする
- タスク（今回）: T7-001 〜 T7-034
- 今回は Exporter と CLI だけを実装すること。Phase 8（品質保証とリリース・T8-001〜）へ踏み込まない。
- 6種の出力形式（Text / JSON / JSONL / CSV / HTML / Timesketch）と9種の CLI command を完成させる。
- Manifest 確定処理（規範 §20 の全必須 field）を実装する。
- ATT&CK dataset への path・version・source URL を受け取る CLI option を追加する。

## 成果物

### 10.1 Exporter（T7-001〜T7-009）

- T7-001: Text exporter（制御文字・ESC の可視 escape、規範 §19.1）
- T7-002: JSON exporter（Case JSON Schema、Schema §5）
- T7-003: JSONL exporter（固定出力順、Manifest 必ず最終行、Schema §6）
- T7-004: CSV exporter（RFC 4180、formula injection 対策 + `csv_sanitized` 記録、規範 §19.2）
- T7-005: HTML exporter（offline、CSP 埋込、text node escape、外部 request なし、規範 §19.3）
- T7-006: Timesketch exporter（必須 field、変換不可 Event の除外 + summary 記録 + Exit Code 1、互換 §8）
- T7-007: JSON/JSONL 出力の UTF-8・LF・NaN/Infinity 禁止（規範 §19.4）
- T7-008: 出力 injection test（CSV formula / terminal ESC / HTML script、規範 §21-11）
- T7-009: 異 Schema major version の自動変換禁止（互換 §10）

### 10.2 CLI（T7-020〜T7-034）

- T7-020: CLI 骨格（`traceforge <COMMAND> [OPTIONS]`、製品 §12）
- T7-021: `analyze`（既定 read-only / recursive / SHA-256 / 外部通信なし、規範 §2）
- T7-022: `--no-hash` を提供しないことの確認（規範 §2）
- T7-023: `timeline`（表示・filter、製品 §12）
- T7-024: `correlate`（保存済み Event へ適用、製品 §12）
- T7-025: `sigma`（保存済み Event へ適用、製品 §12）
- T7-026: `yara`（明示 Evidence へ適用、製品 §12）
- T7-027: `export`（Case 変換、製品 §12）
- T7-028: `rules`（validate・一覧、製品 §12）
- T7-029: `inspect`（単一 Artifact の安全な概要、製品 §12）
- T7-030: `version`（tool・Schema・compatibility profile、製品 §12）
- T7-031: 危険 option の警告と Manifest 記録（製品 §12）
- T7-032: Manifest 確定処理（全必須 field、規範 §20）
- T7-033: run metadata が分析 determinism へ影響しないことの test（規範 §20）
- T7-034: stdout = 解析結果、stderr = log、quiet で結果非抑制（規範 §19.1）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- 出力の既定上書き禁止、入力 directory 内への出力は拒否（規範 §5.4）
- `--no-hash` option を実装してはならない（規範 §2・AGENTS.md 禁止事項）
- 外部通信は禁止（規範 §2）。ATT&CK dataset は手動で file を渡す
- 出力安全性（規範 §19）: CSV formula injection・HTML script injection・terminal ESC escape を防ぐ
- 異なる Schema major version の自動変換は禁止（互換 §10）
- run metadata（run_started_at・OS PID・temp dir・elapsed time・CPU/RAM 使用量）は determinism 比較から除外する（規範 §13.1・§20）
- 決定性（規範 §13）。出力順・attribute 順序は安定。iterator 順に依存しない
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 7 の初学者向け解説 md を作成する（phase7.md）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節・モジュール構成節へ追記する（新依存を追加した場合のみ）
  4. ローカルで fmt / clippy / test / doc / deny / `cargo check --manifest-path fuzz/Cargo.toml` / `cargo bench --no-run` が通ることを確認
  5. 上記が全て通ったらコミットする（ユーザーへの個別確認は不要・本プロジェクトの既定）。push はしない。コミットメッセージは `feat(export,cli): Phase 7 Exporter と CLI - ...` の形式で直近コミットのスタイルに合わせる。
  6. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 7・規範 §19・§20・§17.2・製品 §11・§12・互換 §8・§10 より）

- 6種の出力形式（Text / JSON / JSONL / CSV / HTML / Timesketch）が動作する
- 出力 injection 対策（CSV formula / terminal ESC / HTML script）が test で検証される（規範 §21-11）
- Schema validation が出力に対して成功する（規範 §21-15）
- Timesketch 除外件数記録が動作する
- 異 Schema major version の自動変換が禁止される（互換 §10）
- 9種の command（analyze / timeline / correlate / sigma / yara / export / rules / inspect / version）が動作する
- Manifest が全必須 field を持つ（規範 §20）
- run metadata が分析 determinism へ影響しないことが test で検証される（規範 §13.1・§20）
- stdout = 解析結果、stderr = log、quiet で結果非抑制（規範 §19.1）
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
- Phase 6 の成果（`tf-findings` の `FindingBuilder`・`FindingMergeOptions`・`FindingMergeRule`・`FindingMergeSummary`・`AttackDataset`・`AttackDatasetManifest`・`from_correlation_rule`・`from_sigma_rule_tags`・`built_in_mappings`・`manual_mapping`・`validate_technique_ids`・`attach_attack_mappings`）は Phase 7 以降も前提となる。CLI が Match list を収集した後に `FindingBuilder::build` へ渡し、生成された Finding list を Exporter が出力する。`AttackDataset::from_stix_bytes` へ CLI 経由で dataset file への path を渡す設計。Finding list は Schema §6 の出力順で sort 済み。
