# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトのひな形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 8 品質保証とリリース（T8-001〜T8-027）＝ 次回実装開始** 用に記入済み。
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
Phase 6 Finding 統合と ATT&CK（T6-001〜T6-009）は完了済み（`tf-findings` に Finding merger・ATT&CK dataset 読込・Technique ID 検証・mapping 生成を実装。`src/merger.rs`: Match list → Finding list への1:1 変換・明示統合 rule（`FindingMergeRule`）のみで統合を許可（自動統合禁止・規範 §16）・observed_evidence / inference 分離（製品 §10）・Schema §6 出力順（Severity 降順・finding_id 昇順）・match 喪失なし検証（`FindingMergeSummary::all_matches_referenced`）・決定的 Finding ID（規範 §12.4），`src/attack/` module（`dataset.rs`: STIX bundle bytes から SHA-256 計算と technique 抽出・version pin・取得元記録（互換 §9）、`technique.rs`: Technique ID 形式検証（`T<4桁>(.<3桁>)?`）と dataset 存在検証（不在 ID は `UnknownTechniqueError`・Rule validation error），`mapping.rs`: 4経路（Rule / Sigma tag / built-in / manual）のみ ATT&CK mapping 生成（規範 §15.3）・dataset version + hash 記録）・統合テスト 20件・マイルストーン M4 到達。`tf-core` の `AttackMapping` 型を拡張（`tactic` / `source` / `dataset_version` / `dataset_sha256` 追加）・`AttackMappingSource` enum 新設。`tf-findings` 全テスト 63 合格・workspace 全テスト 1,130 合格）。
Phase 7 Exporter と CLI 完成（T7-001〜T7-034）は完了済み（`tf-export` に6種の出力形式（Text / JSON / JSONL / CSV / HTML / Timesketch）を実装。`src/sanitize.rs`: 共通 sanitization helper（`escape_control_chars`・`sanitize_csv_cell`・`html_text_escape`・規範 §19）・`src/manifest.rs`: Manifest 確定処理（全必須 field・`finalize_manifest`・`manifest_without_run_metadata`・規範 §20・T7-032・T7-033）・`src/schema_check.rs`: Schema major version 検証（互換 §10・T7-009）・6種 exporter（`text.rs` / `json.rs` / `jsonl.rs` / `csv.rs` / `html.rs` / `timesketch.rs`）・統合テスト（`injection_tests.rs`（§21-11・T7-008）・`schema_tests.rs`（§21-15・T7-009）・`determinism_tests.rs`（T7-033））。`tf-cli` に9種の command（`analyze` / `timeline` / `correlate` / `sigma` / `yara` / `export` / `rules` / `inspect` / `version`）を実装。`src/args.rs`: 最小引数 parser（外部 crate 不使用・`--no-hash` 拒否・T7-022）・`src/runtime.rs`: Case 読込・出力書込・RunContext・`src/version_info.rs`: version 情報・`src/commands/`: 9 command 実装・統合テスト 16件。stdout / stderr 分離（規範 §19.1・T7-034）・`tf-engines` の `loader.rs` へ `RuleLoadOptions::to_discovery_options` を追加。マイルストーン M5（機能完成）到達。`tf-export` 全テスト 60 合格・`tf-cli` 全テスト 28 合格・workspace 全テスト 1,218 合格）。

Phase 7 Exporter と CLI 完成編はこれで完了した。M5 マイルストーン（機能完成）に到達した。次回は **Phase 8 品質保証とリリース（T8-001〜T8-027）** を実施し、製品仕様 §13 の品質要件をすべて自動化し、release gate を通すことを推奨する。Phase 8 では golden determinism test（threads 1/2/自動で canonical JSON byte 一致・規範 §13.3・§21-7）・integration / regression / property test の整備・fuzz corpus 整備と campaign・integrity test（解析中の入力変更再現）・benchmark 実測・全 Required 対象の compatibility acceptance 最終確認・README 例の実 fixture からの自動生成・dependency / license / advisory 記録が鍵となる。Phase 7 で作った `tf-export` の 6 出力形式・`tf-cli` の 9 command が全て v1.0 Stable の品質基準を満たすことを検証する。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 8 品質保証とリリース（T8-001〜T8-027）を実装してください。

## プロジェクト基本情報
- 作業ディレクトリ: C:\Users\hirom\project\TraceForge
- Windows PowerShell (5.1) 環境。Shell: powershell。
- Rust 1.97.1（rust-toolchain.toml 固定）。mise 管理の場合は .mise.toml を参照。
- git リポジトリ。Phase 7 Exporter と CLI 完成編までコミット済み。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項・コマンド節
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 8 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §11 — 対象タスク一覧（T8-001〜T8-027）
4. docs/traceforge_normative_core_specification_v1.0.md §13（再現性）・§21（受け入れ条件）・§18（Resource Limit）・§9.4（panic 境界）
5. docs/traceforge_product_specification_v1.0.md §13（品質要件）・§4.5（安全性）
6. docs/traceforge_compatibility_v1.0.md §11（Dependency と License）・§12（compatibility acceptance test）
7. docs/traceforge_implementation_roadmap_v1.0.md §8（release gate）
8. crates/export/ と crates/cli/ — Phase 7 で完成した Exporter と CLI
9. .github/workflows/ci.yml — 既存 CI 構成
10. deny.toml — cargo-deny 設定（依存 license・advisory・bans・sources）
11. fuzz/fuzz_targets/ — 全 fuzz target（core・7 Parser・rule_loader・sigma・yara_x・correlation）

## 対象フェーズ・タスク

- Phase 8 品質保証とリリース: 製品仕様 §13 の品質要件をすべて自動化し、release gate を通す
- タスク（今回）: T8-001 〜 T8-027
- 今回は品質保証とリリースだけを実装すること。新機能（新 Parser・新 engine・新出力形式等）を追加しない。
- golden determinism test・integration / regression / property test の整備・fuzz corpus と campaign・benchmark 実測・README 例の自動生成・release gate checklist を整備する。

## 成果物

### 11.1 決定性・再現性

- T8-001: golden determinism test（threads 1/2/自動で canonical JSON byte 一致、規範 §13.3、§21-7）
- T8-002: 分析レコード vs run metadata の同一性比較分離 test（規範 §13.1）
- T8-003: hash map iteration 順非依存 test（規範 §13.2）
- T8-004: regression test 基盤

### 11.2 耐性・安全性

- T8-010: 破損 fixture 群での panic 非発生 test（製品 §13.2）
- T8-011: fuzz campaign 実施・corpus 蓄積（F-025）
- T8-012: 解析中の入力変更を再現する integrity test（製品 §13.1）
- T8-013: resource limit test（到達時の `complete=false` 含む、規範 §21-14）
- T8-014: 過大 allocation・無限 loop 対策 test（製品 §4.5）
- T8-015: path traversal 対策 test（製品 §4.5）

### 11.3 互換性・リリース

- T8-020: 全 Required 対象の compatibility acceptance 最終確認（互換 §12 全 8 項目）
- T8-021: Timesketch import 検証（実 instance または公式 validator、互換 §8）
- T8-022: Schema validator での全 Golden output 検証（Schema §9）
- T8-023: benchmark 実測（測定条件付き、製品 §13.2）
- T8-024: README 例の実 fixture からの自動生成（製品 §13.2）
- T8-025: dependency・license・advisory 記録の生成（互換 §11）
- T8-026: 参照外部仕様 revision の記録確認（`[MS-SHLLINK]` 等、互換 §12-6）
- T8-027: release gate checklist 実施（roadmap §8）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- 決定性（規範 §13）: golden test は threads 1/2/自動で byte 一致を必須とする（規範 §13.3）
- 安全性: 破損入力で panic しない・過大 allocation・無限 loop・path traversal を防ぐ（製品 §4.5）
- README 例は実際の fixture から生成する。手書きの例を使わない（製品 §13.2）
- benchmark 値は測定条件とともに実測値だけを掲載する（製品 §13.2）
- 外部通信は禁止（規範 §2）。Timesketch import 検証は実 instance または公式 validator を使う
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 8 の初学者向け解説 md を作成する（phase8.md）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節・モジュール構成節へ追記する（新依存を追加した場合のみ）
  4. ローカルで fmt / clippy / test / doc / deny / `cargo check --manifest-path fuzz/Cargo.toml` / `cargo bench --no-run` が通ることを確認
  5. 上記が全て通ったらコミットする（ユーザーへの個別確認は不要・本プロジェクトの既定）。push はしない。コミットメッセージは `feat(qa): Phase 8 品質保証とリリース - ...` の形式で直近コミットのスタイルに合わせる。
  6. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 8・roadmap §8 release gate・規範 §13・§21・製品 §13.2・互換 §11・§12 より）

- 同一 fixture を 1 thread と複数 thread で解析し、分析レコードが byte 単位で一致する（規範 §13.3・§21-7）
- 分析レコード vs run metadata の同一性比較分離が test で検証される（規範 §13.1）
- hash map iteration 順に依存しないことが test で検証される（規範 §13.2）
- 破損 fixture と fuzz corpus で input 起因 panic がない（製品 §13.2）
- 解析中の入力変更を再現する integrity test が通る（製品 §13.1）
- Parser issue・limit 到達・skip が Analysis Manifest へ残る（規範 §21-14）
- 過大 allocation・無限 loop・path traversal 対策が test で検証される（製品 §4.5）
- 全 Required 対象の compatibility acceptance 8項目（互換 §12）が最終確認される
- Timesketch import 検証が実施される（互換 §8）
- 全 Golden output が Schema validator で検証される（Schema §9・§21-15）
- benchmark 値が測定条件付きで実測値として掲載される（製品 §13.2）
- README 例が実際の fixture から自動生成される（製品 §13.2）
- dependency・license・advisory 記録が生成される（互換 §11）
- 参照外部仕様 revision が記録される（互換 §12-6）
- roadmap §8 の release gate checklist 全項目を満たす
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
- Phase 7 の成果（`tf-export` の `CaseData`・`ManifestFinalizationInput`・`finalize_manifest`・`manifest_without_run_metadata`・`missing_manifest_fields`・`default_components`・`escape_control_chars`・`sanitize_csv_cell`・`html_text_escape`・`HTML_CSP`・`check_case_schema_major`・`check_jsonl_schema_major`・6種 exporter（`write_text` / `write_json` / `write_jsonl` / `write_csv` / `write_html` / `write_timesketch`）・`CsvSummary`・`TimesketchSummary`）と `tf-cli` の 9 command（`run`・`parse_args`・`Command`・`RunContext`・`read_case_from_path`・`write_output`・`version_info`・`analyze` / `timeline` / `correlate` / `sigma` / `yara` / `export` / `rules` / `inspect` / `version`）は Phase 8 以降も前提となる。Phase 8 の golden determinism test は `tf-export` の JSON / JSONL 出力を比較対象とする。benchmark は `tf-cli` の `analyze` command を計測対象とする。README 例は `tf-export` の各 exporter 出力を使用する。
