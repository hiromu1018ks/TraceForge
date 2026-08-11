# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 5 Sigma 編（T5-010〜T5-017）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。
Phase 4 前半（Parser framework + LNK）は完了済み（`tf-parsers` に `ArtifactParser` / `ParseSink` / `ParseSummary`・panic 境界・sanitize Issue helper・`EventStoreSink`・LNK Parser（[MS-SHLLINK]・観測型 `lnk_timestamp` Event）・合成 fixture + acceptance test 8条件・M2 縦割り（LNK → EventStore → Timeline → Case JSON + Manifest）を実装、93 テスト合格）。
Phase 4 後半 Prefetch（T4-020〜T4-025）は完了済み（`tf-parsers` に Prefetch Parser（format version 17/23/26/30/31・MAM 圧縮展開（純 Rust XPRESS Huffman）・観測型 `prefetch_execution_observed` Event・未知 version の `TF-W-PREFETCH-UNSUPPORTED-VERSION` skip）・合成 Prefetch fixture ビルダ・literal-only MAM 圧縮ヘルパ・acceptance test 8条件（Prefetch 版）・Prefetch 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 152 合格）。
Phase 4 後半 USN Journal（T4-030〜T4-037）は完了済み（`tf-parsers` に USN Journal Parser（USN_RECORD_COMMON_HEADER で V2/V3/V4 を判定・128-bit file reference 切詰めなし・rename OLD_NAME/NEW_NAME 結合（同一 reference + 近接 USN + 対応 reason の3条件）・同一 Evidence set 内のみの path reconstruction（host 検索禁止）・観測型 `usn_change_observed` Event・未知 MajorVersion の安全 skip + Warning・record-stream 型での部分成功（中間 record 破損は Issue 化し前後の正常 record から Event 生成））・合成 USN V2/V3/V4 fixture ビルダ・acceptance test 8条件（USN 版）・USN 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 223 合格）。
Phase 4 後半 EVTX（T4-040〜T4-046）は完了済み（`tf-parsers` に EVTX Parser（file header / chunk / record の3階層構造・CRC-32 checksum 検証・純 Rust binxml decoder（template instance・substitution・主要値型）・観測型 `event_logged` 汎用 Event + typed mapping 5種（4624/4625/4688/4689/7045・channel + provider + 必須 field 同時検証・検証失敗時は汎用へ戻す）・partial chunk recovery（chunk magic / checksum 不一致・record 破損時は次 magic 探索で継続）・Legacy .evt の Unsupported 扱い（`TF-W-PARSER-UNSUPPORTED-VERSION` Issue）・PowerShell Operational / Sysmon Operational 対応（raw field 保持・typed mapping せず））・合成 EVTX file/chunk/record/binxml fixture ビルダ（literal-only BinXmlBuilder 含む）・acceptance test 8条件（EVTX 版）・EVTX 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 280 合格）。
Phase 4 後半 Registry（T4-050〜T4-055）は完了済み（`tf-parsers` に Registry Parser（`regf` base block + `hbin` bin + cell 群（nk/vk/lf/lh/li/ri）・checksum 計算・循環参照防止・depth/key/value 数上限・LOG1/LOG2 transaction log replay（合成 TFLOG 形式で完全対応・HvLE/RC11/DLOG は既知未対応として `UNSUPPORTED_VERSION` Issue 化・base のみで partial）・dual view（base / recovered）の両方を走査し `registry.view` 属性で区別・ordinal 連番で Event ID 一意性を保証・観測型 Event（`registry_observation` / `registry_key_last_write`・`registry_set` / `registry_delete` 禁止）・value data の型別復元（REG_SZ / REG_DWORD / REG_QWORD / REG_MULTI_SZ / REG_BINARY）・inline data と外部 cell の透過処理・部分成功（中間 cell 破損は Issue 化し前後の正常 cell から継続））・合成 Registry hive fixture ビルダ（RegistryFixtureBuilder・RegistryKeySpec・RegistryValueSpec）・合成 LOG fixture ビルダ（TFLOG）・acceptance test 8条件（Registry 版）・dual view と Amcache.hve の明示的併用検証・Registry 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 374 合格）。
Phase 4 後半 Amcache（T4-060〜T4-065）は完了済み（`tf-parsers` に Amcache Parser（`registry::hive` module の cell parser を再利用・root 直下 subkey 名前からの schema family 認識（Win10 22H2 / Win11 24H2 Inventory・Win 8/8.1 legacy・未知は Warning で skip）・観測型 `amcache_observation` Event のみ生成（process start 断定禁止・`amcache.interpretation_limitation` 属性で明示）・Generic Registry Parser への自動 fallback 禁止（互換 §4.6・§4.7）・Registry Parser との明示的併用（両 Parser が独立して異なる source/event_type の Event を生成）・部分成功（中間 cell 破損は Issue 化し継続）・depth/key/value 数上限・循環参照防止）・合成 Amcache fixture（`RegistryFixtureBuilder` をそのまま使用）・acceptance test 8条件（Amcache 版）・Amcache 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 415 合格）。
Phase 4 後半 Jump Lists（T4-070〜T4-074）は完了済み（`tf-parsers` に Jump Lists Parser（純 Rust CFB container 解析（[MS-CFB]: header / FAT / directory / MiniFAT・循環参照防止・version 3/4 両対応）・DestList stream 解析（v1 Win7 / v3 Win10 22H2 / v4 Win11 24H2・未知 version は Warning Issue で container 全体を誤解析せず）・内包 LNK の ArtifactInstance 化（物理 Evidence へ登録せず `RecordLocator::LogicalPath([stream_name])` で stream 名を Provenance へ保存）・CustomDestinations 解析（独自形式・category + entry 構造・内包 LNK は既存 LnK module で再利用）・観測型 `jump_list_observation` Event のみ生成（`open`/`launch`/`executed` 等の断定禁止・`interpretation_limitation` 属性で明示）・部分成功（CFB 破損・DestList 未知 version・truncated で Warning Issue + 継続）・3 OS 世代 fixture（Win 7 SP1 / Win 10 22H2 / Win 11 24H2）・acceptance test 8条件（Jump Lists 版）・Jump Lists 縦割り（→ Case JSONL + Manifest））・合成 AutomaticDestinations / CustomDestinations fixture ビルダ（CFB container 構築・v1/v3/v4 DestList 構築・Jump List 内包 LNK 構築）を実装、`tf-parsers` 全テスト 465 合格）。
Phase 4 共通検証（T4-090〜T4-092）は完了済み（全 Parser（LNK / Prefetch / USN / EVTX / Registry / Amcache / Jump Lists の7種）の横断検証を実施。`crates/parsers/tests/thread_consistency_tests.rs`（新規）で thread 数 1/複数一致を `std::thread::scope` で検証（互換 §12-4・規範 §13）。`crates/parsers/tests/provenance_reachability_tests.rs`（新規）で ByteRange・LogicalPath・RecordId・ByteOffset・全 Provenance field の物理的到達性を網羅検証（互換 §12-3）。`fuzz/fuzz_targets/{lnk,prefetch,usn,evtx,registry,amcache,jump_lists}.rs`（新規7件）で破損入力でも panic しないことを継続的 fuzzing で検証可能に（F-025・`run_parser_catching_panic` 経由）。実装コード（`crates/parsers/src/`）は1行も変更せず、テストと fuzz target の追加のみ。`tf-parsers` 全テスト 484 合格・マイルストーン M3（全 Parser 完成）到達）。
Phase 5 共通編（T5-001〜T5-003）は完了済み（`tf-engines` に Sigma・YARA-X・Correlation 全てへ共通する Rule file 取扱基盤を実装。`RuleRegistry` が SHA-256 で重複検出し規範 §14 の「1回読込・再読込禁止」を実現。`discover_rule_directory` が filesystem 列挙順へ依存せず UTF-8 byte 順で決定的に列挙（規範 §14）。`RuleLoadError::exit_code` が strict rules なら Exit Code 5・非 strict なら Exit Code 1・root 問題は常に 3 へ区分（規範 §17.2）。`path_norm` module が Rule file 用相対 path 正規化（`\` → `/`、`.`/`..` 拒否、絶対 path 拒否、非 UTF-8 は `%XX` escape、大文字小文字保持）。`fuzz/fuzz_targets/rule_loader.rs`（新規）で F-025 対応。`tf-engines` 全テスト 58 合格・workspace 全テスト 791 合格）。

Phase 5 共通編はこれで完了した。次回は **Phase 5 Sigma 編（T5-010〜T5-017）** を実施し、TF-SIGMA-1.0 subset evaluator を実装することを推奨する。Sigma 編では共通編の `RuleRegistry` が読み込んだ raw bytes を YAML parser へ渡し、logsource routing・selection/condition 評価・modifier・field mapping を実装する。未対応要素（modifier・condition・correlation・filter）を含む Rule は部分評価せず全体を skip する（規範 §15.1・互換 §6.2）。Sigma は Correlation と同じ YAML parser を使うため、先に Sigma を実装することで Correlation 実装もスムーズになる。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 5 Sigma 編（T5-010〜T5-017）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 5 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §8.2 — 対象タスク一覧（T5-010〜T5-017）
4. docs/traceforge_normative_core_specification_v1.0.md §15.1（Sigma）・§17.2（Exit Code 5）
5. docs/traceforge_compatibility_v1.0.md §6（Sigma 対応範囲・subset・field mapping 表）
6. docs/traceforge_schemas_v1.0.md §5.7（Match）・§7（Correlation Rule・Sigma と比較のため）
7. crates/engines/src/loader.rs — Phase 5 共通編の RuleRegistry・LoadedRuleFile・RuleLoadOptions
8. crates/engines/src/lib.rs・path_norm.rs — 公開 API・path 正規化
9. crates/core/src/match_.rs・id.rs — Match 型・match_id(rule_id, rule_content_sha256, ordered_event_ids)
10. crates/core/src/config.rs — SigmaConfig.rule_dirs・LimitsConfig

## 対象フェーズ・タスク

- Phase 5 Sigma 編: TF-SIGMA-1.0 subset evaluator
- タスク（今回）: T5-010 〜 T5-017
- 今回は Sigma 編だけを実装すること。YARA-X（T5-020〜T5-027）・Correlation（T5-030〜T5-042）の各個別実装へ踏み込まない。
- 共通編（T5-001〜T5-003）の RuleRegistry・LoadedRuleFile を前提とし、raw_bytes() で借りた bytes を Sigma parser へ渡す設計とする（規範 §14: 同じ bytes を使う）。

## 成果物

- T5-010: Sigma YAML parser + TF-SIGMA-1.0 subset validator（互換 §6.1〜6.2）。Phase 5 共通編の RuleRegistry が読み込んだ raw_bytes を使い回す。YAML parser・Schema validator を新依存として導入（serde_yaml・serde_yaml_with 等・cargo-deny で許可される license のみ）。
- T5-011: 未対応要素含有 Rule の全体 skip（部分評価禁止、互換 §6.2、規範 §15.1）。未対応 modifier・condition・correlation・filter を1つでも含む Rule は評価せず Warning Issue へ記録し Skip する。
- T5-012: logsource routing（category/product/service/definition、互換 §6.1）。Sigma の logsource block から対象 Event log channel・provider へ mapping する。
- T5-013: selection / condition / quantifier 評価器（互換 §6.1）。Sigma の `detection:` block を Event attribute filter 群へ展開し、condition（AND/OR/NOT/1 of 等）を評価する。
- T5-014: string/field/list modifier（contains・startswith・endswith・cased・exists・all、互換 §6.1）。未対応 modifier は Rule 全体 skip（T5-011 と連動）。
- T5-015: field mapping 実装（互換 §6.3 表、複数候補の OR 評価禁止）。Sigma field 名を TraceForge Event attribute 名へ mapping する。複数候補がある場合は明示順の先頭のみ使用し、OR 結合で複数候補を同時評価しない。
- T5-016: Sigma match → Match 型変換（logsource_mapping 保持、Schema §5.7）。Sigma の検知結果を `tf_core::Match` へ変換する。`match_id` の hash field `rule_content_sha256` は RuleRegistry が算出した SHA-256 を使う。`MatchType::Sigma` を指定し、`logsource_mapping` 拡張 field を格納する。
- T5-017: Sigma 未対応構文 skip test（規範 §21-12）。未対応 modifier・condition・correlation・filter を含む Rule が部分評価されず全体 skip されることを検証する。

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Sigma 変換ツール（sigmac・pySigma 等）は使わず、TF-SIGMA-1.0 subset を自前評価する（roadmap §3.5・§9 リスク対策）
- 未対応要素は黙って無視せず、必ず Skip + Warning Issue として記録する（規範 §15.1）
- 新依存 crate（YAML parser 等）を追加する場合は deny.toml と workspace Cargo.toml と AGENTS.md「依存構成」節へ反映する
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 5 Sigma 編の初学者向け解説 md を作成する（phase5b.md）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番詰め替え禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny / `cargo check --manifest-path fuzz/Cargo.toml` / `cargo bench --no-run` が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 5・規範 §15.1・§21-12・互換 §6 より）

- Sigma Rule が YAML parser へ通され、TF-SIGMA-1.0 subset validator で検証される
- 未対応 modifier・condition・correlation・filter を含む Rule が全体 skip される（規範 §21-12）
- logsource routing が channel/provider へ正しく mapping される
- selection / condition 評価が Event へ対して正しい bool 結果を返す
- 6種 modifier（contains・startswith・endswith・cased・exists・all）が正しく評価される
- field mapping が互換 §6.3 表へ従う（複数候補の OR 評価禁止）
- Sigma match が Match 型（match_type=Sigma・logsource_mapping 保持）へ変換される
- 共通編の RuleRegistry・LoadedRuleFile・SHA-256 を使い回す（規範 §14: 同じ bytes を使う）
- 既存の全テストが引き続き通る（回帰無し）
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 4 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 4 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。
- Phase 3 の成果（`tf-store`）は Phase 4 以降も前提となる。EventStore・TimelineKey・SortedEventIter・最小 JSONL / Manifest 出力を再利用すること。Parser が生成した Event は ParseSink 経由で EventStore へ逐次保存する。
- Phase 4 前半の成果（`tf-parsers` の framework・sink・issue helper・LNK Parser）は Phase 4 後半以降も前提となる。`ArtifactParser` trait・`ParseSink` trait・`EventStoreSink`・`run_parser_catching_panic`・`sanitize_issue_message`・安定 Issue code 定数を再利用すること。各 Parser は `crates/parsers/src/<name>/` へ配置し、`lib.rs` へ公開する。合成 fixture は `tests/common/mod.rs` のヘルパーを拡張する方針。
- Phase 4 後半 Prefetch の成果（`tf-parsers` の Prefetch Parser・`prefetch/` 配下の header/fileinfo/metrics/volume/mam 各 module・XPRESS Huffman 展開器・合成 Prefetch fixture ビルダ・`make_artifact_with_source`・literal-only MAM 圧縮ヘルパ）は以降も前提となる。record-stream 型 Parser（USN・EVTX）では、Phase 4 前半の framework「部分成功」と Prefetch の観測型 Event 設計を参考にすること。
- Phase 4 後半 USN Journal の成果（`tf-parsers` の USN Parser・`usn/` 配下の header/record/reason/combine/path 各 module・合成 USN V2/V3/V4 fixture ビルダ・`filetime_to_datetime` 再利用）は以降も前提となる。Registry でも hive 内 cell 破損での部分成功・観測型 Event 設計を参考にすること。path reconstruction と同様に host filesystem への問い合わせ禁止（同一 Evidence set 内の情報のみ）を守ること。
- Phase 4 後半 EVTX の成果（`tf-parsers` の EVTX Parser・`evtx/` 配下の header/chunk/record/binxml/crc32/mapping 各 module・CRC-32 純 Rust 実装・合成 EVTX file/chunk/record/binxml fixture ビルダ・`BinXmlBuilder` literal-only エンコーダ・3階層構造と partial recovery の設計）は以降も前提となる。Registry でも hive 構造の cell-based 設計・CRC 等の checksum 検証（もし hive format が持てば）・partial recovery（cell 破損時は次 cell を探索して継続）を参考にすること。typed mapping が不要な Parser では観測型 Event（`registry_observation` 等）の設計を参考にすること。
- Phase 4 後半 Registry の成果（`tf-parsers` の Registry Parser・`registry/` 配下の hive/log 各 module・`HiveBins`・`parse_base_block`・`parse_key_node`・`parse_key_value`・`subkey_offsets`・`decode_utf16le_lossy`・`registry_value_type_name`・LOG1/LOG2 replay framework（合成 TFLOG 形式・HvLE/RC11/DLOG は既知未対応）・dual view 設計・`ReplayMeta`・`HiveType`・`detect_hive_type`・合成 Registry hive fixture ビルダ（`RegistryFixtureBuilder`・`RegistryKeySpec`・`RegistryValueSpec`）・合成 LOG fixture ビルダ）は以降も前提となる。Amcache でも hive 構造解析・cell 走査・観測型 Event 設計・value data 型別復元を参考にすること。Amcache.hve は registry hive 形式そのもののため、`registry::hive` module の cell parser を再利用または参照してよい。
- Phase 4 後半 Amcache の成果（`tf-parsers` の Amcache Parser・`amcache/` 配下の mod/schema 各 module・`SchemaFamily`・`detect_schema_family`・`is_inventory_file_metadata_key`・`is_file_metadata_path`・`AMCACHE_OBSERVATION_EVENT_TYPE`・`AMCACHE_REFERENCE`・`AmcacheParser`・Registry Parser との明示的併用設計・schema family 認識に基づく skip と Warning 発行）は以降も前提となる。Jump Lists でも container 内に内包される別形式（LNK）を扱う設計・観測型 Event の設計・schema/version 認識に基づく安全 skip を参考にすること。
- Phase 4 後半 Jump Lists の成果（`tf-parsers` の Jump Lists Parser・`jump_lists/` 配下の mod/cfb/destlist/custom 各 module・`JumpListParser`・純 Rust CFB container 解析（header / FAT / directory / MiniFAT・循環参照防止）・DestList 解析（v1/v3/v4・未知 version は Warning）・内包 LNK の ArtifactInstance 化（`RecordLocator::LogicalPath([stream_name])`）・CustomDestinations 解析・`JUMP_LIST_OBSERVATION_EVENT_TYPE`・`JUMP_LIST_REFERENCE`・合成 AutomaticDestinations / CustomDestinations fixture ビルダ（CFB container 構築含む）・v1/v3/v4 DestList 構築ヘルパ・Jump List 内包 LNK 構築ヘルパ）は以降も前提となる。Phase 5 以降の検知エンジンは、これら全 Parser が生成した Event を入力とする。
- Phase 4 共通検証の成果（`thread_consistency_tests.rs`・`provenance_reachability_tests.rs`・全 Parser への fuzz target）は以降も前提となる。Phase 5 の検知エンジンでも、Rule 評価の決定性（規範 §13）・Rule から元 Evidence / Event への到達性（互換 §12-3 と同様の traceability）・Rule file への fuzz 対応を参考にすること。
- Phase 5 共通編の成果（`tf-engines` の `loader.rs`・`path_norm.rs`・`RuleRegistry`・`LoadedRuleFile`・`RuleLoadOptions`・`RuleLoadSummary`・`RuleLoadError`・`discover_rule_directory`・`load_directory`・`LoadedRuleFile::raw_bytes`・`sha256`・`relative_path`・`SYMLINK_SKIP_CODE`・`MAX_RULE_FILES_LIMIT_CODE`）は Sigma・YARA-X・Correlation 全てへ共通する前提となる。各 engine は `RuleRegistry::load_directory` で読み込んだ `LoadedRuleFile` の `raw_bytes()` を借りて parse/compile へ渡す（規範 §14: 同じ bytes を使う）。`LoadedRuleFile::sha256` を `match_id` の `rule_content_sha256` へ使う。`RuleLoadError::exit_code(strict_rules)` で validation error を Exit Code 5/1 へ区分する。
