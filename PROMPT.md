# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 5 共通編（T5-001〜T5-003）＝ 次回実装開始** 用に記入済み。
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

Phase 4 はこれで完全に完了した（前半 framework + 後半7 Parser + 共通検証）。次回は **Phase 5 共通編（T5-001〜T5-003）** を実施し、Sigma・YARA-X・Correlation 全てへ共通する Rule file 取扱の基盤を作ることを推奨する。共通編では Rule file の1回読み込み・raw bytes SHA-256・再読込禁止（規範 §14）・Rule directory 列挙順の正規化（UTF-8 byte 順）・Rule validation error の Exit Code 5 対応を実装する。これは Phase 5 後半の各検知エンジン（Sigma・YARA-X・Correlation）全ての前提となる。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 5 共通編（T5-001〜T5-003）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 5 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §8.1 — 対象タスク一覧（T5-001〜T5-003）
4. docs/traceforge_normative_core_specification_v1.0.md §14（Rule 評価）・§17.2（Exit Code 5）
5. docs/traceforge_schemas_v1.0.md §5.7（Match）・§7（Correlation Rule）・§8.2（limit）
6. crates/core/src/id.rs（match_id・rule_content_sha256）・match_.rs（Match 型）
7. crates/core/src/manifest.rs（Rule hash 記録用の Manifest 構造）
8. crates/findings/・crates/engines/ — 現状空実装（Phase 5 で拡張）

## 対象フェーズ・タスク

- Phase 5 共通編: Sigma・YARA-X・Correlation 全てへ共通する Rule file 取扱基盤
- タスク（今回）: T5-001 〜 T5-003（検知エンジン共通）
- 今回は共通編だけを実装すること。Sigma（T5-010〜T5-017）・YARA-X（T5-020〜T5-027）・Correlation（T5-030〜T5-042）の各個別実装へ踏み込まない。

## 成果物

- T5-001: Rule file の1回読み込み・raw bytes SHA-256 計算・再読込禁止（規範 §14）。同一 file が複数 directory へ現れたり複数回指定された場合でも1回だけ読み込む。raw bytes から SHA-256 を計算し、Match/Finding ID・Manifest へ記録する（規範 §12.4・§14）。
- T5-002: Rule directory 列挙順の正規化（UTF-8 byte 順、規範 §14）。directory 再帰探索で Rule file を集める際、OS の directory entry 順序（非決定的）へ依存せず、path の UTF-8 byte 順で sort してから処理する。
- T5-003: Rule validation error の Exit Code 5 対応（規範 §17.2）。Rule file の parse・Schema 違反は Exit Code 5（config / rule error）へ区分する。Parser 起因の入力異常（Exit Code 1）や panic（Exit Code 10）とは区別する。

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- 新依存 crate は最小限。Rule file 読み込みは `std::fs`・SHA-256 は `tf-core::hash`（`sha2` crate）で足りる想定。YAML parser は Sigma（T5-010）/ Correlation（T5-030）個別タスクで導入するため、共通編では必要最小限（raw bytes 取得・hash 計算・path 正規化のみ）。
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 5 共通編の初学者向け解説 md を作成する（phase5.md）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番詰め替え禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny / `cargo check --manifest-path fuzz/Cargo.toml` / `cargo bench --no-run` が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 5・規範 §14・§17.2 より）

- Rule file が raw bytes で1回読み込まれ、SHA-256 が計算・記録される（規範 §14）
- 同一 Rule file（path または content hash で同一判定）が再読み込みされない（規範 §14）
- Rule directory の列挙順が UTF-8 byte 順へ正規化される（規範 §14）
- Rule validation error が Exit Code 5 へ区分される（規範 §17.2）
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
