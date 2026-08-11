# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 4 後半（Parser 群: Jump Lists）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。
Phase 4 前半（Parser framework + LNK）は完了済み（`tf-parsers` に `ArtifactParser` / `ParseSink` / `ParseSummary`・panic 境界・sanitize Issue helper・`EventStoreSink`・LNK Parser（[MS-SHLLINK]・観測型 `lnk_timestamp` Event）・合成 fixture + acceptance test 8条件・M2 縦割り（LNK → EventStore → Timeline → Case JSON + Manifest）を実装、93 テスト合格）。
Phase 4 後半 Prefetch（T4-020〜T4-025）は完了済み（`tf-parsers` に Prefetch Parser（format version 17/23/26/30/31・MAM 圧縮展開（純 Rust XPRESS Huffman）・観測型 `prefetch_execution_observed` Event・未知 version の `TF-W-PREFETCH-UNSUPPORTED-VERSION` skip）・合成 Prefetch fixture ビルダ・literal-only MAM 圧縮ヘルパ・acceptance test 8条件（Prefetch 版）・Prefetch 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 152 合格）。
Phase 4 後半 USN Journal（T4-030〜T4-037）は完了済み（`tf-parsers` に USN Journal Parser（USN_RECORD_COMMON_HEADER で V2/V3/V4 を判定・128-bit file reference 切詰めなし・rename OLD_NAME/NEW_NAME 結合（同一 reference + 近接 USN + 対応 reason の3条件）・同一 Evidence set 内のみの path reconstruction（host 検索禁止）・観測型 `usn_change_observed` Event・未知 MajorVersion の安全 skip + Warning・record-stream 型での部分成功（中間 record 破損は Issue 化し前後の正常 record から Event 生成））・合成 USN V2/V3/V4 fixture ビルダ・acceptance test 8条件（USN 版）・USN 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 223 合格）。
Phase 4 後半 EVTX（T4-040〜T4-046）は完了済み（`tf-parsers` に EVTX Parser（file header / chunk / record の3階層構造・CRC-32 checksum 検証・純 Rust binxml decoder（template instance・substitution・主要値型）・観測型 `event_logged` 汎用 Event + typed mapping 5種（4624/4625/4688/4689/7045・channel + provider + 必須 field 同時検証・検証失敗時は汎用へ戻す）・partial chunk recovery（chunk magic / checksum 不一致・record 破損時は次 magic 探索で継続）・Legacy .evt の Unsupported 扱い（`TF-W-PARSER-UNSUPPORTED-VERSION` Issue）・PowerShell Operational / Sysmon Operational 対応（raw field 保持・typed mapping せず））・合成 EVTX file/chunk/record/binxml fixture ビルダ（literal-only BinXmlBuilder 含む）・acceptance test 8条件（EVTX 版）・EVTX 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 280 合格）。
Phase 4 後半 Registry（T4-050〜T4-055）は完了済み（`tf-parsers` に Registry Parser（`regf` base block + `hbin` bin + cell 群（nk/vk/lf/lh/li/ri）・checksum 計算・循環参照防止・depth/key/value 数上限・LOG1/LOG2 transaction log replay（合成 TFLOG 形式で完全対応・HvLE/RC11/DLOG は既知未対応として `UNSUPPORTED_VERSION` Issue 化・base のみで partial）・dual view（base / recovered）の両方を走査し `registry.view` 属性で区別・ordinal 連番で Event ID 一意性を保証・観測型 Event（`registry_observation` / `registry_key_last_write`・`registry_set` / `registry_delete` 禁止）・value data の型別復元（REG_SZ / REG_DWORD / REG_QWORD / REG_MULTI_SZ / REG_BINARY）・inline data と外部 cell の透過処理・部分成功（中間 cell 破損は Issue 化し前後の正常 cell から継続））・合成 Registry hive fixture ビルダ（RegistryFixtureBuilder・RegistryKeySpec・RegistryValueSpec）・合成 LOG fixture ビルダ（TFLOG）・acceptance test 8条件（Registry 版）・dual view と Amcache.hve の明示的併用検証・Registry 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 374 合格）。
Phase 4 後半 Amcache（T4-060〜T4-065）は完了済み（`tf-parsers` に Amcache Parser（`registry::hive` module の cell parser を再利用・root 直下 subkey 名前からの schema family 認識（Win10 22H2 / Win11 24H2 Inventory・Win 8/8.1 legacy・未知は Warning で skip）・観測型 `amcache_observation` Event のみ生成（process start 断定禁止・`amcache.interpretation_limitation` 属性で明示）・Generic Registry Parser への自動 fallback 禁止（互換 §4.6・§4.7）・Registry Parser との明示的併用（両 Parser が独立して異なる source/event_type の Event を生成）・部分成功（中間 cell 破損は Issue 化し継続）・depth/key/value 数上限・循環参照防止）・合成 Amcache fixture（`RegistryFixtureBuilder` をそのまま使用）・acceptance test 8条件（Amcache 版）・Amcache 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 415 合格）。

Phase 4 後半は残り1種の Parser（Jump Lists）を実装する。次回は **Jump Lists（T4-070〜T4-074）** を実装することを推奨する。Jump Lists は CFB（Compound File Binary）container 解析・DestList stream 解析・内包 LNK の ArtifactInstance 化（物理 Evidence としてではなく Jump List 内の ArtifactInstance）・CustomDestinations 解析という新しい課題がある。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 4 後半（Parser 群: Jump Lists）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 4 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §7.8 — 対象タスク一覧（T4-070〜T4-074）
4. docs/traceforge_compatibility_v1.0.md §4.5 — Jump Lists 互換性要件（CFB container・DestList・内包 LNK・CustomDestinations・3 OS 世代・未知 DestList version の Warning 含む）
5. docs/traceforge_compatibility_v1.0.md §12 — Parser acceptance test 基準
6. crates/parsers/src/framework.rs — Phase 4 前半で実装済みの Parser framework（再利用）
7. crates/parsers/src/lnk/ — LNK Parser（Jump Lists 内包 LNK の再利用対象・[MS-SHLLINK]）
8. crates/parsers/src/evtx/ — EVTX Parser の実装例（複雑 container / partial recovery の参考）
9. crates/parsers/src/registry/ — Registry Parser の実装例（hive 構造・観測型 Event の参考）
10. crates/parsers/src/amcache/ — Amcache Parser の実装例（schema 認識・観測型 Event の参考）
11. crates/parsers/tests/common/mod.rs — 合成 fixture ビルダの拡張ポイント

## 対象フェーズ・タスク

- Phase 4 後半: Parser 群（Jump Lists を今回実装・これで Phase 4 全 Parser 完成）
- タスク（今回）: T4-070 〜 T4-074（Jump Lists Parser）
- 今回は Jump Lists だけを実装すること。Phase 5（検知エンジン）等の次フェーズへ踏み込まない。

## 成果物（tf-parsers crate の jump_lists/ へ集中）

- Jump Lists Parser（AutomaticDestinations / CustomDestinations、互換 §4.5）:
  - CFB container 解析（AutomaticDestinations・T4-070）
  - DestList 解析（未知 version は Warning・T4-071・互換 §4.5）
  - 内包 LNK の ArtifactInstance 化（stream 名 + offset を Provenance・新物理 Evidence へ登録しない・T4-072・互換 §4.5）
  - CustomDestinations 解析（T4-073）
- Jump Lists fixture + acceptance test（3 OS 世代: Win 7 SP1 / Win 10 22H2 / Win 11 24H2・T4-074・互換 §4.5・§12）
- Parser framework は Phase 4 前半のものを再利用（新 trait や新 sink は作らない）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Parser は全 Event を `Vec` で返してはならない（sink 型 interface、規範 §9.1）。Phase 4 前半の `ParseSink`・`EventStoreSink` を再利用
- 内包 LNK は新しい物理 Evidence として登録せず、Jump List Evidence 内の ArtifactInstance として扱う。compound stream 名と offset を Provenance へ保存する（互換 §4.5）
- 観測していない行為を Event type で断定しない（規範 §7.1・互換 §4.5）。Jump List entry の存在や timestamp だけから「利用者がその時刻に target を開いた」と断定してはならない
- 未知 DestList version は container 全体を誤解析せず Warning（互換 §4.5）
- 破損入力で panic しない。未対応形式・version を既知形式として推測しない
- 新たな外部依存 crate を追加しない（既存の chrono・serde_json・thiserror で足りる想定。追加が必要なら deny.toml と AGENTS.md へ反映すること）。CFB 解析も純 Rust 自前実装を基本とし、外部 crate へ依存する場合は deny.toml・AGENTS.md へ反映すること
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 4 後半（Jump Lists）の初学者向け解説 md を作成する（phase4g.md 等の別ファイル、phase4f.md の続編として）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番の詰め替えは禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（Jump Lists で新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 4 より）

- 正常 fixture から期待 Event を生成する
- truncated・invalid container・unknown DestList version で panic しない
- Provenance が元 record（CFB stream 内の byte range または compound stream 名 + offset）へ到達する
- 1 thread と複数 thread の出力が一致する
- Jump Lists のみで analyze → Case JSON + Manifest が生成される（Phase 4 前半の LNK・Prefetch・USN・EVTX・Registry・Amcache 縦割りと同じ経路で検証）
- 3 OS 世代（Win 7 SP1 / Win 10 22H2 / Win 11 24H2）の fixture を扱う（互換 §4.5）
- 内包 LNK が物理 Evidence としてではなく Jump List 内 ArtifactInstance として扱われる（互換 §4.5）
- 未知 DestList version は container 全体を誤解析せず Warning Issue へ記録される（互換 §4.5）
- Jump List entry の存在や timestamp だけから「target を開いた」と断定せず、観測型 Event のみ（規範 §7.1・互換 §4.5）
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
