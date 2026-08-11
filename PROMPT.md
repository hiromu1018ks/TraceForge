# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 4 後半（Parser 群: Registry）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。
Phase 4 前半（Parser framework + LNK）は完了済み（`tf-parsers` に `ArtifactParser` / `ParseSink` / `ParseSummary`・panic 境界・sanitize Issue helper・`EventStoreSink`・LNK Parser（[MS-SHLLINK]・観測型 `lnk_timestamp` Event）・合成 fixture + acceptance test 8条件・M2 縦割り（LNK → EventStore → Timeline → Case JSON + Manifest）を実装、93 テスト合格）。
Phase 4 後半 Prefetch（T4-020〜T4-025）は完了済み（`tf-parsers` に Prefetch Parser（format version 17/23/26/30/31・MAM 圧縮展開（純 Rust XPRESS Huffman）・観測型 `prefetch_execution_observed` Event・未知 version の `TF-W-PREFETCH-UNSUPPORTED-VERSION` skip）・合成 Prefetch fixture ビルダ・literal-only MAM 圧縮ヘルパ・acceptance test 8条件（Prefetch 版）・Prefetch 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 152 合格）。
Phase 4 後半 USN Journal（T4-030〜T4-037）は完了済み（`tf-parsers` に USN Journal Parser（USN_RECORD_COMMON_HEADER で V2/V3/V4 を判定・128-bit file reference 切詰めなし・rename OLD_NAME/NEW_NAME 結合（同一 reference + 近接 USN + 対応 reason の3条件）・同一 Evidence set 内のみの path reconstruction（host 検索禁止）・観測型 `usn_change_observed` Event・未知 MajorVersion の安全 skip + Warning・record-stream 型での部分成功（中間 record 破損は Issue 化し前後の正常 record から Event 生成））・合成 USN V2/V3/V4 fixture ビルダ・acceptance test 8条件（USN 版）・USN 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 223 合格）。
Phase 4 後半 EVTX（T4-040〜T4-046）は完了済み（`tf-parsers` に EVTX Parser（file header / chunk / record の3階層構造・CRC-32 checksum 検証・純 Rust binxml decoder（template instance・substitution・主要値型）・観測型 `event_logged` 汎用 Event + typed mapping 5種（4624/4625/4688/4689/7045・channel + provider + 必須 field 同時検証・検証失敗時は汎用へ戻す）・partial chunk recovery（chunk magic / checksum 不一致・record 破損時は次 magic 探索で継続）・Legacy .evt の Unsupported 扱い（`TF-W-PARSER-UNSUPPORTED-VERSION` Issue）・PowerShell Operational / Sysmon Operational 対応（raw field 保持・typed mapping せず））・合成 EVTX file/chunk/record/binxml fixture ビルダ（literal-only BinXmlBuilder 含む）・acceptance test 8条件（EVTX 版）・EVTX 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 280 合格）。

Phase 4 後半は残り3種の Parser（Registry / Amcache / Jump Lists）を順次実装する。次回は **Registry（T4-050〜T4-055）** を実装することを推奨する。Registry は hive 構造（nk/vk 等の cell）・LOG1/LOG2 transaction log replay・base / recovered の dual view という新しい課題がある。観測型 Event（`registry_observation` / `registry_key_last_write`）で `registry_set` / `registry_delete` を禁止する点（互換 §4.7・規範 §7.1）に注意。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 4 後半（Parser 群: Registry）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 4 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §7.6 — 対象タスク一覧（T4-050〜T4-055）
4. docs/traceforge_compatibility_v1.0.md §4.7 — Registry 互換性要件（dual view・観測型 Event・replay 制約含む）
5. docs/traceforge_compatibility_v1.0.md §12 — Parser acceptance test 基準
6. crates/parsers/src/framework.rs — Phase 4 前半で実装済みの Parser framework（再利用）
7. crates/parsers/src/evtx/ — EVTX Parser の実装例（3階層構造・CRC-32・partial recovery・観測型 Event の参考）
8. crates/parsers/src/usn/ — USN Parser の実装例（record-stream 型・部分成功・観測型 Event の参考）
9. crates/parsers/tests/common/mod.rs — 合成 fixture ビルダの拡張ポイント

## 対象フェーズ・タスク

- Phase 4 後半: Parser 群（Registry を今回実装、残り2種は以降へ継承）
- タスク（今回）: T4-050 〜 T4-055（Registry Parser）
- 今回は Registry だけを実装すること。Amcache・Jump Lists へ踏み込まない。

## 成果物（tf-parsers crate の registry/ へ集中）

- Registry Parser（SYSTEM / SOFTWARE / SAM / SECURITY / NTUSER.DAT / UsrClass.dat / Amcache.hve の各 hive、互換 §4.7）:
  - hive 構造解析（base block・nk（key node）・vk（value）・lf/lh（subkey list）等の cell、T4-050）
  - LOG1/LOG2 transaction log replay（replay の成否と使用 log hash を記録、T4-051）
  - dual view（base のみ / recovered = base + replay）の両方を保持し、Provenance へ view を記録（T4-052）
  - replay 不可時は `partial` 扱い（T4-053）
  - 観測型 Event（`registry_observation` / `registry_key_last_write`、`registry_set` / `registry_delete` 禁止、T4-054）
  - Amcache.hve は Registry Parser と Amcache Parser の **明示的併用** を許可（自動 fallback 禁止）
- Registry fixture + acceptance test（互換 §4.7・§12）
- Parser framework は Phase 4 前半のものを再利用（新 trait や新 sink は作らない）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Parser は全 Event を `Vec` で返してはならない（sink 型 interface、規範 §9.1）。Phase 4 前半の `ParseSink`・`EventStoreSink` を再利用
- Registry は hive 単位の木構造 Parser。中間 cell 破損は Issue 化し、前後の正常 cell から Event を生成し続ける（規範 §9.2・§21-5）。境界を特定できない破損だけ Partial 終了
- 観測していない行為を Event type で断定しない（規範 §7.1）。`registry_set` / `registry_delete` を生成してはならず、`registry_observation` / `registry_key_last_write` を使う（互換 §4.7）
- transaction log の無い / replay 不能な hive は `partial` 扱い。完全解析と表明しない（互換 §4.7）
- dual view のどちらから Event を生成したかを Provenance へ記録（互換 §4.7）
- 破損入力で panic しない。未対応形式・version を既知形式として推測しない
- 新たな外部依存 crate を追加しない（既存の chrono・serde_json・thiserror で足りる想定。追加が必要なら deny.toml と AGENTS.md へ反映すること）
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 4 後半（Registry）の初学者向け解説 md を作成する（phase4e.md 等の別ファイル、phase4d.md の続編として）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番の詰め替えは禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（Registry で新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 4 より）

- 正常 fixture から期待 Event を生成する（`registry_observation` と `registry_key_last_write` の両方）
- truncated・invalid cell size・unknown hive type で panic しない
- Provenance が元 cell（hive file 内の byte range または logical path）へ到達する
- 1 thread と複数 thread の出力が一致する
- Registry のみで analyze → Case JSON + Manifest が生成される（Phase 4 前半の LNK・Prefetch・USN・EVTX 縦割りと同じ経路で検証）
- LOG1/LOG2 replay の成否・使用 hash が記録される（互換 §4.7）
- dual view（base / recovered）の両方が保持され、Provenance へ view が記録される（互換 §4.7）
- replay 不可時は Artifact が `partial` になる（互換 §4.7）
- `registry_set` / `registry_delete` を生成せず、観測型 Event のみ（規範 §7.1・互換 §4.7）
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
