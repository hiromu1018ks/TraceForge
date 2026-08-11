# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 4 後半（Parser 群: USN Journal）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。
Phase 4 前半（Parser framework + LNK）は完了済み（`tf-parsers` に `ArtifactParser` / `ParseSink` / `ParseSummary`・panic 境界・sanitize Issue helper・`EventStoreSink`・LNK Parser（[MS-SHLLINK]・観測型 `lnk_timestamp` Event）・合成 fixture + acceptance test 8条件・M2 縦割り（LNK → EventStore → Timeline → Case JSON + Manifest）を実装、93 テスト合格）。
Phase 4 後半 Prefetch（T4-020〜T4-025）は完了済み（`tf-parsers` に Prefetch Parser（format version 17/23/26/30/31・MAM 圧縮展開（純 Rust XPRESS Huffman）・観測型 `prefetch_execution_observed` Event・未知 version の `TF-W-PREFETCH-UNSUPPORTED-VERSION` skip）・合成 Prefetch fixture ビルダ・literal-only MAM 圧縮ヘルパ・acceptance test 8条件（Prefetch 版）・Prefetch 縦割り（→ Case JSONL + Manifest）を実装、`tf-parsers` 全テスト 152 合格）。

Phase 4 後半は残り5種の Parser（USN / EVTX / Registry / Amcache / Jump Lists）を順次実装する。次回は **USN Journal（T4-030〜T4-037）** を実装することを推奨する。USN Journal は record-stream 型（1ファイルに多数 record）であり、Phase 4 前半で据えた framework の「部分成功（中間 record 破損でも前後の Event を保持）」が本格的に活躍する最初の Parser になる。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 4 後半（Parser 群: USN Journal）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 4 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §7.4 — 対象タスク一覧（T4-030〜T4-037）
4. docs/traceforge_compatibility_v1.0.md §4.3 — USN Journal 互換性要件
5. docs/traceforge_compatibility_v1.0.md §12 — Parser acceptance test 基準
6. crates/parsers/src/framework.rs — Phase 4 前半で実装済みの Parser framework（再利用）
7. crates/parsers/src/prefetch/ — Prefetch Parser の実装例（構造・sink 出力・観測型 Event・MAM 圧縮の参考）
8. crates/parsers/tests/common/mod.rs — 合成 fixture ビルダの拡張ポイント

## 対象フェーズ・タスク

- Phase 4 後半: Parser 群（USN Journal を今回実装、残り4種は以降へ継承）
- タスク（今回）: T4-030 〜 T4-037（USN Journal Parser）
- 今回は USN Journal だけを実装すること。EVTX 以降の4種へ踏み込まない。

## 成果物（tf-parsers crate の usn/ へ集中）

- USN Journal Parser（USN_RECORD_COMMON_HEADER で MajorVersion 検出、V2/V3/V4、互換 §4.3）:
  - V2: record length・reason・timestamp・file reference・parent reference・name を検証して取得
  - V3: 128-bit file reference を切り詰めず取得
  - V4: range tracking 情報を保持し、filename がない前提で処理
  - rename OLD_NAME/NEW_NAME 結合（同一 file reference + 近接 USN + 対応 reason のみ結合、不可なら独立 Event）
  - path reconstruction（同一 Evidence set 内の安全な親 directory mapping のみ、host 検索禁止）
  - 未知 MajorVersion の安全 skip + Warning（record length が安全な場合のみ）
- USN fixture + acceptance test（互換 §4.3・§12）
- Parser framework は Phase 4 前半のものを再利用（新 trait や新 sink は作らない）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Parser は全 Event を `Vec` で返してはならない（sink 型 interface、規範 §9.1）。Phase 4 前半の `ParseSink`・`EventStoreSink` を再利用
- USN Journal は record-stream 型。中間 record の破損は Issue 化し、前後の正常 record から Event を生成し続ける（規範 §9.2・§21-5）。境界を特定できない破損だけ Partial 終了
- 観測していない行為を Event type で断定しない（規範 §7.1）。USN record の存在は「ファイルシステム変更の観測」型で扱い、断定型（file_created 実行確定 等）へ変換しない
- 破損入力で panic しない。未対応形式・version を既知形式として推測しない
- rename 結合は「同一 file reference + 近接 USN + 対応 reason」の3条件をすべて満たす場合のみ。1つでも欠ければ独立 Event として保持（断定禁止）
- path reconstruction は同一 Evidence set 内の安全な親 directory mapping のみ。host filesystem へ検索しに行かない
- 128-bit file reference（V3/V4）を切り詰めずに保持する
- 新たな外部依存 crate を追加しない（既存の chrono・serde_json・thiserror で足りる想定。追加が必要なら deny.toml と AGENTS.md へ反映すること）
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 4 後半（USN Journal）の初学者向け解説 md を作成する（phase4c.md 等の別ファイル、phase4b.md の続編として）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番の詰め替えは禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（USN で新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 4 より）

- 正常 fixture から期待 Event を生成する（V2/V3/V4 各2件以上）
- truncated・invalid length・unknown version で panic しない
- Provenance が元 record へ到達する
- 1 thread と複数 thread の出力が一致する
- USN のみで analyze → Case JSON + Manifest が生成される（Phase 4 前半の LNK・Prefetch 縦割りと同じ経路で検証）
- rename OLD_NAME/NEW_NAME 結合と非結合の両方が検証できる
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 4 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 4 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。
- Phase 3 の成果（`tf-store`）は Phase 4 以降も前提となる。EventStore・TimelineKey・SortedEventIter・最小 JSONL / Manifest 出力を再利用すること。Parser が生成した Event は ParseSink 経由で EventStore へ逐次保存する。
- Phase 4 前半の成果（`tf-parsers` の framework・sink・issue helper・LNK Parser）は Phase 4 後半以降も前提となる。`ArtifactParser` trait・`ParseSink` trait・`EventStoreSink`・`run_parser_catching_panic`・`sanitize_issue_message`・安定 Issue code 定数を再利用すること。各 Parser は `crates/parsers/src/<name>/` へ配置し、`lib.rs` へ公開する。合成 fixture は `tests/common/mod.rs` のヘルパーを拡張する方針。
- Phase 4 後半 Prefetch の成果（`tf-parsers` の Prefetch Parser・`prefetch/` 配下の header/fileinfo/metrics/volume/mam 各 module・XPRESS Huffman 展開器・合成 Prefetch fixture ビルダ・`make_artifact_with_source`・literal-only MAM 圧縮ヘルパ）は以降も前提となる。record-stream 型 Parser（USN・EVTX）では、Phase 4 前半の framework「部分成功」と Prefetch の観測型 Event 設計を参考にすること。
