# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 4 後半（Parser 群: Prefetch）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。
Phase 4 前半（Parser framework + LNK）は完了済み（`tf-parsers` に `ArtifactParser` / `ParseSink` / `ParseSummary`・panic 境界・sanitize Issue helper・`EventStoreSink`・LNK Parser（[MS-SHLLINK]・観測型 `lnk_timestamp` Event）・合成 fixture + acceptance test 8条件・M2 縦割り（LNK → EventStore → Timeline → Case JSON + Manifest）を実装、93 テスト合格）。

Phase 4 後半は残り6種の Parser（Prefetch / USN / EVTX / Registry / Amcache / Jump Lists）を順次実装する。次回は **Prefetch（T4-020〜T4-025）** を実装することを推奨する。Phase 4 前半で据えた Parser framework（`ArtifactParser` trait・`ParseSink`・`EventStoreSink`）を再利用し、各形式の byte 列解読に集中する。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 4 後半（Parser 群: Prefetch）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 4 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §7.3 — 対象タスク一覧（T4-020〜T4-025）
4. docs/traceforge_compatibility_v1.0.md §4.1 — Prefetch 互換性要件
5. docs/traceforge_compatibility_v1.0.md §12 — Parser acceptance test 基準
6. crates/parsers/src/framework.rs — Phase 4 前半で実装済みの Parser framework（再利用）
7. crates/parsers/src/lnk/ — LNK Parser の実装例（構造・sink 出力・観測型 Event の参考）

## 対象フェーズ・タスク

- Phase 4 後半: Parser 群（Prefetch を今回実装、残り5種は以降へ継承）
- タスク（今回）: T4-020 〜 T4-025（Prefetch Parser）
- 今回は Prefetch だけを実装すること。USN 以降の5種へ踏み込まない。

## 成果物（tf-parsers crate の prefetfch/ へ集中）

- Prefetch Parser（format version 17/23/26/30/31、互換 §4.1）:
  - executable 名・run count・利用可能な run time・volume・参照 file/directory の取得
  - MAM 圧縮展開（同一 Provenance chain、圧縮前後を別 Evidence と誤認しない、互換 §4.1）
  - 未知 version の安全 skip + `TF-W-PREFETCH-UNSUPPORTED-VERSION`（互換 §4.1）
  - 実行痕跡 Event 化（process start へ断定しない、観測型、互換 §4.1・規範 §7.1）
- Prefetch fixture + acceptance test（各 version 正常 2件以上・MAM・異常系、互換 §4.1・§12）
- Parser framework は Phase 4 前半のものを再利用（新 trait や新 sink は作らない）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Parser は全 Event を `Vec` で返してはならない（sink 型 interface、規範 §9.1）。Phase 4 前半の `ParseSink`・`EventStoreSink` を再利用
- 観測していない行為を Event type で断定しない（規範 §7.1）。Prefetch の存在は「実行痕跡が記録された」の観測型で、process start Event へ断定しない
- 破損入力で panic しない。未対応形式・version を既知形式として推測しない
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 4 後半（Prefetch）の初学者向け解説 md を作成する（phase4b.md 等の別ファイル、phase4.md の続編として）
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番の詰め替えは禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する（Prefetch で新依存を追加した場合のみ）
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 4 より）

- 正常 fixture から期待 Event を生成する
- truncated・invalid length・unknown version で panic しない
- Provenance が元 record へ到達する
- 1 thread と複数 thread の出力が一致する
- Prefetch のみで analyze → Case JSON + Manifest が生成される（Phase 4 前半の LNK 縦割りと同じ経路で検証）
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 4 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 4 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。
- Phase 3 の成果（`tf-store`）は Phase 4 以降も前提となる。EventStore・TimelineKey・SortedEventIter・最小 JSONL / Manifest 出力を再利用すること。Parser が生成した Event は ParseSink 経由で EventStore へ逐次保存する。
- Phase 4 前半の成果（`tf-parsers` の framework・sink・issue helper・LNK Parser）は Phase 4 後半以降も前提となる。`ArtifactParser` trait・`ParseSink` trait・`EventStoreSink`・`run_parser_catching_panic`・`sanitize_issue_message`・安定 Issue code 定数を再利用すること。各 Parser は `crates/parsers/src/<name>/` へ配置し、`lib.rs` へ公開する。合成 fixture は `tests/common/mod.rs` のヘルパーを拡張する方針。
