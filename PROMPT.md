# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 4（Parser 群: Parser framework + LNK）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。
Phase 3（Event Store と Timeline）は完了済み（`tf-store` に length-delimited spool file EventStore・Schema validation・Event ID 一意制約・commit marker・所有者限定 permission・決定的 iteration・external merge sort・Timeline 5 group 順序・filter / summary・最小 JSONL / Manifest 出力を実装、47 テスト合格）。

Phase 4 は7種の Parser 全てを一度に実装するのではなく、**Parser framework + LNK（T4-001〜T4-007, T4-010〜T4-016）を先に実装して M2（縦割りスライス）を達成** し、その後に残り6種を順次実装することを推奨する。次回はまず M2 达成を目指す。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 4（Parser 群: Parser framework + LNK）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 4 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §7.1〜7.2 — 対象タスク一覧（T4-001〜T4-007, T4-010〜T4-016）
4. docs/traceforge_compatibility_v1.0.md §4.4 — LNK 互換性要件
5. docs/traceforge_compatibility_v1.0.md §12 — Parser acceptance test 基準

## 対象フェーズ・タスク

- Phase 4: Parser 群（まず Parser framework + LNK で M2 達成、その後に残り6種）
- タスク（今回）: T4-001 〜 T4-007（Parser framework）、T4-010 〜 T4-016（LNK Parser）
- 今回は Parser framework + LNK だけを実装すること。Prefetch 以降の6種へ踏み込まない。

## 成果物（tf-parsers crate へ集中）

- `ArtifactParser` trait + `ParseSink` trait（sink 型 interface、`Vec` 全件返却禁止、規範 §9.1）
- `ParseSummary` / `ParseStatus`（規範 §9.2）
- record 破損時の部分成功処理（規範 §9.2）
- Parse Issue 仕様（安定 code・巨大値排除・出力順、規範 §9.3）
- Parser 境界の panic 捕捉 → Fatal 記録 → Exit Code 10（規範 §9.4）
- LNK Parser（`[MS-SHLLINK]`）: Shell Link Header・LinkTargetIDList・LinkInfo・StringData・ExtraData 解析
- LNK fixture + acceptance test（互換 §12）
- M2 縦割り: LNK → EventStore → Timeline → JSON Case + Manifest まで通す

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Parser は全 Event を `Vec` で返してはならない（sink 型 interface、規範 §9.1）
- 観測していない行為を Event type で断定しない（規範 §7.1）
- 破損入力で panic しない。未対応形式・version を既知形式として推測しない
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 4 の初学者向け解説 md を作成する
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番の詰め替えは禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 4 より）

- 正常 fixture から期待 Event を生成する
- truncated・invalid length・unknown version で panic しない
- Provenance が元 record へ到達する
- 1 thread と複数 thread の出力が一致する
- LNK のみで analyze → Case JSON + Manifest が生成される（M2 縦割り）
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 4 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 4 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。
- Phase 3 の成果（`tf-store`）は Phase 4 以降も前提となる。EventStore・TimelineKey・SortedEventIter・最小 JSONL / Manifest 出力を再利用すること。Parser が生成した Event は ParseSink 経由で EventStore へ逐次保存する。
