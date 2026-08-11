# PROMPT.md — 実装開始プロンプト（ひな形）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 3（Event Store と Timeline）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。
Phase 2（Evidence パイプライン）は完了済み（`tf-evidence` に source_locator 正規化・決定的 discovery・snapshot + 同時 SHA-256・入出力分離・Artifact 識別 framework・resource limit framework を実装、79 テスト合格）。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 3（Event Store と Timeline）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 3 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §6 — 対象タスク一覧（T3-001 〜 T3-031）

## 対象フェーズ・タスク

- Phase 3: Event Store と Timeline
- タスク: T3-001 〜 T3-031
- Phase 3 の範囲だけを実装すること。Phase 4（Parser 群）以降へ踏み込まない。

## 成果物（tf-store crate へ集中）

- length-delimited spool file Event Store（規範 §10）
- 書き込み時 Schema validation・Event ID 一意制約・commit marker・権限制限（規範 §10）
- timestamp group + Event ID による決定的 iteration（規範 §10・§6.3）
- memory budget 超過時の external merge sort（規範 §10）
- Timeline 5 group の順序付け（規範 §6.3: UtcInstant → timezone 付き LocalTime → timezone 不明 LocalTime → Range → Unknown）
- 縦割り用の最小 JSON / Manifest 出力（M2 用、正式版は Phase 7 へ引き継ぐ）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Runtime の Case へ Vec<Event> を保持してはならない（規範 §10）— 逐次保存・逐次読取
- Event Store は所有者限定 permission（規範 §10）
- Timeline sort は memory 内 sort だけに依存してはならない（規範 §10）
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 3 の初学者向け解説 md を作成する
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番の詰め替えは禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 3 より）

- 規範 §21 の 6（100万 Event で全件 Vec 不要）の test が通る
- 規範 §21 の 8（同一 timestamp の安定順）の test が通る
```

## 運用メモ

- 各セッションの完了時には、チャットへプロンプトを出力せず **本ファイルを次フェーズ用へ更新** する（AGENTS.md 開発ワークフロー 6）。更新した本ファイルは実装完了時のコミットへ含める。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 3 以降も前提となる。Event・Provenance・RecordLocator 型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
- Phase 2 の成果（`tf-evidence`）は Phase 3 以降も前提となる。EvidenceItem・snapshot・source_locator・probe framework・limit framework を再利用すること。
