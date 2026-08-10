# PROMPT.md — 実装開始プロンプト（ひな型）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 2（Evidence パイプライン）＝ 次回実装開始** 用に記入済み。
Phase 1（コアデータモデルと Schema）は完了済み（`tf-core` に決定的 ID・時刻・path・Schema validator・Config・Error 型を実装、122 テスト合格）。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 2（Evidence パイプライン）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 2 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §5 — 対象タスク一覧（T2-001 〜 T2-043）

## 対象フェーズ・タスク

- Phase 2: Evidence パイプライン
- タスク: T2-001 〜 T2-043
- Phase 2 の範囲だけを実装すること。Phase 3（Event Store と Timeline）以降へ踏み込まない。

## 成果物（tf-evidence crate へ集中）

- `source_locator` 正規化（`/` separator・`.`/`..` 禁止・NFC・`%XX` escape、規範 §5.2）
- 決定的 discovery（UTF-8 byte 昇順 sort・filesystem 順非依存・symlink skip、規範 §5.3）
- read-only snapshot + 同時 SHA-256 + before/after integrity check（規範 §5.5）
- Evidence ID / Case ID 生成（Phase 1 の `tf-core::id` を適用、規範 §4.1・§5.6）
- 入出力分離検証と overwrite 保護（Exit Code 4、規範 §5.4）
- Artifact 識別 framework（`probe` と ambiguous 処理、`ProbeResult` 5値、規範 §11）
- resource limit framework（事前 limit・逐次 limit・到達時の5動作、規範 §18、Schema §8.2）

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 仕様書4文書（schemas / normative / compatibility / product）へ実装範囲・進捗を追記しない（製品 §15）
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 既存の CI（fmt / clippy / test / doc / deny / fuzz / bench）が引き続き通ること
- Phase 1 で導入した cargo-deny の許可ライセンス・bans を、追加依存に合わせて調整すること
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 2 の初学者向け解説 md を作成する
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する（タスク ID の再利用・欠番の詰め替えは禁止）
  3. 導入したコマンド・依存・lint 設定を AGENTS.md「コマンド」節へ追記する
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 2 より）

- 規範 §21 の 3（snapshot 中書換で Event 非生成）の test が通る
- 規範 §21 の 9（input directory 内 output 拒否）の test が通る
- 規範 §21 の 10（symlink loop 非追跡）の test が通る
```

## 運用メモ

- 各セッションの完了報告で出力される「次回プロンプト」もこの形式に従う（AGENTS.md 開発ワークフロー 6）。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
- Phase 1 の成果（`tf-core`）は Phase 2 以降も前提となる。Evidence/Artifact/Issue 等の型、決定的 ID・時刻・path モデル、Schema validator、Config、Exit Code を再利用すること。
