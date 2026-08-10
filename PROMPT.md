# PROMPT.md — 実装開始プロンプト（ひな型）

新しい実装セッションを開始するときに使うプロンプトの雛形。
下記コードブロックをそのままコピーして使用する。次フェーズ以降は「対象フェーズ・タスク」「成果物」「完了条件」を該当フェーズのものへ差し替える（差し替え元は `docs/traceforge_implementation_roadmap_v1.0.md` と `docs/traceforge_implementation_tasks_v1.0.md`）。

このファイルは **Phase 0（プロジェクト基盤）＝ 最初の実装開始** 用に記入済み。

```text
TraceForge の実装を開始します。以下の指示に従って Phase 0（プロジェクト基盤）を実装してください。

## 最初に読むもの（この順で）

1. AGENTS.md — 開発ワークフロー・仕様書の優先順位・禁止事項
2. docs/traceforge_implementation_roadmap_v1.0.md §5 Phase 0 — 範囲と完了条件
3. docs/traceforge_implementation_tasks_v1.0.md §3 — 対象タスク一覧

## 対象フェーズ・タスク

- Phase 0: プロジェクト基盤
- タスク: T0-001 〜 T0-013
- Phase 0 の範囲だけを実装すること。Phase 1（コアデータモデル）以降へ踏み込まない。

## 成果物

- Cargo workspace（crate 分割案: core / evidence / store / parsers / engines / findings / export / cli）
- rust-toolchain.toml（toolchain version 固定）
- CI 設定（fmt / clippy / test / doc）
- cargo-deny 設定（license・security advisory チェック）
- cargo-fuzz 雛形、criterion benchmark 雛形
- fixture 管理方針（配置場所、SHA-256・生成 OS・取得方法の記録形式を定める）
- T0-013（fixture 収集計画）は実 Windows 環境が必要なため、収集計画の文書化まででよい

## 制約・ルール

- 応答・ドキュメント・コード内コメントはすべて日本語
- 実装後は必ずセルフレビューし、問題があれば修正してから完了とする
- 完了時に次をすべて行う:
  1. docs/learn/ に Phase 0 の初学者向け解説 md を作成する
  2. docs/traceforge_implementation_tasks_v1.0.md の該当タスク checkbox を [x] に更新する
  3. 導入したコマンド（build / test / lint 等）を AGENTS.md「コマンド」節へ追記する
  4. 実装完了後（上記 1〜3 まで完了・ローカルで fmt / clippy / test / doc / deny が通ることを確認した段階）でコミットする。ユーザーへの個別確認は不要（本プロジェクトの既定、AGENTS.md 開発ワークフロー 5）。push はユーザーの明示要求時のみ。
  5. 次に取り組むべきフェーズ・タスクの提言と、次回そのまま使えるプロンプト（このファイルと同形式）を出力する

## 完了条件（roadmap §5 Phase 0 より）

- 空実装で CI（fmt / clippy / test / doc）が通る
- fuzz / bench の雛形が動作する
```

## 運用メモ

- 各セッションの完了報告で出力される「次回プロンプト」もこの形式に従う（AGENTS.md 開発ワークフロー 6）。
- プロンプト本文へ仕様の細則をコピーしない。正本は常に docs/ の仕様書4文書とし、プロンプトは参照と範囲の指定に留める。
