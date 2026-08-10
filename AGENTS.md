# AGENTS.md

TraceForge — Windows フォレンジック Timeline & Evidence Correlation Engine（Rust 製 CLI）。
現在は**実装前の仕様策定段階**。`docs/` に仕様書と開発計画のみ存在し、コードはまだない。

## 言語

- 応答・ドキュメント・コード内コメントは**すべて日本語**とする（ユーザー必須要件）。

## 開発ワークフロー（ユーザー必須要件）

1. `docs/traceforge_implementation_roadmap_v1.0.md` のフェーズ単位で実装する。フェーズをまたぐ一括実装をしない。
2. 実装後は**必ずセルフレビューし、問題を修正してから完了とする**。
3. フェーズ完了時に、プログラミング初学者向けの解説を `docs/learn/` に md で作成する。
4. `docs/traceforge_implementation_tasks_v1.0.md` の該当タスク checkbox を `[x]` に更新する（タスク ID の再利用・欠番の詰め替えは禁止）。
5. 完了報告では、**次に取り組むべきフェーズ・タスクの提言と、そのまま使える次回プロンプト**を出力する。

## 仕様書（docs/）の優先順位

矛盾時はこの順に従う（上位が正本）:

1. `traceforge_schemas_v1.0.md` — データ形式
2. `traceforge_normative_core_specification_v1.0.md` — 動作（規範語 MUST/SHOULD 厳守）
3. `traceforge_compatibility_v1.0.md` — 対応範囲
4. `traceforge_product_specification_v1.0.md` — 製品概要

実装範囲・進捗・開発順序を仕様書4文書へ追記してはならない（製品 §15）。それらは roadmap / tasks / 本ファイルで管理する。

## 仕様上うっかり違反しやすい禁止事項

- ID は決定的生成のみ。UUID・乱数・実行時刻由来の ID は禁止（規範 §12）
- `--no-hash` option を実装してはならない（規範 §2）
- Evidence 内に記録された Windows path に `PathBuf` を使わない（`WindowsPathValue` を使用、規範 §8）
- 観測していない行為を Event type で断定しない（例: `registry_set` ではなく `registry_observation`、規範 §7.1）
- timezone 不明の local time を UTC へ変換しない（規範 §6.2）
- 出力の既定上書き禁止、入力 directory 内への出力は拒否（規範 §5.4）
- Parser は全 Event を `Vec` で返さない（sink 型 interface、規範 §9.1）
- 破損入力で panic しない。未対応形式・version を既知形式として推測しない

## コマンド

まだ toolchain・ビルド設定が存在しない（Phase 0 未着手）。
Phase 0 で導入するもの: Cargo workspace、`rust-toolchain.toml`、CI（fmt / clippy / test / doc）、cargo-deny、cargo-fuzz、criterion。
**ビルド・test・lint 等のコマンドや構成を新規導入・変更したら、その時点で本ファイルへ追記・更新すること。**
