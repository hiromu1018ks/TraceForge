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

Phase 0 でプロジェクト基盤を導入済み（Rust 1.97.1、`rust-toolchain.toml` 固定）。
mise でローカル環境を管理する場合は `.mise.toml` でバージョンを指定し、`rust-toolchain.toml` と一致させる。

### ビルド・テスト・Lint

| 操作 | コマンド |
|---|---|
| フォーマット確認（workspace） | `cargo fmt --all --check` |
| フォーマット確認（fuzz crate） | `cargo fmt --manifest-path fuzz/Cargo.toml --check` |
| 自動フォーマット | `cargo fmt --all` |
| Lint（警告をエラー扱い） | `cargo clippy --all-targets -- -D warnings` |
| テスト | `cargo test` |
| ドキュメント生成 | `cargo doc --no-deps` |
| ビルド | `cargo build --workspace` |

### 品質ゲート

| 操作 | コマンド |
|---|---|
| cargo-deny（license・advisory・bans・sources） | `cargo deny check` |
| criterion benchmark ビルド | `cargo bench --no-run` |
| fuzz ビルド | `cargo build --manifest-path fuzz/Cargo.toml` |
| fuzz チェック（link 不要） | `cargo check --manifest-path fuzz/Cargo.toml` |

CI（`.github/workflows/ci.yml`）は push / pull_request で上記を自動実行する。
fuzz target の link は Windows MSVC 環境で失敗する（libfuzzer-sys のエントリポイント制約）ため、Linux CI で担保する。

**ビルド・test・lint 等のコマンドや構成を新規導入・変更したら、その時点で本ファイルへ追記・更新すること。**
