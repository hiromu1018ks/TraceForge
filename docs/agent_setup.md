# TraceForge: 新規環境セットアップ手順（AI エージェント向け）

> この文書は AI エージェント（opencode 等）が新しい環境で TraceForge の作業を開始するための最初のセットアップ手順です。人間の開発者が新規参加する場合も同様です。

## 0. 前提

- 対象 OS: Windows / macOS / Linux のいずれか（本プロジェクトは Windows フォレンジックツールだが、開発・テストはどの OS でも可能。fuzz の link のみ Linux CI で担保）
- 必須ツール: `git`、Rust（`rustup` または `mise`）、`cargo-deny`
- 応答・ドキュメント・コード内コメントは**すべて日本語**（AGENTS.md 必須要件）

## 1. リポジトリの clone

```bash
git clone https://github.com/hiromu1018ks/TraceForge.git
cd TraceForge
```

SSH を使う場合（push 時の認証を SSH 鍵で行う場合は初回からこちらが推奨）:

```bash
git clone git@github.com:hiromu1018ks/TraceForge.git
cd TraceForge
```

## 2. ツールチェインと依存の解決

`rust-toolchain.toml` が **Rust 1.97.1** を固定しており、`.mise.toml` も同じバージョンを指定しています。`cd TraceForge` 後に `cargo` を1回でも叩くと、rustup / mise が自動で 1.97.1 を解決します。

```bash
cargo --version          # rust-toolchain.toml 解決をトリガ。1.97.1 が表示されるはず
rustup show              # 解決された toolchain と components (rustfmt, clippy) を確認
```

`Cargo.lock` はコミット対象（T0-005・互換 §11）。clone 直後の依存は lock ファイルで pin 済みのため、他の環境と**完全に同じビルド結果**になります（決定性）。

## 3. 動作確認（クローン直後の健康診断）

```bash
cargo fmt --all --check                              # フォーマット確認
cargo clippy --all-targets -- -D warnings            # Lint（警告はエラー扱い）
cargo test --workspace                               # テスト全件
cargo doc --no-deps                                  # ドキュメント生成
cargo bench --no-run                                 # criterion bench ビルド確認
cargo check --manifest-path fuzz/Cargo.toml          # fuzz target コンパイル確認
```

- テスト数はフェーズごとに増加します。Phase 1 完了時点で 122 件（lib 105 + property 7 + schema_fixtures 10）。
- `fuzz` の **link** は Windows MSVC 環境で失敗します（libfuzzer-sys のエントリポイント制約）。これは仕様（AGENTS.md 記載）。`cargo check` までで OK。link は Linux CI で担保します。

## 4. cargo-deny の導入

`cargo deny check` は CI の deny job と同じ検証（advisories / licenses / bans / sources）を行います。ローカルでも実行できるよう導入します。**バージョンを揃えるため `--locked` 必須**。

```bash
cargo install cargo-deny --locked
cargo deny check                                     # advisories ok / bans ok / licenses ok / sources ok
```

`--locked` を付けると `Cargo.lock` 通りの依存でビルドされ、CI と同じバージョンが入ります。

## 5. 作業の開始手順（必須ドキュメントの読み順）

セットアップ完了後、作業を開始する前に**必ず次の順で読む**（AGENTS.md 開発ワークフロー）:

1. **`AGENTS.md`** — 開発ワークフロー・仕様書の優先順位・禁止事項・コマンド一覧
2. **`docs/traceforge_implementation_roadmap_v1.0.md`** の該当フェーズ（範囲と完了条件）
3. **`docs/traceforge_implementation_tasks_v1.0.md`** の該当フェーズ（タスク一覧）
4. **`PROMPT.md`** — 次に実装すべきフェーズのプロンプト（コードブロックをそのまま実行開始の指示として使う）

### フェーズ継続・新規開始の判定

- `PROMPT.md` は「次回実装開始用」に記入済みです。コードブロック内の「対象フェーズ・タスク」が次に着手すべきフェーズを示します。
- `docs/traceforge_implementation_tasks_v1.0.md` の checkbox（`[x]` = 完了、`[ ]` = 未着手）で進捗を確認できます。未完了の最小フェーズが次の対象です。
- 仕様書4文書（`docs/traceforge_*_v1.0.md`）へ実装範囲・進捗を追記してはなりません（製品 §15）。進捗は tasks の checkbox のみで管理します。

## 6. 実装完了時のコミット規定（要約）

AGENTS.md 開発ワークフローの要約:

1. フェーズ単位で実装する（フェーズをまたぐ一括実装をしない）
2. 実装後は必ずセルフレビューし、fmt / clippy / test / doc / deny が通ることを確認
3. `docs/learn/` へ初学者向け解説 md を作成
4. `docs/traceforge_implementation_tasks_v1.0.md` の該当タスク checkbox を `[x]` へ
5. 導入したコマンド・依存・lint 設定を `AGENTS.md`「コマンド」節へ追記
6. **実装完了時のコミットを既定とする**（ユーザーへの個別確認不要）。push はユーザーの明示要求時のみ
7. 完了報告では次に取り組むべきフェーズ・タスクの提言を行う。**次回プロンプトはチャットへ出力せず `PROMPT.md` を次フェーズ用へ更新**し、コミットへ含める

## 7. push 時の認証設定（必要な場合のみ）

push はユーザーの明示要求時のみ実行します。その際、GitHub 認証が必要です。

```bash
# SSH 鍵を使う場合（推奨）: clone 時から SSH URL を使っていれば追加設定不要
git remote set-url origin git@github.com:hiromu1018ks/TraceForge.git

# HTTPS のままなら Personal Access Token を使う（初回 push 時に聞かれる）
```

## 8. トラブルシュート

| 症状 | 対処 |
|---|---|
| `rustup show` でも 1.97.1 が入らない | `TraceForge` ディレクトリ内で `cargo --version` を叩く。`rust-toolchain.toml` 解決が走る |
| mise 派でバージョンが合わない | `.mise.toml` の `rust = "1.97.1"` と `rust-toolchain.toml` の `channel = "1.97.1"` が一致しているか確認 |
| `cargo deny` が見つからない | ステップ4の `cargo install cargo-deny --locked` を実行 |
| fuzz ビルドで link error（Windows MSVC） | 仕様（AGENTS.md 記載）。`cargo check` までで OK。link は Linux CI で担保 |
| テストが環境依存で落ちる | `TZ` 環境変数や locale が影響していないか確認。DST 関連のテストは IANA timezone database に依存（chrono-tz が同梱済み） |
| 依存ライセンスで deny がFAILED | `deny.toml` の許可リストへ追加する必要あり。変更時は AGENTS.md「コマンド」節の「依存構成」も更新 |

## 9. よく使うコマンド早見表

| 操作 | コマンド |
|---|---|
| フォーマット | `cargo fmt --all` |
| Lint | `cargo clippy --all-targets -- -D warnings` |
| テスト | `cargo test --workspace` |
| ドキュメント | `cargo doc --no-deps` |
| 依存検証 | `cargo deny check` |
| bench ビルド | `cargo bench --no-run` |
| fuzz ビルド | `cargo build --manifest-path fuzz/Cargo.toml` |
| fuzz check（link 不要） | `cargo check --manifest-path fuzz/Cargo.toml` |

詳細は `AGENTS.md`「コマンド」節を参照。
