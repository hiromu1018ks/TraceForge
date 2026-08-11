# AGENTS.md

TraceForge — Windows フォレンジック Timeline & Evidence Correlation Engine（Rust 製 CLI）。
`docs/` に仕様書4文書と開発計画（roadmap / tasks / PROMPT.md）があり、フェーズ単位で実装する。進捗は `tasks` の checkbox で管理し、仕様書4文書へは実装範囲・進捗・開発順序を追記しない（製品 §15）。

## 言語

- 応答・ドキュメント・コード内コメントは**すべて日本語**とする（ユーザー必須要件）。

## 開発ワークフロー（ユーザー必須要件）

1. `docs/traceforge_implementation_roadmap_v1.0.md` のフェーズ単位で実装する。フェーズをまたぐ一括実装をしない。
2. 実装後は**必ずセルフレビューし、問題を修正してから完了とする**。完了前に §コマンド の fmt / clippy / test / doc / deny が通ることをローカルで確認する。
3. フェーズ完了時に、プログラミング初学者向けの解説を `docs/learn/` に md で作成する。
4. `docs/traceforge_implementation_tasks_v1.0.md` の該当タスク checkbox を `[x]` に更新する（タスク ID の再利用・欠番の詰め替えは禁止）。
5. **実装が完了したら（セルフレビュー・検証・上記 3〜4 のドキュメント更新まで全て終えた段階で）コミットする。** ユーザーへの個別確認は不要（本プロジェクトでは実装完了時のコミットを既定とする）。push はユーザーの明示要求時のみ。
6. 完了報告では、**次に取り組むべきフェーズ・タスクの提言**を行う。**次回プロンプトはチャットへ出力せず `PROMPT.md` を次フェーズ用へ更新する**（プロンプト本文は同ファイルの規定形式に従う）。更新した `PROMPT.md` は上記 5 のコミットに含める。

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

### 依存構成（Phase 4 更新）

- workspace 共通依存はルート `Cargo.toml` の `[workspace.dependencies]` へ一元管理し、各 crate は `<dep>.workspace = true` で継承する。version は `Cargo.lock` へ pin され、cargo-deny で再現性と供給連鎖安全を担保する。
- `tf-core` が Phase 1 で追加した依存: `sha2`（SHA-256）、`hex`（lowercase hex）、`serde` / `serde_json`（canonical JSON・Case JSON）、`jsonschema`（Draft 2020-12、default-features を切って `draft202012` のみ有効化・外部通信なし）、`chrono` / `chrono-tz`（EventTime・IANA timezone・DST）、`toml`（設定 load）、`thiserror`（Error 型 derive）。
- `tf-evidence` が Phase 2 で追加した依存: `tf-core`（path + version 指定で cargo-deny wildcard 対応）、`sha2`・`hex`（snapshot 中の同時 SHA-256、規範 §5.5）、`unicode-normalization`（source_locator の NFC 正規化、規範 §5.2）、`thiserror`（Error 型 derive）。dev-dependency に `tempfile`（テスト用一時 directory）。
- `tf-store` が Phase 3 で追加した依存: `tf-core`（path + version 指定）、`serde_json`（Event の canonical JSON 直列化・復元、規範 §10）、`chrono`（EventTime 復元時の DateTime parse、規範 §6）、`thiserror`（Error 型 derive）。dev-dependency に `tempfile`（テスト用一時 directory）。
- `tf-parsers` が Phase 4 で追加した依存: `tf-core`（path + version 指定、Event・Provenance・Issue・ArtifactSource・Error 型）、`tf-evidence`（path + version 指定、EvidenceItem・ProbeResult・probe framework・snapshot）、`tf-store`（path + version 指定、EventStoreSink が EventStore を使う・規範 §9.1・§10）、`serde_json`（attributes の `BTreeMap<String, Value>` 構築・規範 §13.2）、`chrono`（LNK FILETIME → DateTime<Utc> 変換・[MS-SHLLINK] §2.1.3）、`thiserror`（SinkError derive・規範 §17）。dev-dependency に `tempfile`（テスト用一時 directory・EventStore spool file・snapshot）。
- workspace `[workspace.dependencies]` へ `unicode-normalization = "0.1"` を追加した（Phase 2）。
- dev-dependencies: `proptest`（property test、`tests/property_tests.rs`）と `criterion`（benchmark）は `tf-core`。`tempfile` は `tf-evidence`・`tf-store`・`tf-parsers`。
- `deny.toml` の許可ライセンスへ `MIT-0`（MIT No Attribution）を追加した。`jsonschema` の依存 `borrow-or-share` が同ライセンスのため。
- `tf-core` の統合テストは `crates/core/tests/` 配下（`schema_fixtures.rs`・`property_tests.rs`）。Schema §9 fixture は `crates/core/tests/fixtures/schema/` へ保存する。
- `tf-evidence` の統合テストは `crates/evidence/tests/` 配下（`acceptance_tests.rs`）。規範 §21 の受け入れ条件（§21-3・§21-4・§21-9・§21-10）を検証する。
- `tf-store` の統合テストは `crates/store/tests/` 配下（`acceptance_tests.rs`）。規範 §21 の受け入れ条件（§21-2・§21-6・§21-8）を検証する。
- `tf-parsers` の統合テストは `crates/parsers/tests/` 配下（`framework_tests.rs`・`lnk_tests.rs`・`prefetch_tests.rs`・`usn_tests.rs`・`evtx_tests.rs`・`registry_tests.rs`・`acceptance_tests.rs`）。規範 §9（Parser 契約）・互換 §4.1（Prefetch）・互換 §4.2（EVTX）・互換 §4.3（USN）・互換 §4.4（LNK）・互換 §4.7（Registry）・互換 §12（acceptance 8条件）・M2 縦割りを検証する。共通ヘルパー（合成 LNK fixture 生成・合成 Prefetch fixture 生成・合成 USN V2/V3/V4 fixture 生成・合成 EVTX file/chunk/record/binxml fixture 生成・合成 Registry hive fixture ビルダ（`RegistryFixtureBuilder`・`RegistryKeySpec`・`RegistryValueSpec`）・合成 LOG fixture ビルダ（TFLOG）・literal-only MAM 圧縮・snapshot・ArtifactInstance 構築）は `tests/common/mod.rs`。
- `tf-core` の `time.rs` へ Phase 3 で `TimePrecision` / `TimezoneSource` / `TimestampKind` の `from_schema_str` メソッドを追加した（Event 復元に必要な lowercase 文字列からの変換）。
- `tf-parsers` の依存方向: `tf-parsers` → `tf-core`/`tf-evidence`/`tf-store`（本番依存）。`tf-store` は `tf-parsers` へ依存しない（EventStoreSink を tf-parsers 側へ置くことで循環を回避）。M2 縦割りは tf-parsers の統合テストで実施する。

**ビルド・test・lint 等のコマンドや構成を新規導入・変更したら、その時点で本ファイルへ追記・更新すること。**
