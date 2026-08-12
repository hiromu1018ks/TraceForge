# TraceForge

> Windows Forensic Timeline & Evidence Correlation Engine written in Rust

TraceForge は、Windows に残る複数のフォレンジック痕跡を読み取り、共通 Event へ変換し、時系列で整理し、関連する証拠を結び付け、調査上重要な結果を Finding として提示する Rust 製 CLI ツールである。

## 主な機能

| 機能 | 内容 |
|---|---|
| 7 種 Parser | Prefetch・EVTX・USN Journal・LNK・Jump Lists・Amcache・Registry |
| 共通 Event model | 複数形式の痕跡を共通 Event へ変換・Provenance で元 record へ到達可能 |
| Timeline | 時刻の不確実性を隠さない時系列整理（規範 §6） |
| 3 検知 engine | Sigma subset（TF-SIGMA-1.0）・YARA-X・Correlation |
| Finding 統合 | 検知結果を説明可能な Finding へ統合・ATT&CK mapping |
| 6 出力形式 | Text・JSON・JSONL・CSV・HTML・Timesketch |
| 決定的 ID | UUID・乱数を使わない SHA-256 基準の決定的 ID（規範 §12） |
| Read-only・安全 | Evidence を変更しない・外部通信なし・破損入力で panic しない |

## インストール・ビルド

```bash
git clone <repository-url>
cd TraceForge
cargo build --release
```

ビルド成果物は `target/release/tf-cli.exe`（Windows）または `target/release/tf-cli`（Unix）。

Rust 1.97.1（`rust-toolchain.toml` 固定）が必要。

## 使用方法

基本形:

```bash
traceforge <COMMAND> [OPTIONS]
```

9 command:

```
analyze    Evidence を解析して Case を生成する
timeline   Event を Timeline として表示・filter する
correlate  保存済み Event へ Correlation Rule を適用する
sigma      保存済み Event へ Sigma Rule を適用する
yara       明示した Evidence へ YARA-X Rule を適用する
export     Case を別形式へ変換する
rules      Rule の validate と一覧表示を行う
inspect    単一 Artifact の安全な概要を表示する
version    Tool・Schema・Compatibility profile の version を表示する
```

### 例（合成 LNK fixture への解析）

次の例は全て実際の合成 fixture から生成している（製品 §13.2）。完全な出力は [`docs/examples/`](docs/examples/) を参照。

```bash
traceforge analyze sample.lnk --format jsonl
```

出力（JSONL・Schema §6 の固定出力順）:

```json
{"record":{"case_id":"tf-case-v1:f80082a6...","name":"sample.lnk",...},"record_type":"case","schema_version":"1.0.0"}
{"record":{"evidence_id":"tf-evidence-v1:2151072d...","sha256":"54987b29...","size":80,...},"record_type":"evidence","schema_version":"1.0.0"}
{"record":{"artifact_id":"tf-artifact-v1:fed21767...","artifact_type":"lnk","parser_id":"traceforge-lnk",...},"record_type":"artifact","schema_version":"1.0.0"}
{"record":{"event_id":"tf-event-v1:bc0c55fc...","event_type":"lnk_timestamp","assertion":"observed","time":{"value":"2014-11-15T16:53:20Z",...},...},"record_type":"event","schema_version":"1.0.0"}
{"record":{"complete":true,"exit_code":0,...},"record_type":"manifest","schema_version":"1.0.0"}
```

各 Event は Provenance へ source_sha256・record_locator・source_ordinal を持ち、元 record へ到達可能。

### version 表示

```bash
traceforge version
```

### 単一 file の安全な概要

```bash
traceforge inspect sample.lnk
```

## 決定性と再現性

同一の Evidence 内容・入力内相対 path・確定済み設定・Rule 内容・外部データ・TraceForge build から、thread 数に依存しない同一の分析レコードと同一順序を生成する（規範 §13・製品 §4.3）。

- 決定的 ID: 全ての ID は SHA-256 基準で UUID・乱数を使わない（規範 §12）
- canonical JSON: key の UTF-8 byte 順 sort・最短 decimal（Schema §2.1）
- thread 数非依存: threads 1/2/自動で canonical JSON が byte 一致（規範 §13.3）
- run metadata 分離: 実行時刻等は分析 determinism へ影響しない（規範 §13.1）

## 安全性

- **Read-only**: Evidence を変更しない（規範 §2）
- **SHA-256 必須**: `--no-hash` は提供しない（規範 §2）
- **不変 snapshot**: Parser は元 Evidence でなく snapshot を解析（規範 §5.5）
- **入出力分離**: 出力の入力 directory 配下への配置を拒否（規範 §5.4）
- **破損入力で panic しない**: panic 境界が入力起因 panic を捕捉（規範 §9.4）
- **出力 injection 対策**: CSV formula・terminal ESC・HTML script を防止（規範 §19）
- **外部通信なし**: 全処理は offline で完結（規範 §2）

## テスト・品質ゲート

```bash
cargo fmt --all --check                                    # フォーマット確認
cargo clippy --all-targets -- -D warnings                  # Lint
cargo test                                                 # 全テスト実行
cargo doc --no-deps                                        # ドキュメント生成
cargo deny check                                           # license・advisory・bans・sources
cargo check --manifest-path fuzz/Cargo.toml                # fuzz target ビルド検証
cargo bench --no-run                                       # benchmark ビルド検証
```

CI（`.github/workflows/ci.yml`）が push / pull_request で上記を自動実行する。

## ドキュメント

### 仕様書（`docs/`）

| 文書 | 内容 |
|---|---|
| `traceforge_schemas_v1.0.md` | データ形式（Schema） |
| `traceforge_normative_core_specification_v1.0.md` | 動作（規範語 MUST/SHOULD 厳守） |
| `traceforge_compatibility_v1.0.md` | 対応範囲 |
| `traceforge_product_specification_v1.0.md` | 製品概要 |

### 開発計画（`docs/`）

| 文書 | 内容 |
|---|---|
| `traceforge_implementation_roadmap_v1.0.md` | フェーズ・マイルストーン・release gate |
| `traceforge_implementation_tasks_v1.0.md` | 実装タスクリスト・トレーサビリティ |

### リリース記録（`docs/release/v1.0/`）

| 文書 | 内容 |
|---|---|
| `release_gate_checklist.md` | roadmap §8 release gate 全項目の合否状況 |
| `fuzz_campaign_report.md` | fuzz target・corpus・campaign 記録 |
| `benchmark_report.md` | benchmark 実測値と測定条件 |
| `dependency_license_record.md` | 依存・license・advisory 記録 |
| `external_specification_revisions.md` | 参照外部仕様 revision 記録 |
| `timesketch_import_verification.md` | Timesketch import 検証記録 |
| `compatibility_acceptance_summary.md` | 互換 §12 全 8 項目の最終確認 |

### 初学者向け解説（`docs/learn/`）

Phase 0〜8 の各フェーズへ初学者向け解説を配置する。

## crate 構成

```
crates/
├── core/      データモデル・決定的 ID・時刻・Windows path・Schema（Phase 1）
├── evidence/  discovery・snapshot・SHA-256・Artifact 識別（Phase 2）
├── store/     Event Store・決定的 iteration・Timeline（Phase 3）
├── parsers/   7 種 Parser と framework（Phase 4）
├── engines/   Sigma・YARA-X・Correlation 検知（Phase 5）
├── findings/  Finding 統合・ATT&CK mapping（Phase 6）
├── export/    6 出力形式（Phase 7）
└── cli/       9 command エントリポイント（Phase 7）
```

## License

TraceForge 自体の license は別途決定するまで各 crate へ宣言しない。依存 crate の license は `deny.toml`（cargo-deny）で許可リストを運用する。詳細は [`docs/release/v1.0/dependency_license_record.md`](docs/release/v1.0/dependency_license_record.md) を参照。
