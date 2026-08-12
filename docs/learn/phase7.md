# Phase 7: 6種の出力形式と 9種の CLI command を完成させる

## 1. このフェーズで何を作ったか

Phase 6 までで、TraceForge は「Evidence を解析し、Event・Issue・Match・Finding を生成する」パイプラインを持ちました。しかしまだ「人間や他のツールへ結果を渡す」方法がありませんでした。Phase 7 は、この「最後の1マイル」を完成させるフェーズです。

具体的には次を作りました:

- **6種の Exporter**（`tf-export` crate）: Text・JSON・JSONL・CSV・HTML・Timesketch
- **9種の CLI command**（`tf-cli` crate）: `analyze`・`timeline`・`correlate`・`sigma`・`yara`・`export`・`rules`・`inspect`・`version`
- **Manifest 確定処理**（規範 §20）: resolved config digest・counts・components・rules・attack_dataset 等の全必須 field 集約
- **出力安全性**（規範 §19）: CSV formula injection・terminal ESC injection・HTML script injection を防ぐ
- **決定性の保証**（規範 §13.1・§20）: run metadata（時刻・PID 等）が分析結果の同一性比較へ影響しない

## 2. 新しく作ったファイル

### `tf-export` crate（`crates/export/src/`）

- `lib.rs`: 公開 API の再エクスポート
- `case_data.rs`: [`CaseData`] - 全 exporter へ共通の入力型
- `error.rs`: `ExportError` 型（規範 §17.2）
- `sanitize.rs`: 出力安全性の共通 helper（`escape_control_chars`・`sanitize_csv_cell`・`html_text_escape`）
- `schema_check.rs`: Schema major version 検証（互換 §10）
- `manifest.rs`: Manifest 確定処理（T7-032）・run metadata 分離（規範 §13.1）
- `text.rs`: Text exporter（規範 §19.1・T7-001）
- `json.rs`: JSON exporter（Schema §5・T7-002）
- `jsonl.rs`: JSONL exporter（Schema §6・T7-003）
- `csv.rs`: CSV exporter（規範 §19.2・T7-004）
- `html.rs`: HTML exporter（規範 §19.3・T7-005）
- `timesketch.rs`: Timesketch exporter（互換 §8・T7-006）

### 統合テスト（`crates/export/tests/`）

- `injection_tests.rs`: T7-008（出力 injection 対策）
- `schema_tests.rs`: T7-009・§21-15（Schema validation）
- `determinism_tests.rs`: T7-033（run metadata 分離）

### `tf-cli` crate（`crates/cli/src/`）

- `main.rs`: プロセス entry point（stdout/stderr 分離・Exit Code 設定）
- `lib.rs`: `run(&[String])` API（テストから直接呼出可能）
- `args.rs`: 最小引数 parser（clap 等の外部 crate 不使用）
- `runtime.rs`: Case 読込・出力書込・RunContext
- `version_info.rs`: tool・Schema・compatibility profile version
- `commands/mod.rs`: command dispatch
- `commands/{analyze,timeline,correlate,sigma,yara,export,rules,inspect,version}.rs`: 各 command 実装

### 統合テスト（`crates/cli/tests/`）

- `cli_tests.rs`: T7-020〜T7-034 の各 command 挙動検証（16 test）

## 3. 設計のポイント

### T7-001: Text exporter（規範 §19.1）

Text exporter は Evidence 起源文字列へ `escape_control_chars` を適用します。これにより、悪意ある Evidence が terminal 制御文字（ESC sequence）を含んでいても、表示時に可視 escape（`^[` 等）へ変換されます。LF/CR は行構造を保持するためそのまま残します。

### T7-004: CSV exporter と formula injection（規範 §19.2）

表計算ソフトが cell の先頭文字 `= + - @ TAB CR` を formula として解釈する性質を悪用した攻撃を防ぎます。`sanitize_csv_cell` は:

1. RFC 4180 準拠の quoting（`,` `"` `\r` `\n` を含む場合は `"` で囲む）
2. formula 危険文字の検出（先頭の非空白文字が `= + - @ \t \r`）
3. 危険時は先頭へ `'` を1つ前置

`csv_sanitized=true` を Manifest へ記録します（規範 §19.2）。

### T7-005: HTML exporter と CSP（規範 §19.3）

完全 offline で動作する単一 HTML file を生成します。次の安全対策を施しています:

- `Content-Security-Policy` meta tag: `default-src 'none'; script-src 'none'; ...`
- 全 Evidence 起源文字列を `html_text_escape` で entity 参照へ変換
- 外部 CDN・画像・font・script を一切使用しない

### T7-006: Timesketch exporter（互換 §8）

Timesketch は Google が公開している timeline 解析ツールです。各 Event を Timesketch が期待する JSONL 形式（`message`・`datetime`・`timestamp_desc` 等の必須 field）へ変換します。

重要な制約: UTC へ変換できない時刻（timezone 不明 local time・Range・Unknown・DST Ambiguous）は Timesketch Event として出力しません。除外した Event ID と件数を summary へ記録し、Exit Code 1 を返します。

### T7-008: 出力 injection test（規範 §21-11）

`injection_tests.rs` で次の3種の injection を1つの Case へ仕込み、全 exporter で安全性を検証します:

- CSV formula: `=cmd|'/C calc'!A1`
- terminal ESC: `\x1B[2J\x1B[H`
- HTML script: `<script>alert('xss')</script>`

各 exporter がこれらをそのまま出力しないことを確認します。

### T7-009: 異 Schema major version の自動変換禁止（互換 §10）

`schema_check.rs` の `check_case_schema_major` と `check_jsonl_schema_major` が、`schema_version` の major が `1` 以外の場合は error とします。これにより、将来の Schema v2.0.0 への勝手な変換を防ぎます。

### T7-020: CLI 骨格

CLI 引数 parser は外部 crate（clap 等）を使わず自前で実装しました。これにより:

- 依存関係を最小限に抑える
- `--no-hash` を明示的に拒否する（規範 §2・T7-022）
- stdout/stderr の分離を自前で制御（規範 §19.1・T7-034）

`run(&[String]) -> CliResult` API を提供し、テストから直接呼び出せます（subprocess spawn 不要）。

### T7-032: Manifest 確定処理（規範 §20）

`finalize_manifest` が Schema §5.9 の全必須 field を集約します:

- TraceForge version・build commit・target
- Schema version・compatibility profile
- run start/end time（run metadata）
- resolved config と SHA-256
- Case ID
- Evidence・Event・Issue・Match・Finding 件数
- parser・engine・ATT&CK dataset の version 一覧
- timezone assumptions・resource limit・到達状況
- `complete: true/false`・Exit Code

### T7-033: run metadata が determinism へ影響しない（規範 §13.1・§20）

`manifest_without_run_metadata` が Manifest から `run_started_at` と `run_finished_at` を取り除きます。これにより、同じ Case を2回分析した場合、run 時刻が違っても分析レコードは同一であることを検証できます。

### T7-034: stdout/stderr 分離（規範 §19.1）

- **stdout**: 解析結果（version 情報・Timeline・export 結果・rule 一覧 等）
- **stderr**: log（warning・info・error）
- `--quiet`: stderr への log を抑制するが、解析結果（stdout）は抑制しない

## 4. 出力形式毎の安全性

| 形式 | 主な対策 | 関連規範 |
|---|---|---|
| Text | 制御文字・ESC の可視 escape | §19.1 |
| JSON | UTF-8・LF・NaN/Infinity 禁止・canonical key sort | §19.4 |
| JSONL | 1行1 object・string 内改行 escape・Manifest 最終行 | §19.4・Schema §6 |
| CSV | RFC 4180 quoting・formula injection 対策・`csv_sanitized` 記録 | §19.2 |
| HTML | CSP 埋込・text node escape・offline・外部 request 禁止 | §19.3 |
| Timesketch | UTC 変換不可 Event の除外・summary 記録・Exit Code 1 | 互換 §8 |

## 5. CLI command 一覧

| Command | 役割 | 主な関連タスク |
|---|---|---|
| `analyze` | Evidence を解析し Case を生成する | T7-021・T7-031・T7-032 |
| `timeline` | Event を Timeline 形式で表示・filter する | T7-023 |
| `correlate` | 保存済み Event へ Correlation Rule を適用する | T7-024 |
| `sigma` | 保存済み Event へ Sigma Rule を適用する | T7-025 |
| `yara` | 明示した Evidence へ YARA-X Rule を適用する | T7-026 |
| `export` | Case を別形式へ変換する | T7-027 |
| `rules` | Rule の validate と一覧表示を行う | T7-028 |
| `inspect` | 単一 Artifact の安全な概要を表示する | T7-029 |
| `version` | Tool・Schema・Compatibility profile の version を表示する | T7-030 |

## 6. テスト結果

Phase 7 で追加したテスト:

- `tf-export` 単体テスト: 43 件（sanitize・json・jsonl・csv・html・text・timesketch・manifest・schema_check・case_data）
- `tf-export` 統合テスト: 17 件（injection_tests・schema_tests・determinism_tests）
- `tf-cli` 単体テスト: 12 件（args parser）
- `tf-cli` 統合テスト: 16 件（cli_tests）

合計 **88 件の新規テスト** を追加。workspace 全体では **1,218 テスト** 全て合格。

## 7. 既存の制約・制限

- `analyze` command の EventStore→Event list 変換は Phase 7 では `Vec` で行う。100万 Event 規模の streaming 出力は Phase 3 の `tf_store::output::write_jsonl` 経路を使う。
- `sigma`・`correlate`・`yara` の各 command は Rule の compile・評価結果を表示するが、Finding 統合までは行わない（別途 `analyze` で統合 Finder を呼ぶ設計）。
- `inspect` command は file の概要（size・sha256・magic 判定）を表示するのみ。Artifact 識別や Parser 実行は `analyze` を使う。

## 8. 次のステップ

Phase 8（品質保証とリリース）へ進みます:

- golden determinism test（threads 1/2/自動で canonical JSON byte 一致・規範 §13.3・§21-7）
- 破損 fixture 群での panic 非発生 test
- fuzz campaign の実施
- benchmark 実測
- README 例の自動生成
- 全 Required 対象の compatibility acceptance 最終確認

Phase 7 は **M5 マイルストーン（機能完成）** へ到達しました。
