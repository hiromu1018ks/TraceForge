# Schema §9 fixture 一覧（T1-055 / T1-056）

Schema §9 が要求する9種類の fixture。各 fixture は `expect`（`valid` / `invalid`）で
期待結果を明示する。統合テスト `crates/core/tests/schema_fixtures.rs` が各 fixture を
読み込み、対応する validator で検証する。

| # | ファイル | 対象 Schema | 期待結果 | 内容 |
|---|---|---|---|---|
| 1 | `01_minimal_event_time.json` | EventTime | valid | 各 record type の最小 valid（utc_instant 最小形） |
| 2 | `02_full_event_time.json` | EventTime | valid | 全 optional field を含む valid（local_time 全 field） |
| 3 | `03_missing_required.json` | Correlation Rule | invalid | 必須 field 欠落 |
| 4 | `04_major_version_diff.json` | Case JSON | invalid | 異なる major version（Schema §2.3） |
| 5 | `05_unknown_enum.json` | EventTime | invalid | 未知の enum 値 |
| 6 | `06_time_special_forms.json` | EventTime | valid/invalid 混在 | unknown timezone / range / unknown time / 両端 null range |
| 7 | `07_jsonl_without_manifest.jsonl` | JSONL | invalid（未完了） | Manifest 欠落 |
| 8 | `08_unsupported_operator.json` | Correlation Rule | invalid | 未対応 operator |
| 9 | `09_config_limit_zero.toml` | Configuration | invalid | limit が 0（Schema §8.3） |

## ファイル形式

- JSON fixture: `_comment` / `expect` / `schema`（任意）/ `instance`（単数）または
  `instances`（複数、各要素に `expect` を持てる）を持つ。
- JSONL fixture: 通常の TraceForge JSONL envelope。最終行に Manifest がないことで
  未完了を検証する。
- TOML fixture: TraceForge 設定。test 側で `Config::from_toml_str` + `validate` を呼ぶ。

`_comment` は検証で無視する人間向けの注釈。
