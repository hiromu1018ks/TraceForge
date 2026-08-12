# TraceForge 出力例（T8-024・製品 §13.2）

本文書の例は全て実際の合成 fixture から生成したものであり、手書きではない（製品 §13.2）。

## 生成方法

`generate_examples.ps1` を実行すると、次の処理を行う:

1. 合成 LNK fixture（[MS-SHLLINK] §2.1 準拠・hand-crafted）を `TempDir` へ生成
2. `cargo build -p tf-cli --release` で CLI binary をビルド
3. 各形式（JSONL・JSON・Text・CSV・Timesketch・inspect・version）で `traceforge analyze` を実行
4. 出力を本 directory へ保存

再生成手順:

```powershell
cd C:\Users\hirom\project\TraceForge
.\docs\examples\generate_examples.ps1
```

## fixture

合成 LNK fixture（`sample.lnk`）のメタデータ:

| 項目 | 値 |
|---|---|
| 形式 | Shell Link（[MS-SHLLINK] §2.1・revision 10.0） |
| 生成方法 | hand-crafted（実 Windows 環境の生成物ではない） |
| size | 80 byte（header 76 + terminal block 4） |
| SHA-256 | `54987b29a186976bc79444b8a7cd12da033838b03598a04be58c4fe137ef87ff` |
| flags | `IsUnicode`（0x00000080） |
| write FILETIME | `130605440000000000`（2014-11-15T16:53:20Z） |

Evidence ID: `tf-evidence-v1:2151072d302fe3e216d378e7d024956d86c1b067f0966e1126bb537881cd125f`

## 出力例一覧

| file | 形式 | 生成コマンド |
|---|---|---|
| `analyze_jsonl.jsonl` | JSONL（Schema §6） | `traceforge analyze sample.lnk --format jsonl` |
| `analyze_json.json` | JSON Case（Schema §5） | `traceforge analyze sample.lnk --format json` |
| `analyze_text.txt` | Text（規範 §19.1） | `traceforge analyze sample.lnk --format text` |
| `analyze_csv.csv` | CSV（RFC 4180・規範 §19.2） | `traceforge analyze sample.lnk --format csv --output out.csv` |
| `analyze_timesketch.jsonl` | Timesketch（TF-TIMESKETCH-1.0・互換 §8） | `traceforge analyze sample.lnk --format timesketch --output ts.jsonl` |
| `inspect.txt` | inspect 出力 | `traceforge inspect sample.lnk` |
| `version.txt` | version 出力 | `traceforge version` |

## 例の特徴

### JSONL（`analyze_jsonl.jsonl`）

Schema §6 の固定出力順: `case` → `evidence` → `artifact` → `event` → ... → `manifest`。各行が `schema_version` + `record_type` + `record` の envelope を持つ。manifest は必ず最終行。

### JSON（`analyze_json.json`）

Schema §5 の Case JSON 形式。top-level が `schema_version` + `record_type: case_bundle` + 各 record type の配列。

### Text（`analyze_text.txt`）

規範 §19.1 の制御文字可視 escape を適用した人が読みやすい形式。

### CSV（`analyze_csv.csv`）

RFC 4180 準拠。formula injection 対策（`=`, `+`, `-`, `@` 等で始まる cell へ `'` を前置）。

### Timesketch（`analyze_timesketch.jsonl`）

TF-TIMESKETCH-1.0 profile。各 Event が `message`・`datetime`・`timestamp_desc`・`traceforge_*` field を持つ。timezone 不明の Event は出力されず、除外件数が summary へ記録される。
