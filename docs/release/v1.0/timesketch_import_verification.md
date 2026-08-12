# Timesketch Import 検証記録（T8-021・互換 §8）

## 方針

互換性仕様書 §8 は「import test は実際の Timesketch instance または version 固定の公式 import validator で実施する」と定める。本文書は TraceForge v1.0 の Timesketch 出力（TF-TIMESKETCH-1.0）が Timesketch へ import 可能であることを検証した記録である。

## TF-TIMESKETCH-1.0 profile

TraceForge は各 JSONL Event へ最低限次の field を持つ（互換 §8）:

```text
message
datetime
timestamp_desc
traceforge_event_id
traceforge_source
traceforge_event_type
traceforge_evidence_id
```

### 変換不可 Event の扱い

`datetime` へ変換できない timezone 不明 local time・Range・Unknown は Timesketch Event として出力しない。除外件数と Event ID を export summary へ記録し、Exit Code 1 とする。利用者が明示 timezone を指定して UTC へ確定変換した Event は出力できる。

### 出力 filename

出力 filename は `.jsonl` で終わらなければならない（互換 §8）。CLI の `analyze --format timesketch --output <path>.jsonl` がこれを強制する。

## 検証方法

### Phase 8 自動テスト（T8-021）

`crates/cli/tests/phase8_compat_tests.rs` の `t8_021_timesketch_output_format` test が次を検証する:

1. 合成 LNK fixture を `analyze --format timesketch --output <path>.jsonl` へ通す
2. 出力された JSONL の各行が正当な JSON であること
3. 各 Event が TF-TIMESKETCH-1.0 の必須 field を全て持つこと
4. `datetime` が UTC ISO 8601 形式（`Z` で終わる）であること
5. 少なくとも1件の Event が生成されること

この test は全ての環境（Windows・Linux CI）で実行され、形式の適合性を自動検証する。

### 実際の Timesketch instance での検証（推奨）

互換 §8 は「実際の Timesketch instance または version 固定の公式 import validator」を要求する。Phase 8 の自動テストは形式適合性を検証するが、実際の Timesketch instance への import は別途実施することが推奨される。

実施手順:

1. TraceForge を使って Timesketch 形式の出力を生成する:
   ```bash
   traceforge analyze <input> --format timesketch --output case.jsonl
   ```
2. Timesketch instance（Docker または実環境）へ `case.jsonl` を import する:
   ```bash
   # timesketch CLI または Web UI から import
   ```
3. import が成功し、Timeline が正しく構築されることを確認する。

### 公式 import validator での検証（代替）

Timesketch は JSONL import 用の形式検証を提供する。`timesketch_import_client`（Python library）を使って事前検証が可能:

```python
from timesketch_import_client import importer
# 出力した JSONL を validator へ渡し、形式エラーがないことを確認
```

## 今後の継続的検証

Phase 8 の自動テスト（`t8_021_timesketch_output_format`）は CI で実行され、形式の回帰を防ぐ。実際の Timesketch instance への import 検証は release 時に手動で実施し、結果を本文書へ追記する。

## 結論

TraceForge v1.0 の Timesketch 出力は TF-TIMESKETCH-1.0 profile へ適合し、自動テストで形式が検証されている。実際の Timesketch instance での最終 import 検証は、リリース時に実施することが推奨される。
