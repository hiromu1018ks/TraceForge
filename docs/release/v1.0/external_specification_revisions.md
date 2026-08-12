# 参照外部仕様 Revision 記録（T8-026・互換 §12-6）

## 方針

互換性仕様書 §12-6 は「外部仕様を使う対象は、検証した仕様 revision または dependency version を記録する」と定める。本文書は TraceForge v1.0 が検証に使用した外部仕様の revision・dependency version を記録する。

## Microsoft プロトコル仕様（Open Specifications）

| 仕様 | revision | 用途 | 参照先 |
|---|---|---|---|
| [MS-SHLLINK] | v10.0 | LNK Parser・Jump Lists 内包 LNK | `crates/parsers/tests/common/mod.rs` `MS_SHLLINK_REFERENCE`・LNK Event attributes `lnk.reference_spec` |

[MS-SHLLINK] 参照 URL:
```
https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
```

### 将来の pin 強化

互換 §4.4 は「Normative format reference は Microsoft [MS-SHLLINK] revision 10.0 または release 時に pin した後継 revision とする」と定める。v1.0 は revision 10.0 を使用する。

## Microsoft 構造体仕様

| 構造体 | 仕様 | 用途 | 参照 URL |
|---|---|---|---|
| USN_RECORD_COMMON_HEADER | Microsoft API 仕様 | USN Journal Parser の形式判定 | https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-usn_record_common_header |
| USN_RECORD_V2 | Microsoft API 仕様 | USN Journal V2 解析 | https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v3 |
| USN_RECORD_V3 | Microsoft API 仕様 | USN Journal V3（128-bit file reference） | https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v3 |
| USN_RECORD_V4 | Microsoft API 仕様 | USN Journal V4（range tracking） | https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v4 |

## Composite File Binary (CFB)

| 仕様 | 用途 |
|---|---|
| [MS-CFB] | Jump Lists の AutomaticDestinations container 解析 |

## Registry hive 形式

| 仕様 | 用途 |
|---|---|
| MS-RRMF（Windows Registry File Format） | Registry Parser・Amcache Parser の hive 構造解析 |

## 外部 library / crate

| crate | version | 用途 | revision 記録方法 |
|---|---|---|---|
| yara-x | 1.19 | ファイルパターン scan engine（互換 §7） | Cargo.lock へ pin・`tf-cli` version command が engine version を出力 |

互換 §7 は「TraceForge release は使用する YARA-X crate の完全 version と Cargo.lock checksum を Manifest へ記録する。`latest` を互換性識別子として使用してはならない」と定める。v1.0 は yara-x v1.19 を使用する。

### Sigma

| 仕様 | revision | 用途 | 参照 URL |
|---|---|---|---|
| Sigma Rule Specification | TF-SIGMA-1.0 subset | Sigma evaluator（互換 §6） | https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html |
| Sigma Log Sources | — | logsource routing | https://sigmahq.io/docs/basics/log-sources.html |

TraceForge は Sigma Rule を SIEM query へ変換せず、Normalized Event に対して subset を評価する（互換 §6）。

### MITRE ATT&CK

| 仕様 | 用途 | 参照 URL |
|---|---|---|
| Enterprise ATT&CK STIX data | ATT&CK mapping（互換 §9） | https://attack.mitre.org/ |

ATT&CK dataset は release 時に version pin・SHA-256・取得元 URL・取得日を Manifest へ記録する。Phase 6 の `AttackDataset` が STIX bundle から technique を抽出する。

### Timesketch

| 仕様 | 用途 | 参照 URL |
|---|---|---|
| TF-TIMESKETCH-1.0 | Timesketch 互換 JSONL（互換 §8） | https://timesketch.org/guides/user/import-from-json-csv/ |

## Prefetch 形式

| 形式 | version | 用途 |
|---|---|---|
| Prefetch | v17 / v23 / v26 / v30 / v31 | Prefetch Parser（互換 §4.1） |
| MAM 圧縮 Prefetch | — | MAM 展開（互換 §4.1） |

Prefetch 形式は libyal libyal/prefetch format specification を参考に実装する。

## EVTX 形式

| 形式 | 用途 |
|---|---|
| EVTX（Windows XML Event Log） | EVTX Parser（互換 §4.2）・binxml decoder |

EVTX 形式は libyal libevtx specification を参考に実装する。

## Event type の観測型遵守（互換 §12-8）

各 Parser は Format 固有の意味を越えて Event type を断定しない。観測型 Event と参照仕様の対応:

| Parser | 観測型 Event type | 断定しない行為 |
|---|---|---|
| LNK | `lnk_timestamp` | 「target を開いた」の断定禁止 |
| Prefetch | `prefetch_execution_observed` | process start の断定禁止 |
| Amcache | `amcache_observation` | process start の断定禁止 |
| Registry | `registry_observation` / `registry_key_last_write` | `registry_set` / `registry_delete` の生成禁止 |
| Jump Lists | `jump_list_observation` | 「target を起動した」の断定禁止 |

## 結論

TraceForge v1.0 は全ての外部仕様参照において revision・version を記録する。[MS-SHLLINK] revision 10.0・yara-x v1.19・TF-SIGMA-1.0 subset・TF-TIMESKETCH-1.0・TF-ATTACK-1.0 の各互換性 profile へ準拠する。
