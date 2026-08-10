# TraceForge Schema仕様書 v1.0

## 1. 目的

本書はTraceForge v1.0が読み書きするデータの形を定義する。対象は次の4種類である。

1. Case JSON
2. JSONL record
3. Correlation Rule YAML
4. TOML configuration

Schema versionはSemVerで`1.0.0`とする。製品versionとは独立して更新する。

## 2. 共通規則

### 2.1 名前と文字code

- field名とenum値はlowercase `snake_case`とする。
- JSON、JSONL、YAML、TOMLはUTF-8とする。
- JSONとJSONLはLF改行を使用する。
- SHA-256は64文字のlowercase hexとする。
- IDは`tf-<type>-v1:<64 lowercase hex>`とする。
- byte数、件数、offsetは0以上のintegerとする。
- scoreは0.0以上1.0以下のfinite numberとする。
- 不明値は、Schemaがnullを許可するfieldだけnullにできる。空文字列を不明値として使用しない。
- canonical JSONではobject keyをUTF-8 byte順で再帰的にsortする。意味上setであるarrayは各節のsort keyでsortし、sequenceを表すarrayは元順序を保持する。
- numberはNaNとInfinityを禁止し、同じ値を常に同じ最短decimal表現で出力する。

### 2.2 Timestamp

- UTC timestampはRFC 3339のUTC表現を使用する。例: `2026-08-10T01:15:20Z`。
- run metadataは実際の精度を保持してよい。
- Event timeは単一timestamp stringではなく、§4の`event_time`を使用する。
- NaN、Infinity、実在しないcalendar dateを禁止する。

### 2.3 Version compatibility

- Writerは本書が定義するfieldだけを出力する。
- Readerは同一major versionの未知fieldを無視してよいが、値を再出力する場合は保持する。
- 必須field欠落、未知の必須enum、異なるmajor versionはerrorとする。
- JSONLの各行は単独で`schema_version`と`record_type`を持つ。

## 3. 共通定義

### 3.1 ID pattern

```regex
^tf-(case|evidence|artifact|event|match|finding)-v1:[0-9a-f]{64}$
```

### 3.2 Severity

```text
informational
low
medium
high
critical
```

### 3.3 Confidence level

```text
low
medium
high
```

### 3.4 Artifact source

```text
prefetch
evtx
usn_journal
lnk
jump_list
amcache
registry
file
unknown
```

### 3.5 Parse status

```text
complete
partial
skipped
failed
```

## 4. Event Time Schema

`event_time`は次の共通fieldを持つ。

| Field | Type | Required | 説明 |
|---|---|---:|---|
| `type` | enum | Yes | `utc_instant`, `local_time`, `range`, `unknown` |
| `original` | string/null | Yes | Evidence内の元表現 |
| `kind` | string | Yes | timestampの意味 |
| `precision` | enum | Yes | `nanosecond`から`unknown` |
| `timezone_source` | enum | Yes | timezoneの根拠 |
| `uncertainty_ms` | integer/null | Yes | 推定誤差。0以上 |

type別field:

| Type | 追加field |
|---|---|
| `utc_instant` | `value` RFC 3339 UTC string |
| `local_time` | `value` `YYYY-MM-DDTHH:MM:SS[.fraction]`, `timezone` IANA nameまたはnull |
| `range` | `start`, `end` RFC 3339 UTC stringまたはnull。両方nullは禁止 |
| `unknown` | 追加fieldなし |

JSON Schema fragment:

```json
{
  "$id": "https://traceforge.example/schema/v1/event-time.schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TraceForge Event Time v1",
  "oneOf": [
    {
      "type": "object",
      "additionalProperties": false,
      "required": ["type", "value", "original", "kind", "precision", "timezone_source", "uncertainty_ms"],
      "properties": {
        "type": {"const": "utc_instant"},
        "value": {"type": "string", "format": "date-time", "pattern": "Z$"},
        "original": {"type": ["string", "null"]},
        "kind": {"$ref": "#/$defs/timestamp_kind"},
        "precision": {"$ref": "#/$defs/precision"},
        "timezone_source": {"$ref": "#/$defs/timezone_source"},
        "uncertainty_ms": {"type": ["integer", "null"], "minimum": 0}
      }
    },
    {
      "type": "object",
      "additionalProperties": false,
      "required": ["type", "value", "timezone", "original", "kind", "precision", "timezone_source", "uncertainty_ms"],
      "properties": {
        "type": {"const": "local_time"},
        "value": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?$"},
        "timezone": {"type": ["string", "null"], "minLength": 1},
        "original": {"type": ["string", "null"]},
        "kind": {"$ref": "#/$defs/timestamp_kind"},
        "precision": {"$ref": "#/$defs/precision"},
        "timezone_source": {"$ref": "#/$defs/timezone_source"},
        "uncertainty_ms": {"type": ["integer", "null"], "minimum": 0}
      }
    },
    {
      "type": "object",
      "additionalProperties": false,
      "required": ["type", "start", "end", "original", "kind", "precision", "timezone_source", "uncertainty_ms"],
      "properties": {
        "type": {"const": "range"},
        "start": {"type": ["string", "null"], "format": "date-time", "pattern": "Z$"},
        "end": {"type": ["string", "null"], "format": "date-time", "pattern": "Z$"},
        "original": {"type": ["string", "null"]},
        "kind": {"$ref": "#/$defs/timestamp_kind"},
        "precision": {"$ref": "#/$defs/precision"},
        "timezone_source": {"$ref": "#/$defs/timezone_source"},
        "uncertainty_ms": {"type": ["integer", "null"], "minimum": 0}
      },
      "not": {"properties": {"start": {"type": "null"}, "end": {"type": "null"}}}
    },
    {
      "type": "object",
      "additionalProperties": false,
      "required": ["type", "original", "kind", "precision", "timezone_source", "uncertainty_ms"],
      "properties": {
        "type": {"const": "unknown"},
        "original": {"type": ["string", "null"]},
        "kind": {"$ref": "#/$defs/timestamp_kind"},
        "precision": {"$ref": "#/$defs/precision"},
        "timezone_source": {"const": "unknown"},
        "uncertainty_ms": {"type": ["integer", "null"], "minimum": 0}
      }
    }
  ],
  "$defs": {
    "timestamp_kind": {
      "enum": ["created", "modified", "accessed", "executed", "event_logged", "registry_modified", "observed", "unknown"]
    },
    "precision": {
      "enum": ["nanosecond", "microsecond", "millisecond", "second", "minute", "day", "unknown"]
    },
    "timezone_source": {
      "enum": ["artifact_defined", "explicit_offset", "case_default", "cli_override", "inferred", "unknown"]
    }
  }
}
```

## 5. Case JSON Schema

### 5.1 Top level

Case JSONは次のtop-levelだけを持つ。`case`内へEvidenceやEventを重複格納してはならない。

```json
{
  "schema_version": "1.0.0",
  "record_type": "case_bundle",
  "case": {},
  "evidence": [],
  "artifacts": [],
  "events": [],
  "issues": [],
  "matches": [],
  "findings": [],
  "manifest": {}
}
```

### 5.2 Case

| Field | Type | Required |
|---|---|---:|
| `case_id` | TraceForge ID | Yes |
| `external_case_id` | string/null | Yes |
| `name` | string | Yes |
| `analyst` | string/null | Yes |
| `description` | string/null | Yes |
| `default_timezone` | string/null | Yes |
| `tags` | unique string array | Yes |

### 5.3 Evidence

| Field | Type | Required |
|---|---|---:|
| `evidence_id` | TraceForge ID | Yes |
| `source_locator` | relative locator string | Yes |
| `size` | integer >= 0 | Yes |
| `sha256` | lowercase SHA-256 | Yes |
| `integrity_status` | enum | Yes |
| `parse_eligible` | boolean | Yes |

`integrity_status`:

```text
verified_snapshot
changed_during_snapshot
snapshot_failed
```

`snapshot_locator`はprivate runtime情報のためCase JSONへ出力してはならない。

### 5.4 Artifact instance

| Field | Type | Required |
|---|---|---:|
| `artifact_id` | TraceForge ID | Yes |
| `evidence_id` | TraceForge Evidence ID | Yes |
| `artifact_type` | Artifact source enum | Yes |
| `parser_id` | string | Yes |
| `parser_version` | SemVer string | Yes |
| `probe_result` | enum | Yes |
| `detection_reasons` | string array | Yes |
| `parse_status` | Parse status enum | Yes |

### 5.5 Event

| Field | Type | Required |
|---|---|---:|
| `event_id` | TraceForge Event ID | Yes |
| `time` | Event Time | Yes |
| `source` | Artifact source | Yes |
| `event_type` | string | Yes |
| `assertion` | `observed` / `inferred` | Yes |
| `hostname` | string/null | Yes |
| `user` | string/null | Yes |
| `path` | Windows path/null | Yes |
| `program` | string/null | Yes |
| `process` | Process/null | Yes |
| `message` | string | Yes |
| `attributes` | JSON object | Yes |
| `provenance` | Provenance | Yes |

Windows path:

```json
{
  "original": "C:\\Users\\alice\\Downloads\\invoice.exe",
  "comparison_key": "c:\\users\\alice\\downloads\\invoice.exe",
  "normalization_profile": "windows-path-v1",
  "normalization_notes": []
}
```

Process:

```json
{
  "pid": 1234,
  "ppid": 500,
  "process_guid": null,
  "parent_process_guid": null,
  "image_path": null,
  "command_line": "powershell.exe -File example.ps1"
}
```

Provenance:

```json
{
  "evidence_id": "tf-evidence-v1:...",
  "artifact_id": "tf-artifact-v1:...",
  "source_locator": "Security.evtx",
  "source_sha256": "...",
  "parser_id": "traceforge-evtx",
  "parser_version": "1.0.0",
  "record_locator": {"type": "record_id", "value": "12345"},
  "source_ordinal": 12344
}
```

### 5.6 Issue

```json
{
  "issue_id": "TF-W-EVTX-PARTIAL-RECORD",
  "severity": "warning",
  "scope": "record",
  "evidence_id": "tf-evidence-v1:...",
  "artifact_id": "tf-artifact-v1:...",
  "record_locator": {"type": "record_id", "value": "12345"},
  "source_ordinal": 12344,
  "message": "Record was truncated and was skipped"
}
```

Issue severityは`warning / recoverable / fatal`、scopeは`case / evidence / artifact / record / rule / output`とする。

### 5.7 Match

`match_type`は`correlation / sigma / yara_x`とする。共通field:

```text
match_id
match_type
rule_id
rule_sha256
event_ids
evidence_ids
reasons
```

YARA-X matchは`matched_patterns`、Sigma matchは`logsource_mapping`、Correlation matchは`score`と`ordered_event_ids`を追加できる。

### 5.8 Finding

```text
finding_id
title
description
severity
confidence.score
confidence.level
confidence.reasons
event_ids
evidence_ids
match_ids
rule_refs
attack_mappings
observed_evidence
inference
```

Findingは`created_at`を持ってはならない。生成時刻はManifestへ保存する。

### 5.9 Manifest

```text
traceforge_version
build_commit
target
schema_version
compatibility_profile
run_started_at
run_finished_at
resolved_config
resolved_config_sha256
case_id
counts
components
rules
attack_dataset
timezone_assumptions
limits
incomplete_reasons
complete
exit_code
```

## 6. JSONL Schema

各行は次の共通envelopeを持つ。

```json
{
  "schema_version": "1.0.0",
  "record_type": "event",
  "record": {}
}
```

`record_type`は次のいずれかとする。

```text
case
evidence
artifact
event
issue
match
finding
manifest
```

出力順は固定する。

1. case
2. evidence: `evidence_id`昇順
3. artifact: `artifact_id`昇順
4. event: 規範コア仕様のTimeline順
5. issue: 規範コア仕様のIssue順
6. match: `match_id`昇順
7. finding: Severity降順、`finding_id`昇順
8. manifest: 必ず最後の1行

ManifestがないJSONLは未完了出力として扱う。

## 7. Correlation Rule Schema

YAMLはJSON互換data modelへ変換してから次のSchemaで検証する。

YAML anchor、alias、custom tag、duplicate keyは使用してはならない。Parserはduplicate keyを後勝ちで上書きせずvalidation errorにする。

```json
{
  "$id": "https://traceforge.example/schema/v1/correlation-rule.schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["id", "version", "title", "severity", "sequence", "within", "partition_by", "score"],
  "properties": {
    "id": {"type": "string", "pattern": "^TF-CORR-[0-9]{3,}$"},
    "version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
    "title": {"type": "string", "minLength": 1, "maxLength": 200},
    "description": {"type": "string", "maxLength": 4000},
    "enabled": {"type": "boolean", "default": true},
    "severity": {"enum": ["informational", "low", "medium", "high", "critical"]},
    "sequence": {
      "type": "array",
      "minItems": 1,
      "maxItems": 16,
      "items": {"$ref": "#/$defs/step"}
    },
    "within": {"type": "string", "pattern": "^[1-9][0-9]*(ms|s|m|h|d)$"},
    "partition_by": {
      "type": "array",
      "minItems": 1,
      "uniqueItems": true,
      "items": {"enum": ["case_id", "hostname", "user"]},
      "default": ["case_id", "hostname"]
    },
    "allow_uncertain_time": {"type": "boolean", "default": false},
    "max_uncertainty_ms": {"type": ["integer", "null"], "minimum": 0, "default": null},
    "max_matches": {"type": "integer", "minimum": 1, "maximum": 1000000, "default": 100000},
    "score": {"$ref": "#/$defs/score"},
    "mitre_attack": {
      "type": "array",
      "uniqueItems": true,
      "items": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"}
    },
    "tags": {"type": "array", "uniqueItems": true, "items": {"type": "string"}},
    "references": {"type": "array", "uniqueItems": true, "items": {"type": "string", "format": "uri"}}
  },
  "$defs": {
    "step": {
      "type": "object",
      "additionalProperties": false,
      "required": ["event_type"],
      "properties": {
        "event_type": {"type": "string", "minLength": 1},
        "source": {"type": "string"},
        "assertion": {"enum": ["observed", "inferred"]},
        "where": {"type": "array", "items": {"$ref": "#/$defs/predicate"}},
        "bind": {
          "type": "object",
          "propertyNames": {"pattern": "^[a-z][a-z0-9_]{0,63}$"},
          "additionalProperties": {"type": "string", "pattern": "^[a-z][a-z0-9_.]*$"}
        }
      }
    },
    "predicate": {
      "type": "object",
      "additionalProperties": false,
      "required": ["field", "operator"],
      "properties": {
        "field": {"type": "string", "pattern": "^[a-z][a-z0-9_.]*$"},
        "operator": {"enum": ["eq", "neq", "contains", "starts_with", "ends_with", "regex", "exists", "in"]},
        "value": {},
        "variable": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"},
        "case_sensitive": {"type": "boolean", "default": false},
        "normalization_profile": {"type": ["string", "null"], "default": null}
      },
      "allOf": [
        {
          "if": {"properties": {"operator": {"const": "exists"}}, "required": ["operator"]},
          "then": {"not": {"anyOf": [{"required": ["value"]}, {"required": ["variable"]}]}},
          "else": {
            "oneOf": [
              {"required": ["value"], "not": {"required": ["variable"]}},
              {"required": ["variable"], "not": {"required": ["value"]}}
            ]
          }
        }
      ]
    },
    "score": {
      "type": "object",
      "additionalProperties": false,
      "required": ["base", "adjustments"],
      "properties": {
        "base": {"type": "number", "minimum": 0, "maximum": 1},
        "adjustments": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["reason", "value"],
            "properties": {
              "reason": {"type": "string", "minLength": 1, "maxLength": 200},
              "value": {"type": "number", "minimum": -1, "maximum": 1}
            }
          }
        }
      }
    }
  }
}
```

Rule例:

```yaml
id: TF-CORR-001
version: 1.0.0
title: Execution shortly after file creation
description: File creation followed by execution evidence for the same normalized path.
enabled: true
severity: high
partition_by: [case_id, hostname]
within: 5m
allow_uncertain_time: false
max_uncertainty_ms: null
max_matches: 100000
sequence:
  - event_type: file_create
    assertion: observed
    bind:
      file_path: path.comparison_key
  - event_type: program_execution
    assertion: observed
    where:
      - field: path.comparison_key
        operator: eq
        variable: file_path
        normalization_profile: windows-path-v1
score:
  base: 0.75
  adjustments:
    - reason: Exact normalized path match
      value: 0.10
mitre_attack: [T1204.002]
tags: [execution]
references: []
```

## 8. Configuration Schema

### 8.1 優先順位

```text
CLI > explicit config file > default config file > built-in defaults
```

確定後のconfiguration全体をcanonical JSONへ変換し、SHA-256をManifestへ保存する。

### 8.2 Built-in defaults

```toml
[analysis]
recursive = true
snapshot_mode = "always"
timezone = ""
threads = 0
follow_symlinks = false

[strict]
parser = false
rules = false
limits = false

[correlation]
enabled = true
rule_dirs = ["./rules/correlation"]

[sigma]
enabled = true
rule_dirs = ["./rules/sigma"]

[yara]
enabled = true
mode = "suspicious"
rule_dirs = ["./rules/yara"]

[output]
format = "text"
include_provenance = true
overwrite = false

[limits]
max_files = 100000
max_recursion_depth = 64
max_evidence_file_size_bytes = 34359738368
max_snapshot_total_bytes = 1099511627776
max_events = 50000000
max_issues = 100000
max_issues_per_evidence = 10000
max_findings = 1000000
max_correlation_matches_per_rule = 100000
max_correlation_window_seconds = 86400
max_yara_scan_file_size_bytes = 1073741824
max_rule_files = 100000
max_rule_file_size_bytes = 16777216
max_memory_bytes = 2147483648
```

### 8.3 Validation

- `snapshot_mode`はv1.0では`always`だけを受け付ける。
- `threads=0`は自動設定、1以上は明示値とする。
- `timezone=""`はtimezone指定なしを意味する。指定時はIANA timezone nameだけを受け付ける。
- `follow_symlinks=true`はv1.0ではunsupportedとして設定errorにする。将来用fieldとして予約する。
- `yara.mode`は`all / suspicious / explicit`とする。
- `output.format`は`text / json / jsonl / csv / html / timesketch`とする。
- limitは1以上でなければならず、0をunlimitedとして扱ってはならない。
- `max_correlation_window_seconds`を超えるRuleはvalidation errorとする。

## 9. Schema test

実装repositoryは次をfixtureとして保持しなければならない。

- 各record typeの最小valid sample
- 全optional fieldを含むvalid sample
- 必須field欠落sample
- 異なるmajor version sample
- unknown enum sample
- unknown timezone、range、unknown time sample
- JSONL final Manifest欠落sample
- Correlation Ruleの未対応operator sample
- Config limitが0または負数のsample

公式releaseでは、生成した全Golden outputを本書のSchemaから生成したvalidatorで検証する。
