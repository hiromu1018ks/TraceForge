# Phase 5 Sigma 編: Sigma ルールで不審な動きを検知する

## 1. このフェーズで何を作ったか

Phase 5 共通編で Rule file の読込基盤（`RuleRegistry`）を作りました。Phase 5 Sigma 編（T5-010〜T5-017）では、その基盤の上に **Sigma ルール評価エンジン**を実装しました。

Sigma（シグマ）は、セキュリティイベントログ用の汎用ルール記述形式です。YAML で書かれ、世界中で共有されています。TraceForge は Sigma ルールを読み込み、解析済みの Event に対して評価し、マッチしたら Match を生成します。

重要な方針: TraceForge は **Sigma の全機能を評価するわけではありません**。「TF-SIGMA-1.0」という独自の subset（部分集合）のみを評価し、未対応の要素を含むルールは全体を skip します。これは安全性のためです — 理解できない要素を無視して誤った判定をするより、正直に「このルールは評価できない」と伝える方が安全です。

## 2. 新しく作ったファイル

### YAML parser（`crates/engines/src/yaml/`）

Sigma と将来の Correlation で共有する **最小 YAML パーサー**を自前実装しました。

なぜ既存の YAML ライブラリを使わないのか？理由は2つあります:

1. **安全性**: YAML の anchor（`&`）・alias（`*`）・tag（`!`）・duplicate key は、意図しないデータの差し替えや上書きを引き起こす可能性があります。TraceForge は規範 §14・Schema §7 でこれらを明確に禁止しています。自前パーサーなら、これらを確実に検出して拒否できます。

2. **依存リスク**: 外部ライブラリを追加すると、そのライブラリのバグや供給連鎖リスク（サプライチェーン攻撃）に晒されます。Sigma ルールで使う YAML は比較的単純なため、最小パーサーで十分対応できます。

対応している YAML 機能:
- block mapping（`key: value`）
- block sequence（`- item`）
- flow collection（`{a: 1}`, `[1, 2, 3]`）
- 文字列（plain・single-quoted・double-quoted）
- 整数・真偽値・null

拒否する要素:
- `&anchor`・`*alias`・`!tag`（error）
- `---`・`...`（multi-document marker・error）
- `|`・`>`（block scalar・error・未対応）
- 同名 key の重複（error）
- tab 文字のインデント（error）

### Sigma 評価エンジン（`crates/engines/src/sigma/`）

6つのモジュールで Sigma ルール評価を実装しました:

| モジュール | 役割 |
|---|---|
| `modifier.rs` | 6種の modifier（contains・startswith・endswith・cased・exists・all）の定義 |
| `condition.rs` | condition 文字列の parser（AND・OR・NOT・括弧・`1 of`・`all of`） |
| `rule.rs` | SigmaRule 構造体・YAML→struct 変換・未対応要素検出 |
| `fieldmap.rs` | Sigma field 名 → TraceForge Event field への対応表 |
| `logsource.rs` | logsource block から routing 条件（channel・event_type）を構築 |
| `evaluator.rs` | Event への評価・Match 変換 |

## 3. Sigma ルールの構造と評価の流れ

### Sigma ルールの例

```yaml
title: Suspicious PowerShell Encoded Command
id: 12345678-1234-1234-1234-123456789012
status: experimental
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains: "-enc"
    condition: selection
```

### 評価の流れ

1. **YAML parse**: raw bytes → `YamlValue` tree
2. **Rule compile**: `YamlValue` → `SigmaRule`（未対応要素の検出）
3. **Logsource routing**: Event の channel/event_type が logsource 条件を満たすか確認
4. **Selection evaluation**: 各 selection の field 制約を Event へ対して評価
5. **Condition evaluation**: condition 式を評価して true/false を判定
6. **Match 生成**: true なら `Match`（match_type=Sigma）を生成

### Selection の評価

「selection」は field→value の条件の集まりです。1つの selection 内の全条件が AND で結合されます:

```yaml
selection:
    EventID: 4688           # EventID が 4688 と等しい
    CommandLine|contains: "-enc"  # かつ、CommandLine が -enc を含む
```

リスト値は OR（何れか一つ）で評価されます:

```yaml
selection:
    EventID:
        - 4624
        - 4625       # EventID が 4624 または 4625
```

### Modifier の動き

| Modifier | 意味 | 例 |
|---|---|---|
| `contains` | 値が field 値の部分文字列 | `CommandLine\|contains: "-enc"` |
| `startswith` | field 値が値で始まる | `Image\|startswith: "C:\Users\\"` |
| `endswith` | field 値が値で終わる | `Image\|endswith: ".exe"` |
| `cased` | 大文字小文字を区別 | `User\|cased: "Administrator"` |
| `exists` | field の有無を検査 | `Computer\|exists: true` |
| `all` | リスト値が全て match | `Cmd\|contains\|all: ["-enc", "-w"]` |

## 4. 未対応要素の skip（規範 §15.1・§21-12）

TraceForge が対応しない Sigma 機能を含むルールは、**部分評価せず全体を skip**します。

未対応要素の例:
- `base64`・`base64offset`・`re`・`cidr`・`windash` modifier
- aggregation condition（`count() by Field > 5`）
- `near` 演算子
- timeframe
- Sigma Correlation Rule
- Sigma Filter specification
- placeholder（`%var%`）

対応要素と未対応要素が混在していても、ルール全体を skip します。これは「分からないものは安全側に倒す」という方針です。

## 5. field mapping（互換 §6.3）

Sigma ルールの field 名を、TraceForge Event の属性へ変換する対応表です:

| Sigma field | TraceForge field |
|---|---|
| `EventID` | `attributes.evtx.event_id` |
| `Channel` | `attributes.evtx.channel` |
| `Provider_Name` | `attributes.evtx.provider` |
| `Computer` | `hostname` |
| `Image` / `NewProcessName` | `process.image_path.original` |
| `CommandLine` / `ProcessCommandLine` | `process.command_line` |
| `User` / `SubjectUserName` | `user` |
| `TargetFilename` | `path.original` |

対応表にない Sigma field は、Event の `attributes` から直接探します（`evtx.event_data.<field>` 等）。

## 6. Match への変換（T5-016）

Sigma ルールが Event にマッチした場合、次の `Match` レコードを生成します:

```json
{
    "match_id": "tf-match-v1:...",
    "match_type": "sigma",
    "rule_id": "12345678-1234-...",
    "rule_sha256": "abc123...",
    "event_ids": ["tf-event-v1:..."],
    "evidence_ids": ["tf-evidence-v1:..."],
    "reasons": ["Sigma rule '...' matched (selections: selection)"],
    "logsource_mapping": {
        "product": "windows",
        "service": "security",
        "resolved_channel": "Security",
        "routing_reason": "product=windows, service=security"
    }
}
```

`match_id` は決定的生成です（rule_id + rule_sha256 + event_ids）。同じルールと同じ Event から常に同じ ID が生成されます。

## 7. テストと品質ゲート

### テスト構成

| テスト種別 | ファイル | 件数 |
|---|---|---|
| YAML parser unit test | `yaml/tests.rs` | 31 |
| Sigma modifier unit test | `modifier.rs` | 2 |
| Sigma condition unit test | `condition.rs` | 14 |
| Sigma rule unit test | `rule.rs` | 13 |
| Sigma evaluator unit test | `evaluator.rs` | 22 |
| Sigma logsource unit test | `logsource.rs` | 7 |
| Sigma fieldmap unit test | `fieldmap.rs` | 10 |
| Sigma 統合テスト | `tests/sigma_tests.rs` | 25 |
| loader unit test（既存） | `loader.rs` | 39 |
| 共通編 統合テスト（既存） | `tests/acceptance_tests.rs` | 13 |

### Fuzz target

`fuzz/fuzz_targets/sigma.rs` を追加しました。Sigma evaluator へ破損 YAML を投げ、panic しないことを継続的 fuzzing で検証します（F-025）。

### 品質ゲート結果

全て通過:
- `cargo fmt --all --check` ✓
- `cargo fmt --manifest-path fuzz/Cargo.toml --check` ✓
- `cargo clippy --all-targets -- -D warnings` ✓
- `cargo test`（workspace 全 916 件） ✓
- `cargo doc --no-deps` ✓
- `cargo deny check` ✓
- `cargo build --workspace` ✓
- `cargo check --manifest-path fuzz/Cargo.toml` ✓
- `cargo bench --no-run` ✓

## 8. 次のステップ

Phase 5 は3つの構成要素があります:
- **Sigma 編**（T5-010〜T5-017）← 今回完了
- **YARA-X 編**（T5-020〜T5-027）← 次
- **Correlation 編**（T5-030〜T5-042）

次は YARA-X 編を推奨します。YARA-X はファイル内容のパターンマッチングを行うエンジンで、Sigma（イベントログ評価）とは別の検知経路です。Sigma と YARA-X が揃えば、Phase 6 の Finding 統合で両方の Match を統合できるようになります。
