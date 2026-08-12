# Phase 6: 3つの検知結果を説明可能な Finding へ統合する

## 1. このフェーズで何を作ったか

Phase 5 で3つの検知エンジン（Sigma・YARA-X・Correlation）が揃いました。各エンジンは「どの Rule が、どの Event・Evidence で、どんな理由で match したか」を表す **Match**（Schema §5.7）を出力します。しかし Match はエンジン毎に形式が違い、人間が読んで「これは何が起きているのか？」を理解するには不十分です。

Phase 6 では **Finding**（Schema §5.8）という「人間が説明できる形の検知結果」へ Match を統合する仕組みを作りました。Finding は次のような特徴を持ちます:

- **Severity**（真実だった場合の調査上の重要度）と **Confidence**（Evidence がどの程度 Finding を支持しているか）を明確に分離する
- **観測事実**（observed_evidence）と **推論**（inference）を分けて記述する（推測を観測として扱わない）
- 全ての元 Event・Evidence・Rule hash へ参照が到達できる
- **ATT&CK mapping** を使って、検知された活動が MITRE ATT&CK のどの Technique に該当するかを記録する

Phase 6 では `tf-findings` crate を本格実装し、Phase 1 で定義した Finding 型へ具体的な値を埋める仕組みと、ATT&CK STIX dataset を読み込んで Technique ID を検証する仕組みを提供します。

## 2. 新しく作ったファイル

### `tf-findings` crate 本体（`crates/findings/src/`）

- `lib.rs`: 公開 API の再エクスポート
- `merger.rs`: **Finding merger**（T6-001〜T6-005）。Match list → Finding list への変換
- `attack/mod.rs`: ATT&CK 関連 module の纏め
- `attack/dataset.rs`: **STIX dataset 読込と manifest**（T6-006）
- `attack/technique.rs`: **Technique ID の形式検証と dataset 存在検証**（T6-007）
- `attack/mapping.rs`: **ATT&CK mapping 生成**（T6-008・T6-009）

### 統合テスト（`crates/findings/tests/`）

- `acceptance_tests.rs`: T6-001〜T6-009 の受け入れ条件を end-to-end で検証（20テスト）

### tf-core の拡張

- `crates/core/src/finding.rs`: `AttackMapping` へ `tactic` / `source` / `dataset_version` / `dataset_sha256` field を追加。`AttackMappingSource` enum（`Rule` / `SigmaTag` / `BuiltIn` / `Manual`）を新設。

## 3. 設計のポイント

### T6-001: Finding merger（match 喪失なし）

`FindingBuilder::build(&matches)` が Match list を受け取り、Finding list を返します。重要な性質:

- **入力 Match は必ず何らかの Finding の `match_ids` へ含まれる**（match 喪失なし）
- `FindingMergeSummary::all_matches_referenced()` でこれを検証できる

各 Match は原則として1件の Finding へ1:1 変換されます。Merger は入力 Match を `(rule_sha256, match_id)` の byte 昇順で sort してから処理し、出力 Finding list を Schema §6 の出力順（Severity 降順・finding_id 昇順）で返します。

### T6-002: 自動統合禁止（規範 §16）

これが一番重要な設計上の制約です。規範 §16 は「同じ Event や Evidence を参照するという理由だけで異なる Finding を自動統合してはならない」と定めます。

実装では明示統合 rule（`FindingMergeRule`）が指定された場合だけ複数 Match を1つの Finding へ統合します:

```rust
let options = FindingMergeOptions {
    merge_rules: vec![FindingMergeRule {
        group_id: MergeGroupId::new("TF-FINDING-MERGE-001"),
        rule_ids: vec!["sigma-A".into(), "yara-A".into()],
        title: "Suspicious activity cluster".into(),
        // ...
    }],
    ..Default::default()
};
let builder = FindingBuilder::new(options);
```

統合 rule 無しのデフォルト状態では Match 1件 → Finding 1件の1:1 変換になります。「共通 Event/Evidence を参照しているから自動でまとめる」という推測は行いません。

### T6-003: Finding 必須 field

Schema §5.8 と規範 §16 が定める必須 field を全て埋めます:

- `finding_id`: 決定的生成（規範 §12.4）
- `title` / `description`: Rule ID と match type から生成
- `severity`: Correlation は score base から推定、Sigma/YARA-X は既定（`default_severity` で上書き可）
- `confidence`: Correlation は score、Sigma/YARA-X は既定 `0.5`
- `event_ids` / `evidence_ids` / `match_ids` / `rule_refs`: Match list から集計して sort
- `observed_evidence` / `inference`: T6-004 参照

Finding は `created_at` を持ってはならない（Schema §5.8）。生成時刻は Manifest の `run_started_at` へ保存します。

### T6-004: observed_evidence と inference の分離

製品 §10 は「Sigma・YARA-X・Correlation の結果を統合する場合も、各結果を失わず、Finding からすべての元 Event と Evidence を参照できるものとする」と定めます。これを実現するため、Finding の説明文を次の2つに分けます:

- **`observed_evidence`**: 客観的事実のみ。推測を含めない。
  - 例: `rule_id=sigma-powershell`、`match_type=sigma`、`event_ids=[tf-event-v1:e1]`、`reason: Sigma rule '...' matched (selections: ...)`
- **`inference`**: 推論。観測事実に基づく人間向けの解釈。
  - 例: `Sigma rule 'sigma-powershell' matched (severity=medium). Investigate the referenced events/evidence.`

Merger は `observed_evidence` へ推測語（"Investigate"・"likely incident"・"may indicate" 等）を含めないことを保証します。

### T6-005: 参照検証（製品 §10）

`FindingMergeSummary` が入力 Match 全てを過不足無く統合したことを検証情報として返します:

```rust
pub struct FindingMergeSummary {
    pub findings: Vec<Finding>,
    pub input_match_count: usize,
    pub referenced_match_ids: BTreeSet<String>,
    // ...
}

impl FindingMergeSummary {
    pub fn all_matches_referenced(&self, input_match_ids: &BTreeSet<String>) -> bool {
        self.referenced_match_ids == *input_match_ids
    }
}
```

テストでは event_ids・evidence_ids・rule_sha256・match_ids の4軸全てで「入力 Match の情報が全て Finding へ到達できる」ことを検証しています。

### T6-006: ATT&CK STIX dataset の version pin・SHA-256

MITRE ATT&CK は STIX 2.x bundle 形式で dataset を公開します（`https://github.com/mitre/cti`）。TraceForge は外部通信を行わない（規範 §2）ため、ユーザーが手動で取得した STIX bundle file への path を CLI 経由で渡す設計です。

```rust
pub struct AttackDatasetManifest {
    pub version: String,        // 例: "15.1"
    pub sha256: String,         // STIX bundle bytes の SHA-256
    pub source_url: String,     // 取得元 URL
    pub retrieved_at: String,   // 取得日（RFC 3339 UTC）
}

pub struct AttackDataset {
    pub manifest: AttackDatasetManifest,
    techniques: BTreeMap<String, TechniqueInfo>,
}

impl AttackDataset {
    pub fn from_stix_bytes(
        bundle_bytes: &[u8],
        manifest: AttackDatasetManifest,
    ) -> Result<Self, AttackDatasetError>;
}
```

`from_stix_bytes` は STIX bundle を JSON として parse し、`attack-pattern` 型の object から `external_references` 経由で Technique ID を取り出します。SHA-256 は渡された bytes から計算して manifest へ上書きします（ユーザーの手入力ミスを防ぐため）。

### T6-007: Technique ID の dataset 存在検証

互換 §9 は「Technique/Sub-technique ID が dataset に存在しない Rule は validation error とする」と定めます。名前は ID から dataset で解決し、Rule 内の自由記述名を正本として使用してはなりません。

実装は2段階:

1. **形式検証**（`validate_technique_id_format`）: `T<4桁数字>(.<3桁数字>)?` であること
2. **存在検証**（`validate_technique_ids`）: dataset へ問い合わせて存在すること

```rust
pub enum UnknownTechniqueError {
    InvalidFormat(String),
    NotInDataset { id: String, version: String },
}
```

不在 ID は Rule validation error となり、規範 §17.2 の Exit Code 5（strict rules mode）または Exit Code 1（Warning・既定）へ寄与します。

### T6-008: ATT&CK mapping 生成（4経路のみ）

規範 §15.3 は ATT&CK mapping の生成経路を4つに限定します:

1. **Rule**: Correlation Rule の `mitre_attack` field。`from_correlation_rule()`
2. **Sigma tag**: Sigma Rule の `tags` 内 `attack.tXXXX` 形式。`from_sigma_rule_tags()`
3. **Built-in**: TraceForge 組み込みの既定 mapping。`built_in_mappings()`
4. **Manual**: ユーザーが明示的に指定。`manual_mapping()`

自動推測（例: Event 内容から technique を推定）・外部サービス問合せは禁止します。各 mapping は `AttackMappingSource` で生成元を明示します:

```rust
pub enum AttackMappingSource {
    Rule,
    SigmaTag,
    BuiltIn,
    Manual,
}
```

Phase 6 では `built_in_mappings()` は空 list を返します（Phase 7 以降で Parser が検出した挙動と technique を結びつける組み込み mapping を追加する拡張ポイント）。

### T6-009: ATT&CK mapping への dataset version + hash 記録

規範 §15.3 は「Technique 名と ID に加えて、使用した ATT&CK dataset version と SHA-256 を記録する」と定めます。`AttackMapping` は次の field を持ちます:

```rust
pub struct AttackMapping {
    pub technique_id: String,
    pub technique_name: Option<String>,
    pub tactic: Option<String>,
    pub source: AttackMappingSource,
    pub dataset_version: Option<String>,    // T6-009
    pub dataset_sha256: Option<String>,     // T6-009
}
```

dataset 経由で mapping を生成した場合は version と sha256 が必ず付与されます。dataset 無しで生成した場合は `None` になります（後で attach できる）。

## 4. ATT&CK dataset の扱い（実運用向けメモ）

TraceForge は外部通信を行わないため、ATT&CK dataset の取得はユーザー責任です。実運用では次のように使います:

1. ユーザーが MITRE CTI repo から STIX bundle をダウンロード（例: `enterprise-attack-15.1.json`）
2. CLI へ `--attack-dataset ./enterprise-attack-15.1.json --attack-version 15.1 --attack-source-url https://github.com/mitre/cti/releases/tag/15.1` のように指定
3. TraceForge が file を読み込み、SHA-256 を計算して Manifest へ記録
4. Rule が宣言した Technique ID を dataset へ照合。不在 ID は validation error

Phase 6 では CLI は未実装（Phase 7 で対応）のため、本フェーズでは library API として提供しています。

## 5. 決定性（規範 §13）

Phase 6 の全出力は thread 数・iterator 順に依存しません:

- Match list は事前に `(rule_sha256, match_id)` で sort してから処理
- Finding list は Schema §6 の出力順（Severity 降順・finding_id 昇順）で返す
- event_ids・evidence_ids・match_ids・rule_refs は全て `BTreeSet` で集計して sort 済み
- ATT&CK mapping は `technique_id` 昇順で sort
- 統合 rule は `MergeGroupId` の byte 昇順で評価

これにより、入力 Match list の順序が違っても同一 Finding list が出力されます（テスト `finding_list_order_is_deterministic_regardless_of_input` で検証）。

## 6. Finding ID の決定性（規範 §12.4）

Finding ID は次の4 field から決定的に生成されます:

1. `finding_type`（`correlation` / `sigma` / `yara_x` / `merge`）
2. `rule_content_sha256_list`（sort 済み）
3. `sorted_event_ids`
4. `sorted_evidence_ids`

```rust
pub fn finding_id(
    finding_type: &str,
    rule_content_sha256_list: &[&str],  // sort 済みであること
    sorted_event_ids: &[&str],          // sort 済みであること
    sorted_evidence_ids: &[&str],       // sort 済みであること
) -> String;
```

Merger は内部で sort してからこの関数へ渡します。UUID・乱数・実行時刻由来は禁止です。

## 7. 既存機能との関係

- **Phase 1 の `AttackMapping` 型を拡張**: `technique_id` と `technique_name` だけだったものへ `tactic` / `source` / `dataset_version` / `dataset_sha256` を追加。Phase 1 で作った `attack_mappings: vec![]` を使っているコードはそのまま動く（空 list なので新 field は影響しない）。
- **Phase 5 の3エンジンが生成する Match を入力とする**: Sigma Match の `logsource_mapping`、YARA-X Match の `matched_patterns`、Correlation Match の `score` と `ordered_event_ids` を観測事実（observed_evidence）へ展開する。
- **Phase 7 の Exporter と CLI が Finding を出力**: `tf-findings` が生成した Finding list を Case JSON・JSONL・Text・HTML 等の各形式へ出力する。ATT&CK dataset への path は CLI option から受け取る。

## 8. テストと品質ゲート

### テスト構成

- `tf-findings` 単体テスト: 43件
- `tf-findings` 統合テスト（`acceptance_tests.rs`）: 20件
- 合計: 63件の新規テスト
- workspace 全体: 1,130テスト合格（Phase 5 Correlation 編の 1,067 から +63）

### 品質ゲート

全て通過:

- `cargo fmt --all --check`: OK
- `cargo fmt --manifest-path fuzz/Cargo.toml --check`: OK
- `cargo clippy --all-targets -- -D warnings`: OK
- `cargo test`: 1,130 passed
- `cargo doc --no-deps`: warning 0
- `cargo deny check`: advisories/bans/licenses/sources 全て ok
- `cargo check --manifest-path fuzz/Cargo.toml`: OK
- `cargo bench --no-run`: OK

## 9. 次に学ぶべきこと

Phase 6 で Finding と ATT&CK mapping の library API が揃いました。次は **Phase 7 Exporter と CLI**（T7-001〜T7-034）です:

- **6種の Exporter**（Text / JSON / JSONL / CSV / HTML / Timesketch）へ Finding list を出力
- 出力安全性（CSV formula injection・HTML CSP・terminal ESC escape）の実装
- 9種の CLI command（`analyze` / `timeline` / `correlate` / `sigma` / `yara` / `export` / `rules` / `inspect` / `version`）
- ATT&CK dataset への path・version・source URL を受け取る CLI option
- Manifest 確定処理（全必須 field の集約）

Phase 6 の Finding merger と ATT&CK dataset API が、Phase 7 の CLI から直接呼び出される設計です。
