# Phase 5 Correlation 編: 複数 Event の時系列パターンを検知する

## 1. このフェーズで何を作ったか

Phase 5 共通編（T5-001〜T5-003）で `RuleRegistry` を、Sigma 編（T5-010〜T5-017）で Event 1件評価エンジンを、YARA-X 編（T5-020〜T5-027）でファイルバイトパターンスキャンエンジンを作りました。Phase 5 Correlation 編（T5-030〜T5-042）では3つ目の検知経路として **Correlation 評価エンジン**を実装しました。

Correlation とは「複数の Event が特定の順序・時間窓・同じ partition（host/user 等）で発生したとき、それを1つの不審な事象として検知する」仕組みです。例えば:

1. マルウェアの実行ファイルがファイルシステムへ作成された（`file_create`）
2. その直後に同じ path のプログラムが実行された（`program_execution`）

この2つの Event が5分以内・同一 host で発生したら「ユーザーがダウンロードしたファイルをすぐに実行した」可能性が高い、という検知ができます。Sigma では1件の Event しか評価できませんが、Correlation は Event 間の関係を評価できます。

3つの検知エンジンの違い:

| 観点 | Sigma | YARA-X | Correlation |
|---|---|---|---|
| 評価対象 | Event 1件 | Evidence file の byte 内容 | 複数 Event の時系列 |
| Rule 形式 | Sigma YAML | YARA 独自構文 | TraceForge Correlation YAML（Schema §7） |
| 主な評価要素 | logsource・selection・condition | byte pattern・meta | sequence・step・within・partition_by |
| Match 拡張 field | `logsource_mapping` | `matched_patterns` | `score`・`ordered_event_ids` |

Correlation は Phase 6 の Finding 統合で特に重要になります。検知の確からしさを score で表現でき、ATT&CK mapping・Evidence 参照を保持したまま人間が理解できる Finding へ変換できるためです。

## 2. 新しく作ったファイル

### Correlation engine（`crates/engines/src/correlation/`）

5つのモジュールで構成されています:

- `mod.rs`: 公開 API の再エクスポート
- `rule.rs`: Schema §7 の CorrelationRule 構造体・YAML parser・Schema validation（T5-030・T5-031）
- `predicate.rs`: 8種 predicate operator の評価器（T5-033・T5-038）
- `fieldresolver.rs`: `path.comparison_key` 等の dot path を Event から解決する helper
- `evaluator.rs`: sequence 評価・partition・within・score 計算・match 生成（T5-032・T5-034〜T5-042）

### 依存の追加

- ワークスペースの `Cargo.toml` へ `regex = "1"` を追加（predicate `regex` operator 用）
- `tf-engines/Cargo.toml` へ `chrono` と `regex` を追加

### Fuzz target（`fuzz/fuzz_targets/correlation.rs`）

破損した YAML・不正 Schema・巨大 sequence で panic しないことを継続的 fuzzing で検証します（F-025・規範 §9.4）。

### 統合テスト（`crates/engines/tests/correlation_tests.rs`）

T5-030〜T5-042 の受け入れ条件を end-to-end で検証します（計26テスト）。

## 3. 設計のポイント

### T5-030: YAML parser と Schema §7

Correlation Rule は Schema §7 の JSON Schema へ従う YAML です。Sigma 編で作った内蔵 YAML parser（`src/yaml/`）をそのまま使います。禁止要素（anchor/alias/tag/duplicate key/multi-doc/block scalar/tab）は YAML parser の時点で error になります。

Phase 5 Correlation 編で YAML parser を1箇所だけ拡張しました: **浮動小数の parse** です。Sigma subset は整数と文字列しか値にとらないため Float variant が不要でしたが、Correlation Rule の `score.base`（例: `0.75`）には float が必要です。`YamlValue::Float(f64)` を追加し、`parse_plain_scalar` で有限値の float を認識するようにしました。

```rust
// YAML parser 内の float 認識（parser.rs）
if let Ok(f) = s.parse::<f64>()
    && f.is_finite()
    && s.contains(['.', 'e', 'E'])
{
    return YamlValue::Float(f);
}
```

`is_finite()` で NaN・Infinity を弾きます（Schema §2 共通規則）。`.inf`/`.nan` 等は文字列として扱われ、後段の Schema validation で数値型が期待されていれば error になります。

### T5-031: Schema validation

`tf-core` が既に持っている `correlation_rule_validator()`（`crates/core/schemas/correlation-rule.schema.json` から compile される JSON Schema validator）へ、YAML 互換 data model へ変換した JSON 値を渡して検証します。Schema は次を検査します:

- 必須 field（`id`・`version`・`title`・`severity`・`sequence`・`within`・`partition_by`・`score`）
- `id` の pattern（`^TF-CORR-[0-9]{3,}$`）
- `severity` の enum（`informational/low/medium/high/critical`）
- `partition_by` の enum（`case_id/hostname/user`）と重複禁止
- `operator` の enum（8種のみ。`levenshtein` 等の未対応 operator は Schema 違反）
- predicate の `value`/`variable` 相互排他（`exists` は value/variable 持たない、他はどちらか一方）

YAML → `YamlValue` tree → `serde_json::Value`（`to_json()` method で変換）→ Schema validator、という流れです。YAML parser が既に duplicate key を検出しているため、JSON 変換で値が上書きされることはありません。

### T5-032: sequence / step / where / bind 評価器

sequence は時系列順に評価する step の list です。各 step は:

- `event_type`（必須）: Event の `event_type` field と一致する必要がある
- `source`（任意）: `ArtifactSource`（`evtx`・`prefetch` 等）と一致
- `assertion`（任意）: `observed` か `inferred` で filter
- `where`（任意）: predicate list。全て満たす必要がある（AND）
- `bind`（任意）: 変数名 → field path。この step で match した Event から値を取り出して変数へ束縛し、以後の step の `where` で `variable` 参照できる

評価アルゴリズムは **backtracking 探索**です:

1. 全 Event を `(timestamp, event_id)` の決定的順で sort する
2. 各 Event を開始候補として step 0 を試す
3. step i の条件を満たす次の Event を、今の Event より後の時刻から探す
4. 全 step を満たす組み合わせが見つかったら Match を生成
5. 最後まで探したら1つ前の step へ戻って次の候補を試す（backtrack）

同じ Evidence 事実を重複して加点しないよう、生成済みの `match_id`（`rule_id + sha256 + ordered_event_ids` から決定的生成）で重複を排除します。

### T5-033: 8種 predicate operator

Schema §7 が定める8種を実装しました:

| operator | 意味 | 例 |
|---|---|---|
| `eq` | 厳密等価（型・case sensitive flag も考慮） | `user eq alice` |
| `neq` | eq の否定 | `user neq root` |
| `contains` | 部分文字列一致 | `message contains "lsass"` |
| `starts_with` | 前方一致 | `path starts_with "C:\\Temp"` |
| `ends_with` | 後方一致 | `path ends_with ".exe"` |
| `regex` | 正規表現 match（`regex` crate 使用） | `user regex "^svc-[a-z]+$"` |
| `exists` | field が存在する | `process.pid exists` |
| `in` | list のいずれかと等価 | `event_id in [4624, 4625]` |

`case_sensitive` flag（既定 `false`）は文字列比較全般へ影響します。既定では Unicode simple case fold（`to_lowercase`）で比較します。

### T5-034: within の両端含む・max_correlation_window_seconds

`within` は sequence 全体の時間窓です。例えば `within: 5m` であれば、最初の Event から最後の Event までの時間差が5分（300,000 ms）以内である必要があります。

規範 §14.1 は「within の境界は両端を含む」と明記します。つまり丁度5分（300,000 ms）の差でも match します。実装は `delta_ms <= within_ms` という比較で表現されます。

Schema §8.3 は設定 `max_correlation_window_seconds`（既定86,400秒＝1日）を超える `within` を持つ Rule を validation error とします。例えば `within: 2d` の Rule は compile 時に `CorrelationError::WithinInvalid` を返します。これは巨大な時間窓が性能問題や誤検知を引き起こすのを防ぐためです。

### T5-035・T5-036: partition_by と hostname 不明時の扱い

`partition_by` は「同じ partition に属する Event 同士だけを match させる」ための指定です。例えば `partition_by: [hostname]` と書くと、hostname が同じ Event 同士でしか sequence を組み立てません。

規範 §14.1 は次を定めます:

- hostname が両方存在し同一 → same partition（match 可能）
- 一方だけ hostname 不明 → 既定で **非 match**（different partition）

これを実装するのが `events_in_same_partition` 関数です:

```rust
PartitionKey::Hostname => match (&a.hostname, &b.hostname) {
    (Some(x), Some(y)) => x == y,
    _ => false, // どちらかが None なら別 partition
},
```

hostname 不明のために sequence から除外された Event は `CorrelationEvaluationWarning::HostnameUnknown` 警告として記録され、呼出側が Manifest へ残せます。

### T5-037: 不確実時刻の扱い

規範 §6.4 は Correlation の時刻規則を定めます:

- 時間窓を使う Correlation は、比較可能な UTC instant 同士だけを既定で対象とする
- timezone 不明・Unknown・開区間 Range を rule が暗黙に match させてはならない
- Rule が不確実時刻を許可する場合、`allow_uncertain_time: true` と最大許容誤差（`max_uncertainty_ms`）を明記し、match reason へその事実を記録する

実装は「厳密に確実な時刻」を `is_time_strictly_certain()` で判定します:

- `TemporalValue::UtcInstant` で、`uncertainty_ms` が未設定または `max_uncertainty_ms` 以内 → 厳密に確実
- それ以外（LocalTime・Range・Unknown 等）→ 不確実

不確実 Event は:

- `allow_uncertain_time=false`（既定）→ sequence から除外し `UncertainTimeExcluded` 警告を記録
- `allow_uncertain_time=true` → sequence へ受け入れるが `UncertainTimeUsed` 警告を記録（match reason へも明記）

### T5-038: null・型の厳密比較

規範 §14.1 は「null は空文字列と等しくない」「型が違う値を暗黙変換しない」と定めます。

実装は `strict_eq_value(lhs, rhs, case_sensitive)` 関数で、2つの JSON 値を型厳密に比較します:

- `null` 同士は等しい。`null` と他の型は等しくない
- integer `5` と string `"5"` は等しくない（型が違う）
- integer `5` と float `5.0` は等しくない（JSON の表示形式が異なる）
- 文字列同士は `case_sensitive` flag を尊重（既定は `to_lowercase` で case fold）

これにより Rule 作者が意図しない暗黙の型変換で誤検知されるのを防ぎます。

### T5-039: 未対応 operator を含む Rule 全体 skip

Correlation Rule が Schema §7 の `operator` enum（8種）に無い値を含む場合、Schema validation が error を返し、Rule 全体が compile 失敗になります。本 engine は部分評価をせず、Schema 違反の Rule は一切評価しません（規範 §14.1・§15.1 と一貫）。

`CorrelationError::is_unsupported_skip()` で「未対応要素による skip」かを判定でき、呼出側は strict rules mode なら Exit Code 5・それ以外は Exit Code 1（Warning）へ寄与させます。

### T5-040: match 重複生成禁止・max_matches 打ち切り

同じ Rule・同じ順序付き Event ID list から複数の match を生成してはなりません（規範 §14.2）。これを担保するのが `match_id` の決定性です:

```rust
// crates/core/src/id.rs
pub fn match_id(rule_id: &str, rule_content_sha256: &str, ordered_event_ids: &[&str]) -> String {
    // rule_id + sha256 + ordered_event_ids を length-prefixed で連結して SHA-256
}
```

同じ `ordered_event_ids` からは同じ `match_id` が生成されます。engine は生成済みの `match_id` を `HashSet` で管理し、重複を検出したら新たな Match を追加しません。

`max_matches`（既定100,000・最大1,000,000）は1つの Rule あたりの Match 数上限です。到達した場合は探索を打ち切り、`CorrelationEvaluationResult.truncated=true` を返します。呼出側はこの flag を見て:

- strict rules mode でなければ Exit Code 1（CaseWithWarnings）
- strict rules mode なら Exit Code 5（RuleValidationOrStrictRulesError）

へ寄与させます。これは規範 §14.2 と §17.2 の要件です。

### T5-041: score 計算

各 Correlation Match は `score` を持ちます。score は Schema §7 の `score` block で定義されます:

```yaml
score:
  base: 0.75
  adjustments:
    - reason: Exact normalized path match
      value: 0.10
```

最終 score は `base + sum(adjustments.value)` を [0.0, 1.0] へ clamp したものです（`tf_core::finding::Score::total()` が計算）。

Level 変換は規範 §14.3 の固定閾値で行います:

```text
0.00 <= score < 0.50  → low
0.50 <= score < 0.80  → medium
0.80 <= score <= 1.00 → high
```

`tf_core::finding::ConfidenceLevel::from_score(score)` がこの変換を提供します。

### T5-042: 同一 Evidence 事実の二重加点防止

規範 §14.3 は「同一の Evidence 事実を異なる Artifact 表示から二重加点してはならない」と定めます。本 engine の設計は次の3点でこれを担保します:

1. **adjustments は Rule 宣言固定**: engine は独自の加点を行わず、Rule が明示した `adjustments` だけを適用する。Evidence 由来の動的加点ロジックを持たない。
2. **match_id 一意性**: 同一 `ordered_event_ids` からの複数 Match 生成を禁止（§14.2）。これにより同じ Event 群を複数 Match へ分けて加点することができない。
3. **event_ids と evidence_ids を分離**: Match の `event_ids` は sort 済み set 表現。同じ evidence_ids set を持つ Match は match_id で区別される。

結果として、同じ Evidence 事実に対する score の合計は常に単一の `base + adjustments` となります。

## 4. 複雑な判定の例

Schema §7 の冒頭にある Rule 例を考えます:

```yaml
id: TF-CORR-001
version: 1.0.0
title: Execution shortly after file creation
severity: high
partition_by: [case_id, hostname]
within: 5m
sequence:
  - event_type: file_create
    bind:
      file_path: path.comparison_key
  - event_type: program_execution
    where:
      - field: path.comparison_key
        operator: eq
        variable: file_path
score:
  base: 0.75
  adjustments:
    - reason: Exact normalized path match
      value: 0.10
```

この Rule を次の3 Event へ適用します:

| Event ID | event_type | timestamp | hostname | path.comparison_key |
|---|---|---|---|---|
| e1 | file_create | 10:00:00 | host-A | `c:\users\alice\dropper.exe` |
| e2 | program_execution | 10:01:30 | host-A | `c:\users\alice\dropper.exe` |
| e3 | program_execution | 10:30:00 | host-B | `c:\users\alice\dropper.exe` |

評価の流れ:

1. e1 が step 0（`file_create`）に match。bind で `file_path = "c:\users\alice\dropper.exe"` を記憶
2. e2 が step 1（`program_execution`）の候補。`path.comparison_key eq file_path` をチェック。一致する。10:00:00 〜 10:01:30 は5分以内（90秒）。hostname が host-A で同一。→ **Match 生成**
3. e3 も step 1 の候補だが、hostname が host-B で異なるため partition 違反。スキップ

結果: 1つの Match（`ordered_event_ids: [e1, e2]`）が生成される。score は `0.75 + 0.10 = 0.85` で clamp なし・level=high。

もし `e3` の hostname が host-A であっても、時刻差が30分で5分 window を超えるため、やはり match しません。

## 5. 既存機能との関係

### Sigma 編・YARA-X 編との一貫性

3つの検知 engine は全て Match 型（`tf_core::match::Match`）へ結果を出力します。Correlation の Match は:

- `match_type: correlation`
- `score: Some(Score)` （Sigma・YARA-X は None）
- `ordered_event_ids: Some(Vec<String>)` （Sigma・YARA-X は None）
- `logsource_mapping: None`（Sigma のみ）
- `matched_patterns: None`（YARA-X のみ）

これにより Phase 6 の Finding 統合は3経路を透過的に扱えます。

### 共通編 RuleRegistry の再利用

`CompiledCorrelationRule::compile(raw_bytes, sha256, max_window_seconds)` は `LoadedRuleFile::raw_bytes()` と `LoadedRuleFile::sha256` をそのまま受け取ります。共通編の `RuleRegistry::load_directory` で読み込んだ file を1回ずつ compile するだけでよく、Rule file の再読込は発生しません（規範 §14）。

### EventStore との関係

Correlation evaluator は `impl Iterator<Item = Event>` を受け取ります。EventStore が提供する決定的 iteration（timestamp group + event_id 順）をそのまま渡せば、thread 数によらず同一の評価結果が得られます（規範 §13）。本 engine は `tf-store` へ依存せず、`tf-core` の `Event` 型だけを知っています。

## 6. テストと品質ゲート

### テスト網羅

- `correlation/rule.rs` の unit test: T5-030・T5-031（YAML parse・Schema validation）
- `correlation/predicate.rs` の unit test: T5-033・T5-038（predicate operator・厳密比較）
- `correlation/fieldresolver.rs` の unit test: field path 解決
- `correlation/evaluator.rs` の unit test: T5-032・T5-034〜T5-042（sequence・partition・within・score・dedupe 等）
- `tests/correlation_tests.rs` の統合テスト: end-to-end の受け入れ条件（26テスト）

合計で本フェーズのテストは `tf-engines` に 60以上追加され、workspace 全体で 1,067 テストが通ります。

### 品質ゲート

次を全て実行し、通ることを確認しました:

- `cargo fmt --all --check`
- `cargo fmt --manifest-path fuzz/Cargo.toml --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`（workspace 全体）
- `cargo doc --no-deps`
- `cargo deny check`（license・advisory・bans・sources）
- `cargo check --manifest-path fuzz/Cargo.toml`
- `cargo bench --no-run`

### Fuzz target

`fuzz/fuzz_targets/correlation.rs` が破損入力で panic しないことを継続的 fuzzing で検証します。Windows MSVC 環境では libfuzzer-sys の link が失敗するため、本プロジェクトでは `cargo check` でビルド検証し、実際の fuzz 実行は Linux CI で行います。

## 7. 次に学ぶべきこと

Phase 5 はこれで完了です。3つの検知エンジン（Sigma・YARA-X・Correlation）が揃い、Phase 6 Finding 統合へ進める状態になりました。Phase 6 では:

- Correlation・Sigma・YARA-X の Match を人間が理解できる Finding へ統合する
- Finding merger が「同じ Event/Evidence を参照するという理由だけで自動統合しない」ことを保証する（規範 §16）
- 決定的 Finding ID（規範 §12.4）の生成
- ATT&CK dataset の pin と mapping 生成

これらを実装する中で、Correlation が持つ `score` と `ordered_event_ids` が Finding の confidence 計算へどう活用されるかを見ていきます。
