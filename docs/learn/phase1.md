# Phase 1 学習ノート: TraceForge の「心臓」をつくる

> 対象読者: Rust で `enum` / `struct` / `trait` を一通り書けるレベルの初学者。Phase 0 を読み終えた人。

Phase 1 は **コアデータモデルと Schema** を実装するフェーズでした。いよいよ `tf-core` crate へ本格的なコードを書き、TraceForge 全機能の土台となる「型」を固定します。このノートでは、Phase 1 で何を作り、なぜそれが forensics ツールに必要なのかを解説します。

---

## 1. 「決定性」がすべて: 同じ入力は同じ結果

### forensics における決定性の意味

TraceForge は証拠分析ツールです。「同じ証拠を分析したら、いつ・誰が・どの環境で分析しても、**必ず同じ結果** が出る」必要があります。さもないと、法廷等で「この分析結果は信頼できるか」と問われたときに答えられません。

これを **決定性（determinism）** と呼びます（規範 §13）。Phase 1 のほとんどの設計は、この決定性を壊さないためにあります。

### 決定性を壊す「罠」と対策

| 罠 | なぜダメか | TraceForge の対策 |
|---|---|---|
| UUID や乱数で ID を作る | 毎回違う ID になる | SHA-256 で決定的生成（規範 §12） |
| `HashMap` を使う | iteration 順が不定 | `BTreeMap` で常に sort 済み（規範 §13.2） |
| thread 到着順で番号を振る | 並列実行で順序が変わる | 元 record の順序（`source_ordinal`）を使う |
| JSON の key 順がバラバラ | byte 比較で一致しない | canonical JSON で key を sort（Schema §2.1） |
| 不明時刻を UTC へ勝手に変換 | 情報が捏造される | `Unknown` のまま保持（規範 §6.2） |

Phase 1 で実装したモジュールは、すべてこの「決定性」を守るためのものです。

---

## 2. 決定的 ID: SHA-256 と length-prefixed encoding

### ID の形

TraceForge の ID は全て次の形です（規範 §12.1）。

```text
tf-<型>-v1:<64文字の小文字hex>
```

例: `tf-evidence-v1:e3b0c44298fc1c149afbf4c8996fb924...`

`<型>` は `case` / `evidence` / `artifact` / `event` / `match` / `finding` の6種類。後半の64文字は SHA-256 の hash 値（小文字 hex）です。

### なぜ UUID ではなく SHA-256 か

UUID（ universally unique identifier ）は「ほぼ確実に一意」ですが、**毎回違う値** になります。同じ証拠を2回分析すると、別の UUID が振られ、分析結果の比較ができません。

SHA-256 なら、**同じ入力からは必ず同じ hash** ができます。つまり「Evidence の中身が同じなら、Evidence ID も同じ」になります（規範 §12）。

### length-prefixed encoding: hash の入力を一意にする

ID を計算するとき、複数の field をつなげて hash に入れます。例えば Evidence ID は:

```text
TRACEFORGE-EVIDENCE-ID-V1 + source_locator + size + sha256
```

を hash に入れます（規範 §5.6）。しかし、単純に文字列を結合すると問題が起きます:

```text
("ab", "c") と ("a", "bc") がどちらも "abc" になる
```

これだと異なる入力が同じ hash になり、ID が衝突します。これを防ぐため、各 field の **長さ** を前につけます（規範 §12.2）。

```text
field = [4 byte の長さ][field の中身]
```

`("ab", "c")` なら `[2]"ab"[1]"c"`、`("a", "bc")` なら `[1]"a"[2]"bc"` になり、異なる byte 列になります。

これが **length-prefixed encoding** です。`crates/core/src/length_prefixed.rs` に実装しました。

```rust
let mut buf = LengthPrefixed::new();
buf.append_str("ab");  // [0,0,0,2] 'a' 'b'
buf.append_str("c");   // [0,0,0,1] 'c'
```

特殊ルール:
- **null**（値がない）は長さ `0xFFFFFFFF`。空文字列（長さ 0）と区別される。
- **整数** は10進数 ASCII へ変換してから length-prefix。`123` → `[3]"123"`。
- **list** は先頭に要素数をつける。

### ID 生成関数

`crates/core/src/id.rs` に6種類の ID 生成関数があります。例えば:

```rust
// Evidence ID（規範 §5.6）
let id = tf_core::id::evidence_id("Security.evtx", 1024, &sha256_hex_string);
```

各 ID の hash field 順序は仕様書で厳密に決まっていて、例えば Event ID は12個の field をこの順で連結します（規範 §12.3）。順序が違うと別の ID になるので、仕様書をそのまま実装しました。

> **初学者のポイント**: `message`（表示文）は Event ID の hash に含めません。これにより、「説明文を少し直しても Event ID は変わらない」=「同じ Event と扱える」ようになります。Parser の表示改善で ID が変わる事故を防ぐ設計です。

---

## 3. canonical JSON: byte 単位で一致させる

### 何が難しいか

JSON は便利ですが、そのままでは「同じデータ」でも byte 列が変わります:

```json
{"b": 1, "a": 2}   // key 順が違う
{"a": 2, "b": 1}
```

この2つは意味は同じですが、文字列として比較すると別物です。これだと「分析結果が一致するか」を byte 比較で確認できません。

### canonical JSON の規則（Schema §2.1）

TraceForge は次の規則で JSON を直列化します:

1. **object の key を UTF-8 byte 順で再帰 sort**
2. **number は NaN と Infinity を禁止**（有限値のみ）
3. **同じ値は常に同じ最短 decimal 表現**（`0.1` が `0.10000001` にならない）
4. **sequence の array は元順序を保持**（時系列等）
5. **set の array は sort してから**（tags 等）

`crates/core/src/canonical.rs` がこれを実装します。中身はシンプルで、一度 `serde_json::Value` へ変換し、object の key を `BTreeMap`（常に sort 済みの map）で詰め替えてから文字列化します。

```rust
pub fn to_canonical_string<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let value = serde_json::to_value(value)?;
    let canonical = canonicalize_value(&value)?;  // key を再帰 sort
    Ok(serde_json::to_string(&canonical)?)
}
```

float の最短表現は `serde_json` が内部で使う `ryu` アルゴリズムに任せます。`1.0` は `"1.0"`、`0.1` は `"0.1"` になります。

> **初学者のポイント**: 「golden test」（規範 §13.3）は、この canonical JSON のおかげで成り立ちます。同じ証拠を別環境で分析しても、canonical JSON が byte 一致することを自動 test で確認できます。

---

## 4. 時刻モデル: 「不明」を「不明」として扱う

### forensics 特有の厳しさ

一般のプログラムでは、時刻が不明なら「現在時刻」や `0`（1970年元旦）を入れることがあります。しかし forensics では **観測していない事実を捏造してはいけません**（規範 §6.2）。

- timestamp が記録されていない Event があった → `Unknown` として保持
- timezone が分からない local time があった → UTC へ勝手に変換しない
- DST で2通りに解釈できる時刻 → どちらかを選ばず、両方の情報を保持

これを実現するため、TraceForge は単一の `DateTime` ではなく、`EventTime` 型で時刻の「意味」を保持します（規範 §6.1）。

### TemporalValue の4種類

```rust
pub enum TemporalValue {
    UtcInstant { value: DateTime<Utc> },         // UTC と分かっている
    LocalTime { value: NaiveDateTime, timezone: Option<String> },  // local time
    Range { start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>> },  // 区間
    Unknown,  // 時刻不明
}
```

`UtcInstant` は「Artifact が UTC を明示した場合だけ」使います。`LocalTime` は timezone が `None`（不明）になり得ます。`Unknown` は「時刻を取得できなかった」場合で、現在時刻で補完しません（規範 §6.2）。

### DST（サマータイム）の罠

DST がある地域（例: ニューヨーク）では、年に2回トラブルがあります:

- **spring forward**: 時計が2:00 → 3:00 へ飛ぶ。`2:30` は存在しない時刻。
- **fall back**: 時計が3:00 → 2:00 へ戻る。`2:30` は2通りに解釈できる。

これを勝手に変換すると情報が消えます。`crates/core/src/time.rs` の `local_to_utc_outcome` は3種類の結果を返します:

```rust
pub enum LocalToUtcOutcome {
    Single(DateTime<Utc>),            // 一意に変換できた
    Ambiguous { first, second },      // 2通りに解釈できる
    NonExistent,                      // 存在しない時刻
}
```

呼び出し側は `NonExistent` なら Warning を出し、`Ambiguous` なら Range として保持します（規範 §6.2）。

> **初学者のポイント**: `chrono` と `chrono-tz` crate を使いました。`chrono` は Rust で時刻を扱う定番 crate で、`DateTime<Utc>`（UTC）と `NaiveDateTime`（timezone なし）という2つの型を提供します。`chrono-tz` は IANA timezone database（`Asia/Tokyo` 等）を扱います。

---

## 5. Windows path: `PathBuf` を使わない

### なぜ `PathBuf` がダメか

Rust の `PathBuf` は OS の path 区切り文字（Unix は `/`、Windows は `\`）へ依存します。TraceForge を Linux で動かすと、`PathBuf` は Evidence 内の Windows path（`C:\Users\...`）を Unix 流に解釈しようとし、path の比較が壊れます。

そこで Evidence 内に記録された Windows path には `PathBuf` を使わず、独自の `WindowsPathValue` 型を使います（規範 §8、AGENTS.md 禁止事項）。

### WindowsPathValue の構造

```rust
pub struct WindowsPathValue {
    pub original: String,           // 元表現そのまま
    pub comparison_key: Option<String>,  // 正規化済み比較鍵
    pub normalization_profile: String,   // "windows-path-v1"
    pub normalization_notes: Vec<String>, // 適用した規則の記録
}
```

`original` は絶対に変えません。`comparison_key` は比較用に正規化したものです。

### windows-path-v1 の6規則（規範 §8）

1. `/` を `\` へ変換
2. 重複 `\` を1つに（UNC 先頭 `\\` は保持）
3. drive letter を大文字へ（`c:` → `C:`）
4. 比較 key だけ Unicode case fold（小文字化）
5. `.` component を削除
6. root を越えない `..` を解決

重要なのは「環境変数展開・drive mapping・8.3 名展開はしない」こと。これらは文脈依存で、決定性を壊します。Case 固有の mapping が明示された場合だけ行います（Phase 6 以降）。

> **初学者のポイント**: 「`PathEquivalent`（path が同じファイルを指す可能性がある）」という概念も重要です（規範 §8）。path が一致しても「同じファイル」の証明にはなりません。あくまで「一致する可能性がある」扱いです。

---

## 6. Schema validator: 出力が仕様を満たすか機械的に検証

### なぜ Schema validator が要るか

TraceForge は JSON や JSONL で結果を出力します。その出力が「仕様書の形式」を満たしているか、人間が目視で確認するのは無理です。機械的に検証します。

Schema 仕様書は各レコード型（Event Time、Correlation Rule 等）の JSON Schema fragment を定義しています（Schema §4、§7）。これを `jsonschema` crate へ読み込ませて検証します。

```rust
// crates/core/src/schema.rs
let validator = tf_core::schema::event_time_validator();
let ok = validator.is_valid(&event_time_json);  // true / false
```

### fixture test（Schema §9）

「validator が正しく動くか」を確認するため、Schema §9 は9種類のテスト用データ（fixture）を要求します:

1. 最小 valid サンプル
2. 全 field 充填 valid サンプル
3. 必須 field 欠落（invalid）
4. 異なる major version（invalid）
5. 未知の enum 値（invalid）
6. 不明 timezone / range / unknown time
7. Manifest 欠落 JSONL（未完了）
8. 未対応 operator の Correlation Rule（invalid）
9. limit が 0 の Config（invalid）

これらを `tests/fixtures/schema/` へファイルで保存し、`tests/schema_fixtures.rs` で読み込んで検証します。Phase 1 の完了条件は「この9種が全部期待通りに通ること」でした。

> **初学者のポイント**: `jsonschema` crate は JSON Schema という標準規格を読み込んで検証するライブラリです。今回は `default-features = false` で余分な機能（HTTP 参照等）を切り、外部通信しない安全な構成にしました（規範 §2: 外部 network access なし）。

---

## 7. 設定と Exit Code: 安全な既定値と分かりやすい終了

### 設定の優先順位（Schema §8.1）

```text
CLI option > explicit config file > default config file > built-in defaults
```

Phase 1 では「built-in defaults」と「explicit config file（TOML）」を読むところまで実装しました。CLI option の parse は Phase 7 です。

重要なのは **安全な既定値**（規範 §2）:

- `snapshot_mode = "always"`（必ず snapshot を作る）
- `follow_symlinks = false`（symlink を追わない）
- `output.overwrite = false`（上書きしない）

これらは「利用者が気をつけなくても安全」な既定値です。`follow_symlinks = true` は v1.0 では validation error にします（Schema §8.3）。

### Exit Code の優先順位（規範 §17.2）

process が終了するときの code（0 = 成功、10 = Fatal 等）は、単なる数値の大きさではなく、決まった優先順位で選びます:

```text
10 > 6 > 5 > 4 > 3 > 2 > 1 > 0
```

複数の問題が同時に起きたら、この順で一番強いものを最終 Exit Code にします。例えば「Warning あり（1）」と「CLI error（2）」なら、CLI error の 2 になります。

`crates/core/src/error.rs` の `ExitCode::merge` がこれを実装します。

---

## 8. テスト方針: unit / property / fixture の3層

Phase 1 では3種類のテストを書きました。

### unit test（各モジュール内）

`#[cfg(test)] mod tests` で各モジュールの関数を直接テストします。例えば `id.rs` のテストは「同一入力で同一 ID が出る」「message を変えても Event ID が変わらない」等を検証します。

### property test（`tests/property_tests.rs`）

`proptest` crate を使い、**ランダムな入力で性質が成り立つか** を大量に検証します。例えば:

- 任意の文字列入力で、Evidence ID が常に決定的か
- 任意の path で、正規化を2回繰り返しても結果が変わらない（べき等）
- 任意の日時で、DST 変換が panic しない

property test は人間が思いつかない入力を自動生成するので、edge case の発見に強いです。

### fixture test（`tests/schema_fixtures.rs`）

Schema §9 の9種 fixture をファイルで保存し、validator へ読み込ませて期待結果を検証します。これは「仕様書が意図した通りに動くか」の最終確認です。

Phase 1 では合計 **122 個のテスト** が通ります（unit 105 + property 7 + fixture 10）。

---

## 9. 実装したモジュール一覧

`crates/core/src/` の構成:

| モジュール | 役割 | 対応タスク |
|---|---|---|
| `hash.rs` | SHA-256 lowercase hex | T1-002 |
| `length_prefixed.rs` | ID の hash 入力符号化 | T1-001 |
| `id.rs` | 決定的 ID 6 種生成 | T1-003〜008 |
| `canonical.rs` | canonical JSON | T1-050 |
| `time.rs` | EventTime / DST / IANA | T1-010〜016 |
| `path.rs` | WindowsPathValue / windows-path-v1 | T1-030〜032 |
| `event.rs` | Event / Provenance / RecordLocator | T1-020〜024 |
| `case.rs` | Case / Evidence / Artifact / Severity | T1-040〜041 |
| `issue.rs` | Issue 型 | T1-042 |
| `match_.rs` | Match 型 | T1-043 |
| `finding.rs` | Finding / Confidence | T1-044 |
| `manifest.rs` | Manifest 型 | T1-045 |
| `schema.rs` | JSON Schema validator | T1-051, T1-054 |
| `jsonl.rs` | Case JSON / JSONL envelope | T1-052〜053 |
| `config.rs` | TOML 設定 / validation | T1-060〜063 |
| `error.rs` | Error 階層 / Exit Code / strict mode | T1-070〜072 |

---

## 10. 検証結果: Phase 1 の完了条件

roadmap §5 が定める Phase 1 の完了条件:

- ✅ **Schema §9 の全 fixture test（9 種）が通る** — `tests/schema_fixtures.rs` で10件合格
- ✅ **ID・時刻・Windows path の unit / property test が通る** — 105 + 7 件合格

実際に確認したこと:

| 確認項目 | 結果 |
|---|---|
| `cargo fmt --all --check` | 合格 |
| `cargo clippy --all-targets -- -D warnings` | 警告ゼロ |
| `cargo test --workspace` | 122 件合格 |
| `cargo doc --no-deps` | ドキュメント生成成功 |
| `cargo deny check` | advisories / licenses / bans / sources 全て ok |
| `cargo bench --no-run` | criterion benchmark ビルド成功 |
| `cargo check --manifest-path fuzz/Cargo.toml` | fuzz target コンパイル成功 |

---

## 11. 次のフェーズ（Phase 2）で何が始まるか

Phase 2 は **Evidence パイプライン** です。Phase 1 で固定した型を使って、実際の証拠ファイルを扱う準備をします:

- **Discovery**: 入力 directory を決定的順序で列挙（規範 §5.3）
- **Snapshot**: 読み取り専用で証拠を private 領域へ複製しながら SHA-256 を計算（規範 §5.5）
- **Evidence ID 生成**: Phase 1 の `id::evidence_id` を使って、各証拠へ ID を振る
- **Artifact 識別**: 拡張子だけでなく magic / header で形式を判定（規範 §11）
- **入出力分離**: 出力先が入力と重複しないことを検証（規範 §5.4）

Phase 1 の「Evidence ID を決定的生成する関数」が、Phase 2 でついに実データへ適用されます。Phase 1 で型と ID 計算を固定したおかげで、Phase 2 は「証拠の集め方」に集中できます。

初学者の方へ: Phase 2 からはファイル I/O と並列処理が出てきます。`std::fs`、`std::io::Read`、`std::thread` 等に不安があれば、[The Rust Programming Language](https://doc.rust-lang.org/book/) の第12〜16章を眺めてから取り組むとよいでしょう。

---

## 12. まとめ: Phase 1 が終わって分かったこと

- **決定性は意識しないと壊れる** — `HashMap`、UUID、現在時刻参照、thread 到着順。すべて「便利だが決定性を壊す」罠。Phase 1 でこれらを排除する土台を作った。
- **「不明」を「不明」と扱う勇気** — 一般のプログラミングでは「不明なら適当に埋める」ことがあるが、forensics では許されない。`EventTime::Unknown`、`LocalTime { timezone: None }` はそのための型。
- **Schema validator は安全網** — 人間の目視に頼らず、機械的に仕様違反を検出できる。fixture test で validator 自体の健全性も担保する。
- **`PathBuf` 禁止は Rust らしい制約** — OS 抽象化の恩恵と代償。Evidence 内の Windows path は独自型で扱うことで、Linux で動かしても Windows の意味論を保てる。

次は Phase 2 で、この土台の上に証拠パイプラインを構築します。
