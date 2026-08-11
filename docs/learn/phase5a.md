# Phase 5 共通編 学習ノート: 検知エンジン基盤・Rule file 取扱（T5-001〜T5-003）

> 対象読者: Phase 4 共通検証（phase4h.md）を読み終えた人。Rust で `enum` / `trait` / `Result` / `BTreeMap` / `Path` を一通り使えるレベル。

Phase 4 が完了し、TraceForge は Windows の主要な forensic artifact 7種をすべて解析できるようになりました。次は Phase 5「検知エンジン」です。Event 群へ検知ルールを適用して脅威を発見します。

Phase 5 は Sigma・YARA-X・Correlation の3経路へ分かれていますが、本ノートはその**共通基盤**を解説します。各検知エンジンが前提とする「Rule file の1回読み込み」「directory 列挙の決定性」「validation error の Exit Code 5 区分」を実装します。これらは規範 §14・§17.2 が全検知エンジンへ課す要件です。

---

## 1. Phase 5 の位置づけと「共通編」の意味

### Phase 5 は何をするフェーズか

Phase 4 までで、Windows の証拠（Evidence）から Event を取り出せます。しかし「この Event の並びは不審なプロセス実行パターンだ」とか「この file は既知のマルウェア hash と一致する」といった**脅威判定**はまだできません。Phase 5 では、**ルール（Rule）**と呼ばれる条件記述を Event へ適用し、**Match**（一致）や **Finding**（脅威判定）を生成します。

3つの検知経路があります:

| 経路 | 形式 | 目的 |
|---|---|---|
| Sigma | YAML で書かれた汎用検知ルール | Windows Event Log 等へのルールベース検知（互換 §6） |
| YARA-X | YARA 形式の pattern match | file 内容への byte pattern 検知（互換 §7） |
| Correlation | TraceForge 独自の YAML 形式 | 複数 Event の時系列 pattern 検知（Schema §7） |

### 「共通編」とは

3経路は扱うルール形式が違いますが、**Rule file の取扱**については規範 §14 が**全経路へ共通する要件**を定めています:

- 1回だけ読み込む（再読込禁止）
- raw bytes の SHA-256 を計算する
- directory 列挙順は UTF-8 byte 順へ正規化する
- YAML anchor/alias/custom tag は禁止

これらを各 engine がバラバラに実装すると重複が発生し、不整合が生まれます。Phase 5 共通編では**1つの loader**へこれらを集約し、Sigma・YARA-X・Correlation すべてが同じ基盤を使うようにします。

本ノートで扱うタスクは3つ:

| タスク | 内容 | 対応仕様 |
|---|---|---|
| T5-001 | 1回読み込み・raw bytes SHA-256・再読込禁止 | 規範 §14 |
| T5-002 | directory 列挙順の正規化（UTF-8 byte 順） | 規範 §14 |
| T5-003 | validation error の Exit Code 5 区分 | 規範 §17.2 |

個別 engine（Sigma T5-010〜・YARA-X T5-020〜・Correlation T5-030〜）は後続フェーズで実装します。今回は**基盤**だけを作ります。

---

## 2. T5-001: 1回読み込み・raw bytes SHA-256・再読込禁止

### なぜ「1回だけ」なのか

規範 §14 は「Rule file を1回だけ bytes として読み込み、同じ bytes を parse または compile しなければならない。評価中に Rule file を再読込してはならない」とします。これには2つの理由があります:

1. **決定性（規範 §13）**: file を2回読み込むと、間に file が書き換えられた場合に1回目と2回目で異なる bytes になる可能性がある。これを防ぐため、読み込みは1回だけに制限する。
2. **性能**: 数万件の Rule file を何度も読み込むのは無駄。

### SHA-256 をどこで使うか

各 Rule file の raw bytes から SHA-256 を計算し、これを**Rule の一意識別子**として使います。具体的には:

- **Match ID**（`tf_core::id::match_id`）の hash field `rule_content_sha256` へ使う
- **Finding ID**（`tf_core::id::finding_id`）の `rule_content_sha256_list` へ使う
- **Manifest** の `rules` 一覧へ記録する
- **重複検出**（同じ内容の file が複数 directory にあっても1回だけ読み込む）の key に使う

つまり SHA-256 は「この Rule が何であるか」を一意に表す指紋のようなものです。

### `RuleRegistry`: 重複検出の中心

`RuleRegistry` は `BTreeMap<String, LoadedRuleFile>`（key が SHA-256）を持つ registry です。`BTreeMap` を使うことで:

- **重複検出**: 同じ SHA-256 が既にあるか O(log n) で判定できる
- **順序一定**: iteration 順が常に SHA-256 の byte 順（決定性）

```rust
#[derive(Default)]
pub struct RuleRegistry {
    by_sha256: BTreeMap<String, LoadedRuleFile>,
}

impl RuleRegistry {
    pub fn load(
        &mut self,
        path: &Path,
        root: &Path,
        options: &RuleLoadOptions,
    ) -> Result<Option<LoadedRuleFile>, RuleLoadError> {
        load_single(path, root, options, self)
    }
}
```

戻り値が `Result<Option<LoadedRuleFile>, ...>` となっているのがポイントです:

- `Ok(Some(loaded))`: 新規 file を読み込んだ
- `Ok(None)`: **同一 SHA-256 が既に存在し、再読込を skip した**（規範 §14）
- `Err(error)`: file 読込時の validation error

この3通りにより、「新規に読み込んだ」「重複で skip した」「error で中断」を呼出側が明確に区別できます。

### `LoadedRuleFile`: raw bytes を保持する

`LoadedRuleFile` は1つの Rule file の読込結果を表します:

```rust
#[derive(Clone, Debug)]
pub struct LoadedRuleFile {
    pub host_path: PathBuf,           // host 上の絶対 path（参照用）
    pub relative_path: String,        // root からの正規化相対 path（sort key）
    pub raw_bytes: Vec<u8>,           // 1回だけ読み込んだ bytes（規範 §14）
    pub sha256: String,               // raw bytes の SHA-256 lowercase hex
    pub size: u64,                    // raw bytes の size
}
```

各 engine は `raw_bytes()` accessor を通じて bytes を借り、Sigma なら YAML parser・YARA-X なら compiler・Correlation なら YAML parser へ渡します。これにより「同じ bytes を parse または compile する」という規範 §14 の要件を満たします。

### symlink を拒否する理由

規範 §2（安全プロファイル）は symlink を追跡しません。Rule file も同様で、`fs::symlink_metadata` で事前に symlink でないことを確認します:

```rust
let meta = fs::symlink_metadata(path)?;
if meta.is_symlink() {
    return Err(RuleLoadError::Symlink(path.to_path_buf()));
}
```

これは Rule file が symlink 先へ書き換えられることで解析結果が変化するのを防ぐためです（決定性の保証）。

---

## 3. T5-002: directory 列挙順の正規化（UTF-8 byte 順）

### OS の directory 順序は当てにならない

Windows の NTFS も Linux の ext4 も、`readdir` 等の directory 列挙は**順序を保証しません**。ファイルを作った順・ハッシュ表の格納順・タイミングによって結果が変わり得ます。

もし「`a.yml` を先に読む」「`z.yml` を先に読む」で Rule の登録順が変わると、Match ID の生成順や Manifest の出力順が環境依存になってしまいます。これは規範 §13（決定性）違反です。

### 解決策: 正規化相対 path で sort

規範 §14 は「Rule directory の列挙順は**正規化相対pathのUTF-8 byte順**とする」と定めます。つまり:

1. 各 file の root directory からの相対 path を計算する
2. `\` を `/` へ正規化する（Windows 対応）
3. その文字列の UTF-8 byte 列で辞書式 sort する

これを `discover_rule_directory` 関数が行います:

```rust
pub fn discover_rule_directory(
    input_root: &Path,
    options: &RuleDiscoveryOptions,
) -> Result<DiscoveryOutcome, RuleLoadError> {
    // ... symlink 検査 ...
    let mut outcome = DiscoveryOutcome::default();
    if root_meta.is_dir() {
        walk_directory(input_root, input_root, 0, options, &mut outcome)?;
    }
    // 規範 §14: 正規化相対 path の UTF-8 byte 順で sort。
    outcome.files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(outcome)
}
```

`sort_by` は安定 sort（`slice::sort_by`）です。`String::cmp` は UTF-8 byte 列の比較になります。これにより、どの OS でも同じ列挙順が保証されます。

### path 正規化の規則（`path_norm.rs`）

相対 path の正規化は `path_norm` module が担当します。Evidence の source_locator（規範 §5.2）と似た規則ですが、Rule file 用に必要最小限にしています:

1. `\` を `/` へ統一（Windows separator 対応）
2. `.` や `..` component を**拒否**（解決ではなく拒否・規範 §2 安全プロファイル）
3. 先頭 `/` や Windows drive letter は絶対 path として拒否
4. 連続 separator・先頭/末尾 separator は無視
5. 非 UTF-8 byte は `%XX`（大文字 hex）escape（規範 §5.2 準拠）
6. **大文字小文字は保持**（case-sensitive と case-insensitive 両方の filesystem で決定性を保つため）

```rust
pub fn normalize_rule_relative_path(relative: &str) -> Result<String, RulePathError> {
    if relative.is_empty() {
        return Err(RulePathError::Empty);
    }
    let unified = relative.replace('\\', "/");
    // 絶対 path 検査・`.`/`..` 検査...
    Ok(components.join("/"))
}
```

### なぜ source_locator（Phase 2）を再利用しないのか

Evidence 用の `normalize_source_locator`（`tf-evidence` crate）とほぼ同じ規則ですが、わざわざ別途実装しています。理由は2つ:

1. **依存関係の最小化**: `tf-engines` が `tf-evidence` へ依存すると、Evidence snapshot・probe framework 等の大量のコードが間接的に引き込まれる。Rule file の path 正規化のためだけにこれは過剰。
2. **関心の分離**: source_locator は Evidence 特有（NFC 正規化を含む）。Rule path は ASCII file 名が多く、規範 §14 は NFC を要求しない。別物として扱う方が仕様へ忠実。

将来的に共通化の必要性が高まれば `tf-core` へ抽出することも検討できますが、Phase 5 共通編では局所実装を選んでいます。

### 再帰走査の深度制限

Schema §8.2 は `max_recursion_depth` を既定 64 とします。Rule directory も同じ制限を適用します:

```rust
fn walk_directory(
    dir: &Path, root: &Path, depth: u64,
    options: &RuleDiscoveryOptions, outcome: &mut DiscoveryOutcome,
) -> Result<(), RuleLoadError> {
    if options.recursive && depth > options.max_recursion_depth {
        return Ok(());
    }
    // ... read_dir ...
}
```

root 直下は depth=0、subdirectory は depth=1、... と増え、`max_recursion_depth` を超えると打ち切ります。これは循環参照（symbolic link 等）による無限ループを防ぐ安全装置です。symlink 自体は事前に弾いていますが、防御的に二重の安全を確保しています。

---

## 4. T5-003: validation error の Exit Code 5 対応

### Exit Code の優先順位（規範 §17.2）

TraceForge の process 終了 code は規範 §17.2 で次のように定められています:

| Code | 意味 |
|---:|---|
| 0 | 完全成功。Warning・skip・limit 到達なし |
| 1 | Case は生成されたが Warning・partial・skip・limit 到達あり |
| 2 | CLI または設定 error |
| 3 | 入力 path または Evidence discovery error |
| 4 | 出力作成・安全検証・overwrite error |
| **5** | **Rule validation または strict rules error** |
| 6 | strict parser または strict limits error |
| 10 | TraceForge 内部 Fatal error または panic |

複数 error が同時に起きた場合は、**数字の大きさではなく** `10 > 6 > 5 > 4 > 3 > 2 > 1 > 0` の優先順位で最大のものを選びます（規範 §17.2）。これは Phase 1 の `ExitCode` enum が `merge` メソッドで実装済みです。

### なぜ Rule error を Exit Code 5 へ分けるのか

Parser の入力異常（Exit Code 1）や TraceForge 内部エラー（Exit Code 10）とは**区別**する必要があります:

- **Exit Code 1（Warning/skip）**: 「解析は完了したが、一部 skip した」等の**続行可能な問題**。ユーザーは結果を信用してよい。
- **Exit Code 5（Rule validation error）**: 「ユーザーが指定した Rule file が不正である」という**設定に起因する問題**。ユーザーは Rule を直すまで解析結果を信用すべきでない。
- **Exit Code 10（Fatal/panic）**: TraceForge 自体のバグ。開発者へ報告すべき。

Rule file が壊れている（YAML 文法エラー・Schema 違反・未対応機能を含む）のに Exit Code 1 で終わると、ユーザーは「解析は成功した」と誤解してしまいます。これを防ぐため、Rule 起因の問題は Exit Code 5 で明示します。

### strict rules mode の扱い

規範 §17.1 は `--strict rules` を定めます。strict rules mode では**1件でも Rule validation error があれば即時停止**し、Exit Code 5 で終わります。非 strict なら当該 Rule を skip して解析を継続し、Exit Code 1（Warning 寄与）となります。

これを `RuleLoadError::exit_code` メソッドが表現します:

```rust
impl RuleLoadError {
    pub fn exit_code(&self, strict_rules: bool) -> ExitCode {
        match self {
            // 入力 root の問題は strict に関わらず Exit Code 3。
            RuleLoadError::RootAccessFailed { .. }
            | RuleLoadError::RootIsSymlink(_) => ExitCode::InputOrDiscoveryError,
            // 個別 file の問題は strict なら 5、非 strict なら 1。
            _ => self.validation_exit_code(strict_rules),
        }
    }

    fn validation_exit_code(&self, strict_rules: bool) -> ExitCode {
        if strict_rules {
            ExitCode::RuleValidationOrStrictRulesError
        } else {
            ExitCode::CaseWithWarnings
        }
    }
}
```

「root directory が存在しない」等は CLI/input error（Exit Code 3）とします。これは strict mode に関わらず fatal です（Rule directory 自体が見つからないと処理が始まらないため）。

### `RuleLoadSummary`: error を蓄積して続行

実際の directory 読込では、1つの file が壊れていても他の正常 file の読込を続けたい場面がほとんどです。`RuleRegistry::load_directory` は個別 file の error を `summary.errors` へ蓄積し、処理を継続します:

```rust
pub struct RuleLoadSummary {
    pub loaded: Vec<LoadedRuleFile>,           // 新規に読み込んだ file
    pub skipped_duplicates: Vec<PathBuf>,      // 既読で skip
    pub symlink_skipped: Vec<PathBuf>,         // symlink で skip
    pub truncated: bool,                       // max_files 到達
    pub errors: Vec<RuleFileError>,            // 個別 file の error
    pub max_files_limit: Option<u64>,          // 到達した limit
}
```

呼出側は次のように strict と非 strict を切り替えます:

```rust
let summary = registry.load_directory(&rule_dir, &opts)?;
let exit_code = if strict_rules && !summary.errors.is_empty() {
    ExitCode::RuleValidationOrStrictRulesError  // Exit Code 5
} else if !summary.errors.is_empty() || !summary.symlink_skipped.is_empty() || summary.truncated {
    ExitCode::CaseWithWarnings                  // Exit Code 1
} else {
    ExitCode::Success                           // Exit Code 0
};
```

より精密には `ExitCode::merge` で全 error の exit_code を集約します:

```rust
let exit = summary.errors.iter().fold(ExitCode::Success, |acc, e| {
    acc.merge(e.error.exit_code(strict_rules))
});
```

これにより「strict なら1件でも 5 になったら 5」「非 strict なら全部 1 でも最悪値は 1」が正しく計算できます。

---

## 5. 実装の全体像

### ファイル構成

```
crates/engines/
├── Cargo.toml                # tf-core/sha2/hex/thiserror へ依存
├── src/
│   ├── lib.rs                # 公開 API の再公開
│   ├── path_norm.rs          # 相対 path 正規化（normalize_rule_relative_path 等）
│   └── loader.rs             # RuleRegistry・discover_rule_directory・RuleLoadError
└── tests/
    └── acceptance_tests.rs   # T5-001〜T5-003 の受け入れテスト13件
```

fuzz target も1件追加しました:

```
fuzz/
├── Cargo.toml                # tf-engines/tempfile 追加
└── fuzz_targets/
    └── rule_loader.rs        # Rule loader fuzz target（F-025）
```

### `tf-engines` の依存

最小限に抑えています:

| 依存 | 用途 |
|---|---|
| `tf-core` | `ExitCode`・`sha256_hex`・`Config`・`is_lowercase_sha256_hex` |
| `sha2` | SHA-256 計算（`tf-core` 経由でも使えるが明示依存） |
| `hex` | digest の lowercase hex 変換 |
| `thiserror` | Error 型 derive |
| `tempfile` (dev-only) | テスト用一時 directory |

外部の YAML parser・YARA-X crate は**共通編では未使用**です。Sigma（T5-010）・Correlation（T5-030）が YAML parser を、YARA-X（T5-020）が `yara-x` crate を個別に導入します。共通編は raw bytes 取得・hash 計算・path 正規化のみを提供します。

### 既存 crate との関係

```
tf-core (Phase 1)
   ↑
   └── tf-engines (Phase 5 共通編) ← NEW
```

`tf-engines` は `tf-core` のみへ依存します。`tf-evidence`（Evidence snapshot）・`tf-store`（EventStore）・`tf-parsers`（Parser 群）へは**依存しません**。これにより:

- Rule 読込は Evidence snapshot や Event store へ影響しない
- 依存関係がシンプルで cargo-deny・ビルド時間への影響も小さい
- 将来 Sigma・Correlation が Evidence ID を参照する場面でも、Registry へ問い合わせる形にできる

---

## 6. テスト戦略

### 単体テスト（44件）+ 受け入れテスト（13件）

`loader.rs` と `path_norm.rs` の末尾に単体テストを、`tests/acceptance_tests.rs` に end-to-end の受け入れテストを配置しています。主な検証項目:

**T5-001 関連:**
- `load_single_rule_file_computes_sha256`: raw bytes から SHA-256 が計算される
- `duplicate_sha256_not_reloaded_same_path`: 同一 file の2回目読込は skip
- `duplicate_sha256_not_reloaded_different_path`: 異なる path でも同一内容なら skip
- `file_size_limit_rejected`: `max_rule_file_size_bytes` 超過で拒否
- `symlink_rejected`: symlink は拒否（Unix skip・Windows は管理者権限不要のため省略）

**T5-002 関連:**
- `discover_directory_utf8_byte_order`: z/a/m の作成順でも a/m/z へ sort
- `discover_directory_utf8_byte_order_independent_of_creation_order`: 作成順に依存しない
- `discover_recursive_subdir`: subdirectory も含めて sort
- `discover_max_recursion_depth`: 深度制限が機能する
- `discover_max_files_limit_truncates`: file 数上限で打ち切り

**T5-003 関連:**
- `exit_code_strict_rules_returns_5_for_validation_error`: strict なら 5
- `exit_code_non_strict_returns_1_for_validation_error`: 非 strict なら 1
- `exit_code_input_error_for_root_problems`: root 问题是常に 3
- `exit_code_aggregation_via_merge`: 複数 error の優先順位集約
- `load_directory_continues_after_error`: error があっても処理継続

### Fuzz target（F-025）

`fuzz/fuzz_targets/rule_loader.rs` は libFuzzer が生成した任意 byte 列を一時 file へ書き出し、`RuleRegistry::load` へ投げます。これにより「破損内容・巨大 size・境界値入力で panic しない」ことを継続的 fuzzing で検証します（規範 §9.4: 最終安全網）。

実際の fuzz 実行は Linux CI のみで行います。Windows MSVC では libfuzzer-sys の link が失敗するため、本プロジェクトでは `cargo check --manifest-path fuzz/Cargo.toml` でビルド検証だけ行います。

### 受け入れテストの例

受け入れテストは、規範 §14・§17.2 の受け入れ条件を end-to-end で検証します:

```rust
#[test]
fn acceptance_t5_001_rule_file_is_read_once_and_sha256_computed() {
    let dir = make_tmpdir();
    let content = b"title: Acceptance\ndetection:\n  condition: selection\n";
    let path = write_file(dir.path(), "rule.yml", content);

    let mut registry = RuleRegistry::new();
    let loaded = registry.load(&path, dir.path(), &RuleLoadOptions::default())
        .expect("読込成功")
        .expect("新規 file なので読み込まれる");

    assert_eq!(loaded.raw_bytes(), content);
    assert_eq!(loaded.sha256, sha256_hex(content));
    assert!(is_lowercase_sha256_hex(&loaded.sha256));
}
```

このように「file を1回読み込み、raw bytes が保持され、SHA-256 が正しく計算される」ことを1つのテスト関数で検証します。

---

## 7. Sigma・YARA-X・Correlation 側から見た使い方

共通編が提供する基盤を、後続タスクの各 engine がどう使うか、**予行演習**として示します（実際の各 engine 実装は次フェーズ以降）。

### Sigma（T5-010〜）の場合

```rust
let mut registry = RuleRegistry::new();
let opts = RuleLoadOptions::from_config(&config);
let summary = registry.load_directory(&config.sigma.rule_dirs[0], &opts)?;

for rule_file in &summary.loaded {
    // raw bytes をそのまま YAML parser へ渡す（規範 §14: 同じ bytes を使う）
    let yaml: SigmaYaml = parse_yaml(rule_file.raw_bytes())?;
    let rule = validate_sigma_subset(&yaml)?;  // TF-SIGMA-1.0 subset 検証
    // rule_id と rule_file.sha256 を使って Match ID を生成
}
```

### YARA-X（T5-020〜）の場合

```rust
for rule_file in registry.iter() {
    // raw bytes を YARA-X compiler へ渡す（規範 §14: 同じ bytes を使う）
    let rules = yara_x::Compiler::new()
        .add_source(rule_file.raw_bytes())?;  // &str でなく &[u8]
    // rule_file.sha256 を Manifest へ記録
}
```

### Correlation（T5-030〜）の場合

```rust
for rule_file in registry.iter() {
    // raw bytes を YAML parser へ渡し、anchor/alias/custom tag を検出（規範 §14）
    let yaml = strict_yaml_parse(rule_file.raw_bytes())?;
    let rule: CorrelationRule = validate_correlation_schema(&yaml)?;
    // rule_file.sha256 を Match ID の hash field へ使う
}
```

いずれの engine でも、**`raw_bytes()` で借りた bytes を使う**こと・**`sha256` を ID や Manifest へ使う**こと・**registry が重複検出を担う**ことが共通します。共通編がこれを可能にします。

---

## 8. セルフレビューで修正したポイント

実装後のセルフレビューで次を見直しました:

1. **単一 file 入力時の relative_path 計算を簡素化**
   - 当初 `relative_path_key(input_root, input_root.parent())` と親 directory を基準にしていたが、単一 file 入力は「root 親 context がない」ため不自然だった
   - `file_name_or_fallback` で file 名を取り、`normalize_rule_relative_path` を通すだけへ簡素化
   - `tf-evidence` の `discover` 関数と同じ方針

2. **`LoadedRuleFile` を lib.rs から公開**
   - `RuleRegistry::iter()` の戻り値型や `RuleLoadSummary.loaded` の要素型として使われるため、利用側が import できるように
   - 併せて `MAX_RULE_FILES_LIMIT_CODE`（limit 到達時の Issue code）も公開

3. **fuzz target の依存追加**
   - `fuzz/Cargo.toml` へ `tf-engines = { path = "../crates/engines" }` と `tempfile = "3"` を追加
   - これにより libFuzzer が生成した bytes を RuleRegistry::load へ流せる

4. **テストの Windows 互換性**
   - symlink テストは `#[cfg(unix)]` で守り、Windows では代替パスへ
   - PowerShell 上の cargo でもテストが通ることを確認

---

## 9. 次のステップ（Phase 5 後続）

Phase 5 共通編が完了したので、次は個別 engine の実装です。推奨順序:

1. **Sigma（T5-010〜T5-017）**: YAML parser 導入・TF-SIGMA-1.0 subset evaluator・未対応構文の全体 skip（互換 §6）
2. **YARA-X（T5-020〜T5-027）**: `yara-x` crate pin・compile error 処理・3 mode（all/suspicious/explicit）
3. **Correlation（T5-030〜T5-042）**: YAML strict parser・Schema 検証・sequence 評価・score 計算

Sigma を最初に推奨する理由は、Correlation と同じ YAML parser を先に導入できるためです。Correlation は Sigma より複雑（sequence・partition_by・within・score 計算等）なので、Sigma で YAML と Rule file 取扱の流れを作ってから Correlation へ進むとスムーズです。

---

## 10. まとめ: Phase 5 共通編を終えて

- **`tf-engines` crate** を新依存追加なし（既存 workspace 依存のみ）で実装
- **`RuleRegistry`**: SHA-256 で重複検出し、規範 §14 の「1回読み込み・再読込禁止」を実現
- **`discover_rule_directory`**: filesystem 列挙順へ依存せず、UTF-8 byte 順で決定的に列挙
- **`RuleLoadError::exit_code`**: strict rules なら Exit Code 5・非 strict なら Exit Code 1・root 問題は常に 3 へ区分
- **44 単体テスト + 13 受け入れテスト + 1 fuzz target** で T5-001〜T5-003 を検証
- **Sigma・YARA-X・Correlation 全ての前提**となる基盤が完成

特に重要だったのは「決定性の徹底」です。SHA-256 による重複検出・UTF-8 byte 順の sort・BTreeMap による順序一定・非 symlink・単一読込、これらすべてが規範 §13（決定性）へ合致します。Phase 4 まで Event について徹底してきた決定性を、Phase 5 では Rule file についても同じ厳しさで保証しました。

次は Sigma から個別 engine の実装へ進みます。共通編で作った `RuleRegistry` に乗せて、各 engine が raw bytes を借りて parse・compile する形になります。
