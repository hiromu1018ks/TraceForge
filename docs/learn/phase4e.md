# Phase 4 後半 学習ノート: Registry Parser

> 対象読者: Phase 4 後半 EVTX Parser（phase4d.md）を読み終えた人。Rust で `trait` / `Result` / `enum` / `match` / 再帰関数を一通り書けるレベル。

Phase 4 後半は残り3種の Parser を順次実装します。本ノートはその4つ目、**Registry Parser** を解説します。Windows Registry hive（`SYSTEM` / `SOFTWARE` / `SAM` / `SECURITY` / `NTUSER.DAT` / `UsrClass.dat` / `Amcache.hve`）は、永続化・利用履歴・設定などフォレンジックで欠かせない証拠源です。ここでは **hive の cell 木構造**・**LOG1/LOG2 transaction log による dual view**・**観測型 Event** という3つの新しい課題を扱います（互換 §4.7）。

---

## 1. Registry hive とは何か

### Windows Registry

Windows はシステム設定・アプリ設定・ユーザー設定・セキュリティ情報などを「Registry」という階層型データベースへ保存します。`regedit.exe` で見る `HKEY_LOCAL_MACHINE\SOFTWARE\...` のようなツリーがその全体像です。

フォレンジックでは次のような調査に Registry が使われます:

- いつシステムへインストールされたか（`SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate`）
- どの program が最近実行されたか（`NTUSER.DAT\...\UserAssist`）
- どの USB device が接続されたか（`SYSTEM\...\USB`）
- 自動起動設定（`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`）
- ユーザー毎の設定（`NTUSER.DAT`・`UsrClass.dat`）

### hive file

Registry の実体は disk 上の **hive file** です。主要な hive:

| file 名 | 対応 HKEY | 主な用途 |
|---|---|---|
| `SYSTEM` | HKEY_LOCAL_MACHINE\SYSTEM | service・device driver・boot 設定 |
| `SOFTWARE` | HKEY_LOCAL_MACHINE\SOFTWARE | software 設定・Windows 情報 |
| `SAM` | HKEY_LOCAL_MACHINE\SAM | local account 情報（secret 復号は対象外） |
| `SECURITY` | HKEY_LOCAL_MACHINE\SECURITY | policy・cached credential（同上） |
| `NTUSER.DAT` | HKEY_CURRENT_USER | user 毎の設定 |
| `UsrClass.dat` | HKEY_CLASSES_ROOT（user 毎） | shell association・COM 登録 |
| `Amcache.hve` | （独立） | program 実行履歴（Amcache Parser と併用、互換 §4.6・§4.7） |

本 Parser はこれらすべての hive 形式へ対応します（互換 §4.7 Required）。

---

## 2. hive file の構造

hive file は次の2階層から成ります:

```
┌─────────────────────────────┐
│ base block (4096 byte)      │  magic "regf"・root cell offset・hive bins size・checksum
├─────────────────────────────┤
│ hive bins data              │  複数の hbin bin + cell 群
│   ├── hbin 0 (通常 4096 byte)│  magic "hbin"・bin size
│   │   ├── cell 0            │  先頭4 byte = signed size（負 = 使用中）
│   │   ├── cell 1            │  cell の中身は種別（nk/vk/lf/...）へ
│   │   └── ...
│   ├── hbin 1
│   └── ...
└─────────────────────────────┘
```

`base block`（`regf` header）は hive 全体の metadata を持ちます。重要な field:

- `root_cell_offset`: ルート key（nk cell）の hive bins data 先頭からの相対 offset
- `hive_bins_data_size`: hive bins 領域の size
- `major_version` / `minor_version`: 通常 `1.3` または `1.5`
- `checksum`（offset 508）: 先頭 508 byte を 127 個の u32 LE へ分け、XOR を取った値

本 Parser は checksum を計算して保持しますが、不一致でも即 skip はせず partial 扱いで解析を継続します（破損 hive からも価値ある情報を取り出すため、規範 §9.2 部分成功）。

### cell の size field

各 cell の先頭4 byte は **signed i32** で size を表します:

- **負値**: 使用中 cell。絶対値が size（size field 自身を含むか含まないかは実装依存。本 Parser は含まない扱いで 4 を引く）。
- **正値**: 空き cell（free）。本 Parser は空き cell を無視します。

```rust
pub fn cell_size_at(&self, offset: u32) -> Option<u32> {
    let raw = i32::from_le_bytes(...);
    if raw >= 0 {
        return None;  // 空き cell
    }
    let abs = (-(raw as i64)) as u32;
    if abs < 4 { return None; }
    Some(abs - 4)
}
```

### 主な cell 種別

cell 本体の先頭2 byte が signature で、種別を識別します:

| signature | 種別 | 役割 |
|---|---|---|
| `nk` (0x6B6E) | key node |Registry key。名前・subkey list・value list・last-write timestamp を持つ |
| `vk` (0x764B) | key value | key の値。名前・データ型・データ本体を持つ |
| `lf` / `lh` | fast leaf / hash leaf | subkey の nk offset のリスト（hint 付き） |
| `li` | index leaf | subkey の nk offset のリスト（hint 無し） |
| `ri` | index root | 複数の subkey list（lf/lh/li/ri）を結合する |

value list と value count は nk が持ちますが、value list 自体は signature 無しで単なる `u32` 配列です。

---

## 3. 再帰的木走査

Registry は木構造なので、root から DFS（深さ優先探索）で走査します。本 Parser は各 nk cell へ到達するたびに:

1. **`registry_key_last_write` Event** を1件生成（key の timestamp 観測）
2. **value list** をたどり、各 vk cell から **`registry_observation` Event** を生成（value の存在観測）
3. **subkey list**（lf/lh/li/ri）を再帰的に展開し、各 subkey nk へ対して 1. へ戻る

```rust
fn walk_subtree(&self, bins, nk_offset, parent_path, depth, ...) {
    // depth 上限・key 数上限・循環参照検出
    if depth >= MAX_KEY_DEPTH { emit_issue(...); return Partial; }
    if *total_keys >= MAX_KEYS { emit_issue(...); return Partial+Abort; }
    if !visited_cells.insert(nk_offset) { return Ok; }  // 循環検出

    let nk = bins.parse_key_node(nk_offset)?;  // 失敗は record Issue 化
    let key_path = format!("{parent_path}\\{name}");

    sink.emit_event(build_key_last_write_event(...))?;

    for vk_offset in bins.value_list_offsets(...) {
        match bins.parse_key_value(vk_offset) {
            Ok(vk) => sink.emit_event(build_observation_event(...))?,
            Err(_) => { emit_issue(...); partial = true; }
        }
    }

    for child_offset in bins.subkey_offsets(...) {
        let result = self.walk_subtree(bins, child_offset, key_path, depth + 1, ...);
        if result.abort { return Partial+Abort; }
        if result.partial { partial = true; }
    }
}
```

### 循環参照・上限の防御

攻撃者が壊れた hive を用意すると、subkey list が自分自身や親を指すことがあります。このとき無限 loop へ陥らないよう、**訪問済み nk offset** と **subkey list offset** を `HashSet` で管理します（`hive.rs::collect_subkey_offsets`）。

また極端に深い木や広い木からの stack overflow・OOM を防ぐため、depth 上限（`MAX_KEY_DEPTH = 512`）・key 数上限（`MAX_KEYS = 2_000_000`）・value 数上限（`MAX_VALUES = 10_000_000`）を設けます。到達時は `PARTIAL_RECORD_BOUNDARY` Issue へ記録し、解析を打ち切ります（規範 §9.2 部分成功）。

---

## 4. 観測型 Event の設計（規範 §7.1・互換 §4.7）

Registry snapshot は「ある時点での状態記録」であって、操作の直接観測ではありません。したがって:

- **`registry_key_last_write`**: key の last-write timestamp（什么時にその key が最後に更新されたか）
- **`registry_observation`**: value が存在すること（名前・型・データ）

を **観測型 Event** として生成します。**`registry_set` / `registry_delete` は生成しません**（規範 §7.1: 「Registry snapshot の key 存在や last-write だけから RegistrySet または RegistryDelete を生成してはならない」、互換 §4.7）。

これはフォレンジック分析における誇張（overstatement）を防ぐためです。例えば `Run` key へ `evil.exe` があっても、それが「いつ設定されたか」は snapshot からは分かりません（直前の再起動で上書きされたかもしれない）。調査者は他の証拠（USN・Prefetch 等）と突き合わせて「設定された時刻」を推論します。

各 Event の `assertion` は `Observed`、`source` は `Registry` です。

### 必須 field（互換 §5）

互換 §5 は Registry Artifact の必須 field として **hive type・view・key path・value name/data・last-write・replay status** を定めます。これらは Event 属性へ記録します:

| 属性 | 例 | 内容 |
|---|---|---|
| `registry.hive_type` | `system` / `software` / ... | source_locator から推定 |
| `registry.view` | `base` / `recovered` | dual view のどちらから生成したか |
| `registry.key_path` | `ROOT\Sub` | ルートからの完全 key 名 |
| `registry.value_name` | `Count` | value 名（名前無し value は空文字） |
| `registry.value_data` | 42 / "alice" / hex | 型に応じて復元 |
| `registry.last_write_filetime` | `132548480000000000` | 生 FILETIME 値 |
| `registry.replay_status` | `none` / `success` / `failed-hvle` / ... | LOG replay の結果 |
| `registry.log1_sha256` / `registry.log2_sha256` | 64 桁 hex | LOG file の SHA-256（与えられた場合のみ） |

### hive type の推定

source_locator の末尾（file 名）から hive type を推定します:

```rust
fn detect_hive_type(source_locator: &str) -> HiveType {
    let name = source_locator.rsplit(['/', '\\']).next().unwrap_or("");
    if name.eq_ignore_ascii_case("system") { HiveType::System }
    else if name.eq_ignore_ascii_case("software") { HiveType::Software }
    // ...
}
```

`Amcache.hve` も Registry Parser の対象です（互換 §4.7: Amcache Parser と明示的併用可能）。自動 fallback はしません。

---

## 5. value data の型別復元

vk cell の value data は byte 列ですが、データ型（`data_type`）に応じて JSON value へ復元します（`value_data_to_json`）:

| data_type | JSON 表現 | 復元方法 |
|---|---|---|
| `REG_SZ` (1) | String | UTF-16LE → UTF-8 lossy |
| `REG_EXPAND_SZ` (2) | String | 同上 |
| `REG_DWORD` (4) | Number (u32) | little-endian 4 byte |
| `REG_DWORD_BIG_ENDIAN` (5) | Number (u32) | big-endian 4 byte |
| `REG_MULTI_SZ` (7) | Array<String> | UTF-16LE を NUL 区切りで分割 |
| `REG_QWORD` (11) | Number (u64) | little-endian 8 byte |
| `REG_BINARY` (3) その他 | String | SHA-256 hex（元 byte 列の指紋） |

`REG_BINARY` を直接 hex 文字列へすると巨大になりやすいので、本 Parser は SHA-256 へ hash して 64 桁 hex で記録します。元 byte 列が必要な場合は snapshot file から復元できます（Provenance が byte range を指すため）。

### inline data と外部 cell

vk cell の data が 4 byte 以下の場合、**inline** で格納されます（`data_size` の MSB を立て、`data_offset` field の 4 byte へ直接 pack）。それより大きい場合は別 cell を指します。

本 Parser は両方を透過的に扱います（`hive.rs::parse_key_value`）。inline 判定は `data_size_raw & 0x8000_0000 != 0`。

---

## 6. LOG1 / LOG2 transaction log と dual view（互換 §4.7）

### なぜ LOG があるのか

Windows は hive への書き込みを **transaction log**（`.LOG1`・`.LOG2`）へ記録してから hive へ反映します。電源断等で hive 本体への書き込みが中途半端になった場合、LOG を hive へ再適用（replay）することで一貫した状態へ復旧できます。

互換 §4.7 は次を Required として求めます:

- **base view**: hive 本体のみを解析した結果
- **recovered view**: base + LOG replay を適用した結果

両方を保存し、どちらの view から Event を生成したかを記録します。LOG が存在するのに replay できない場合（既知未対応形式・破損）は `partial` 扱いとし、完全解析と表明してはなりません。

### 本 Parser の対応範囲

実 Windows の LOG 形式は Microsoft が公式仕様を公開しておらず、`HvLE`（Windows Vista 以降）・`RC11` / `DLOG`（古い形式）等のリバースエンジニアリング成果に依存します。本 Parser は v1.0 では次の方針をとります:

| 形式 | 検出 | 完全 replay | 扱い |
|---|---|---|---|
| **合成 LOG（TFLOG）** | ✓ | ✓ | recovered view を構築 |
| **HvLE** | ✓ | − | `KnownUnsupported`・base のみ・partial |
| **RC11 / DLOG** | ✓ | − | 同上 |
| 不正・短すぎる | − | − | `Malformed`・base のみ・partial |

合成形式（`TFLOG`）は本 Parser が定義する最小形式で、テスト可能です:

```
magic "TFLOG\0\0\0" (8 byte)
sequence: u32 LE
entry_count: u32 LE
entries[entry_count]:
  target_offset: u32 LE
  data_length: u32 LE
  data: [u8; data_length]
```

replay は単純に base bytes の copy へ各 entry を上書きします。本 Parser はこれを「recovered view 構築の検証用」として使います。実 Windows LOG 形式の完全対応は将来の Phase または別 component へ委ねます。

### dual view の実装

`parse()` は次の流れで dual view を構築します:

```rust
fn parse(&self, snapshot, context, sink) -> ParseSummary {
    let base_bytes = read_all(snapshot)?;
    // LOG の hash を先に計算（各 Event 属性へ記録するため）
    let log1_hash = self.log1.as_ref().map(|b| parse_log(b).sha256_hex);
    let log2_hash = self.log2.as_ref().map(|b| parse_log(b).sha256_hex);

    // replay を先に判定
    let (recovered_bytes, replay_status) = match replay_logs(&base_bytes, ...) {
        Recovered { bytes, .. } => (Some(bytes), "success"),
        KnownUnsupported { .. } => (None, "failed-hvle"); emit_issue(...); partial = true,
        Malformed => (None, "failed-malformed"); emit_issue(...); partial = true,
        NoLog => (None, "none"),
    };

    let replay_meta = ReplayMeta { log1_hash, log2_hash, replay_status };

    // base view を走査（全 Event へ replay_meta を伝える）
    self.walk_and_emit(&base_bytes, "base", &replay_meta, ...)?;

    // recovered view を走査（成功時のみ）
    if let Some(rec_bytes) = recovered_bytes {
        self.walk_and_emit(&rec_bytes, "recovered", &replay_meta, ...)?;
    }
}
```

各 Event の属性へ `registry.replay_status`・`registry.log1_sha256`・`registry.log2_sha256`（完全 64 桁 hex）を記録します（互換 §4.7: 「replay の成否と使用 log hash を記録」）。

### 視点別の記録場所

| 情報 | 記録先 | 理由 |
|---|---|---|
| `view` (base / recovered) | `registry.view` 属性 | Event 単位で区別する必要があるため |
| `replay_status` | `registry.replay_status` 属性 | artifact 全体の状態だが、各 Event から分かるようにするため |
| LOG file の SHA-256 | `registry.log1_sha256` / `registry.log2_sha256` 属性 | artifact metadata だが、Manifest 拡張未対応のため |
| 失敗理由 | Issue（`UNSUPPORTED_VERSION` / `MALFORMED_INPUT`）| 人間が読む詳細メッセージ |

成功時は Issue を出しません（Warning severity で成功を報告するのは誤解を招くため）。失敗時は Issue へ完全 hash を含めて、どの LOG file へ対する失敗か追跡できるようにします。

---

## 7. 部分成功（規範 §9.2・§21-5）

Registry hive は1つの file に数千〜数百万の cell が含まれます。1つの cell が壊れていても、他の正常 cell からは Event を生成すべきです（規範 §9.2 部分成功）。

本 Parser が部分成功扱いするケース:

| ケース | 扱い | Issue |
|---|---|---|
| base block の magic 不一致 | `Skipped`・解析中止 | `MALFORMED_INPUT` |
| base block の checksum 不一致 | 解析継続・終了時 partial | （現状は警告なし・将来拡張） |
| snapshot が base block に満たない | `Skipped` | `TRUNCATED_RECORD` |
| root cell offset が範囲外 | partial | `MALFORMED_INPUT` |
| hive_bins_data_size が file 長に満たない | partial | `TRUNCATED_RECORD` |
| nk cell の parse 失敗 | partial・当該 cell は skip | `MALFORMED_INPUT` |
| vk cell の parse 失敗 | partial・当該 cell は skip | `MALFORMED_INPUT` |
| subkey list の一部が読めない | partial・読めた分だけ処理 | `TRUNCATED_RECORD` |
| key depth 上限到達 | partial・当該 subtree を打切 | `PARTIAL_RECORD_BOUNDARY` |
| key 数・value 数上限到達 | partial・全体を打切 | `PARTIAL_RECORD_BOUNDARY` |
| LOG replay 失敗 | partial・base view のみ | `UNSUPPORTED_VERSION` / `MALFORMED_INPUT` |

いずれのケースでも **panic しません**。すべての byte access は範囲チェックを行い、不正な size・offset は error へ変換されます（規範 §9.4 panic 境界）。

---

## 8. 合成 fixture と acceptance test

### 合成 hive fixture

実 Windows 環境から hive を採取するのは手間がかかります。本 Phase では `tests/common/mod.rs` の `RegistryFixtureBuilder` が hand-crafted な合成 hive を構築します:

```rust
let spec = RegistryKeySpec {
    name: "ROOT".to_string(),
    last_write_filetime: filetime_from_unix_offset(0),
    values: vec![RegistryValueSpec::dword("Count", 42)],
    subkeys: vec![RegistryKeySpec {
        name: "Sub".to_string(),
        values: vec![RegistryValueSpec::sz("User", "alice")],
        ..Default::default()
    }],
    ..Default::default()
};
let bytes = common::build_registry_fixture(&spec);
```

この builder は nk/vk/lf cell を直列化し、`regf` base block と checksum を付与します。実 Windows 環境の生成物ではないため、fixture 管理方針へは「合成（hand-crafted, MS-RRMF / libyal libregf 準拠）」として記録します（互換 §12-5）。

### 合成 LOG fixture

replay 可能な合成 LOG も構築できます（`build_registry_log_fixture`）:

```rust
let log_entry = common::registry_log_entry(target_offset, new_bytes);
let log_bytes = common::build_registry_log_fixture(&[log_entry]);
let parser = RegistryParser::new().with_log1(log_bytes);
```

### acceptance test 8条件（互換 §12）

`registry_tests.rs` と `acceptance_tests.rs` の `reg_acceptance_12_*` で、互換 §12 の8条件を Registry 版で検証します:

| 条件 | 検証内容 |
|---|---|
| §12-1 | root + subkey + 複数 value から5件の Event を生成 |
| §12-2 | truncated / base block のみ / magic 壊し / root offset 範囲外 で panic しない |
| §12-3 | Provenance の `record_locator` が nk/vk cell の byte range を指す |
| §12-4 | 同一入力で同一 Event ID（決定性） |
| §12-5 | fixture SHA-256 lowercase hex 64 桁 |
| §12-6 | `registry.reference_spec`・`registry.parser_version` を属性へ記録 |
| §12-7 | HvLE LOG を `UNSUPPORTED_VERSION` Issue へ記録（黙殺しない） |
| §12-8 | `registry_set` / `registry_delete` を生成せず、観測型 Event のみ |

加えて **dual view**（base 5 event + recovered 5 event = 10 event）・**Amcache.hve の hive type 推定**・**Registry 単体での縦割り（→ Case JSONL + Manifest）** も独立テストで検証します。

---

## 9. Event ID の一意性と dual view

base view と recovered view は同じ hive 構造を持ちます。root key の cell offset は両 view で同じです。すると record_locator が同じになり、Event ID が衝突しそうに見えます。

これを防ぐため、本 Parser は **`ordinal`（source_ordinal 兼 event_ordinal）を base と recovered で連番** にします:

```rust
let mut ordinal: u64 = 0;
// base walk（ordinal 0..N）
self.walk_and_emit(&base_bytes, "base", ..., &mut ordinal, ...)?;
// recovered walk（ordinal N..M・base の続き）
self.walk_and_emit(&rec_bytes, "recovered", ..., &mut ordinal, ...)?;
```

`ordinal` が異なれば Event ID（規範 §12.3）も異なります。テスト `base_and_recovered_events_have_distinct_ids` で重複無しを検証します。

---

## 10. 既存 framework の再利用

Phase 4 前半で作った framework をそのまま使います:

- `ArtifactParser` trait: `parser_id` / `parser_version` / `artifact_type` / `probe` / `parse`
- `ParseSink` trait: `emit_event` / `emit_issue`（Vec で返さない・規範 §9.1）
- `ParseSummary`: `status` / `records_seen` / `events_emitted` / `issues_emitted` / `bytes_consumed`
- `run_parser_catching_panic`: Parser 内の panic を Fatal issue へ変換（規範 §9.4）
- `record_issue` / `artifact_issue`: Issue の便利 helper。message は `sanitize_issue_message` で安全化
- 安定 Issue code 定数（`MALFORMED_INPUT_CODE` / `TRUNCATED_RECORD_CODE` / `UNSUPPORTED_VERSION_CODE` / ...）
- `EventStoreSink`: `EventStore` への適応

新しく依存 crate は追加しません（既存の `chrono`・`serde_json`・`thiserror` で足りました）。`tf_core::hash::sha256_hex` で LOG file の hash を計算します。

---

## まとめ

Phase 4 後半の Registry Parser で次を作りました:

- **hive 構造解析**（`registry/hive.rs`）: `regf` base block + `hbin` bin 群 + cell 群（nk/vk/lf/lh/li/ri）。checksum 計算・循環参照防止・depth/key/value 数上限。
- **LOG1/LOG2 replay**（`registry/log.rs`）: 合成 LOG（TFLOG）形式で完全 replay・HvLE/RC11/DLOG は既知未対応として Issue 化。replay 成否と完全 SHA-256 を各 Event 属性へ記録（互換 §4.7）。
- **dual view**（`registry/mod.rs`）: base view と recovered view の両方を走査。`registry.view` 属性で区別。ordinal は連番で Event ID の一意性を保証。
- **観測型 Event**（`registry_observation` / `registry_key_last_write`）: `registry_set` / `registry_delete` は生成しない（規範 §7.1・互換 §4.7）。
- **value data の型別復元**: REG_SZ / REG_DWORD / REG_QWORD / REG_MULTI_SZ / REG_BINARY を JSON value へ。inline data と外部 cell の両方を透過的に扱う。
- **合成 fixture + acceptance test**: hand-crafted な hive builder・LOG builder。互換 §12 の8条件を Registry 版で検証。縦割り（Registry → Case JSONL + Manifest）も確認。

Phase 4 前半で据えた framework（`ParseSink`・`ParseSummary`・panic 捕捉・`EventStoreSink`）が、木構造 Parser でも破綻せず動くことを確認しました。次のステップは残り2種（Amcache・Jump Lists）です。Amcache は schema family 認識と Registry Parser との明示的併用（自動 fallback 禁止）、Jump Lists は CFB container 解析と内包 LNK の Artifact 化という新しい課題があります。
