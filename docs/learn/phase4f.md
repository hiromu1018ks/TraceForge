# Phase 4 後半 学習ノート: Amcache Parser

> 対象読者: Phase 4 後半 Registry Parser（phase4e.md）を読み終えた人。Rust で `trait` / `Result` / `enum` / `match` / 再帰関数を一通り書けるレベル。

Phase 4 後半は残り2種の Parser を順次実装します。本ノートはその5つ目、**Amcache Parser** を解説します。`Amcache.hve` は Windows が program の実行痕跡・file metadata・device census 等を記録する registry hive で、フォレンジックでは「どの program が認識されていたか」「いつ頃から存在していたか」を調べる重要な証拠源です。ここでは **schema family 認識**・**観測型 Event**・**Registry Parser との明示的併用** という3つの新しい課題を扱います（互換 §4.6・§4.7）。

---

## 1. Amcache.hve とは何か

### 役割

Windows 7 以降、OS は program や file の実行・認識情報を `C:\Windows\AppCompat\Programs\Amcache.hve` という registry hive へ蓄積しています。主な用途:

- どの program がいつ頃認識されていたか（SHA-1・会社名・製品名・バージョン）
- application の install / 実行痕跡
- device census（OS 名・バージョン・ハードウェア構成）
- program shortcut 情報

フォレンジックでは「マルウェアの実行痕跡」「不正 program の持ち込み」「program の初回認識日時」等の調査へ使われます。

### Win10 22H2 / Win11 24H2 の Inventory schema

Windows 10 (1607) 以降、Amcache.hve の内部構造は **Inventory schema** と呼ばれる形式へ切り替わりました。root key（`Root`）の直下に次のような subkey が並びます:

| subkey 名 | 保持する情報 |
|---|---|
| `InventoryApplicationFile` | 個別 file 単位の metadata（SHA-1 hash・会社名・製品名・バージョン等） |
| `InventoryApplication` | application 単位の情報 |
| `InventoryApplicationShortcut` | application shortcut 情報 |
| `InventoryDevicePnp` | PnP device 情報 |
| `InventoryDeviceContainer` | device container 情報 |
| `DeviceCensus` | OS 名・バージョン・ハードウェア構成 |

Windows 10 22H2 と Windows 11 24H2 は共にこの Inventory schema family へ属します（細かな subkey の増減はありますが基本構造は同一）。本 Parser はこの2 build を Required 対応とします（互換 §4.6）。

### Windows 8 / 8.1 の legacy schema

Windows 8 / 8.1（と Windows 10 の初期 build の一部）は異なる構造を持ち、root 直下に `File` や `Programs` という subkey が置かれます。本 Parser はこれも認識対象としますが、Required ではありません（専用 fixture が必要・互換 §4.6 Optional）。

---

## 2. schema family 認識（T4-060）

Amcache Parser の第一の課題は「入力 hive がどの schema family か」を判定することです。本 Parser は **root key 直下の subkey 名前一覧** から判定します（`crates/parsers/src/amcache/schema.rs`）。

```rust
pub fn detect_schema_family(root_subkey_names: &[String]) -> SchemaFamily {
    let has = |indicators: &[&str]| -> bool {
        root_subkey_names.iter().any(|n| {
            let n_lower = n.to_ascii_lowercase();
            indicators.iter().any(|ind| n_lower == ind.to_ascii_lowercase())
        })
    };

    if has(WIN10_INVENTORY_INDICATORS) {
        SchemaFamily::Win10Inventory
    } else if has(WIN8_LEGACY_INDICATORS) {
        SchemaFamily::Win8Legacy
    } else {
        SchemaFamily::Unknown
    }
}
```

指標となる subkey 名は次の通り:

```rust
const WIN10_INVENTORY_INDICATORS: &[&str] = &[
    "InventoryApplicationFile",
    "InventoryApplication",
    "InventoryApplicationShortcut",
    "InventoryDevicePnp",
    "InventoryDeviceContainer",
    "DeviceCensus",
];

const WIN8_LEGACY_INDICATORS: &[&str] = &["File", "Programs"];
```

これらのどれか1つでも存在すれば、対応する family へ分類します。両方ある場合は新しい OS を信頼して Inventory family を優先します。

### case-insensitive 照合

実 Windows の key 名はほぼ全て ASCII で、大文字・小文字は仕様上 fixed ですが、本 Parser は case-insensitive で照合します（不正 hive への耐性）。`"inventoryapplicationfile"` や `"FILE"` のような細工にも同じように反応します。

---

## 3. なぜ「観測型 Event」なのか（規範 §7.1・互換 §4.6）

Amcache.hve への record の存在は「その program / file が当該 host 上で認識されていた」という観測であって、「実行された」「起動した」という直接観測ではありません。

具体例で考えると:

- **実行を意味しないケース**: file を copy しただけ・archive を展開しただけ・installer へ同梱されていただけ・network 経由で転送されただけ
- **実行を意味するケース**: user が明示的に起動した・scheduler が起動した・別 program から呼び出された

Amcache.hve の record だけでは、これらを区別できません。したがって本 Parser は [`AMCACHE_OBSERVATION_EVENT_TYPE`]（`amcache_observation`）のみを生成し、`process_start` / `program_launched` / `installed` 等の断定型 Event type は生成しません（規範 §7.1・互換 §4.6）。

実行を示す別 Evidence（EVTX Security 4688・Prefetch・UserAssist 等）との Correlation でのみ、実行 Finding を作成できます。

### interpretation_limitation 属性

互換 §5 は Amcache の必須 field として「interpretation limitation」を求めています。本 Parser は各 Event の属性 `amcache.interpretation_limitation` へ次の文字列を記録します:

```rust
const INTERPRETATION_LIMITATION: &str =
    "record existence only; not direct evidence of process start";
```

これで Correlation / Finding component が「この Event は観測のみで実行断定ではない」ことを機械的に判定できます。

---

## 4. なぜ「Generic Registry 自動 fallback 禁止」なのか（互換 §4.6・§4.7）

Amcache.hve は registry hive 形式そのものなので、Registry Parser（[`crate::registry::RegistryParser`]）でも解析できます。では「Amcache Parser が schema family を認識できなかった時、裏で自動的に Registry Parser へ fallback すればよいのでは？」と考えたくなりますが、**これは禁止** されています（互換 §4.6・§4.7）。

理由は2つ:

1. **暗黙の振る舞いは再現性を損なう**: 同一 Evidence を解析したのに schema 認識の成否によって生成される Event 群が変わると、利用者が解析結果を理解しにくくなります。
2. **Parser の責務を明確にする**: Amcache Parser は Amcache 専用、Registry Parser は汎用 hive 用。責務混合は保守性を下げます。

代わりに本 Parser は「未知 schema を検出したら Warning Issue を発して Event 生成を skip する」設計です:

```rust
if !schema_family.is_supported() {
    // 未知 schema: Warning Issue のみ。Generic Registry への自動 fallback 禁止（互換 §4.6）。
    sink.emit_issue(artifact_issue(
        UNSUPPORTED_VERSION_CODE,
        IssueSeverity::Warning,
        ...
        "未知 Amcache schema family のため解析を skip した（Generic Registry Parser \
         への自動 fallback は行わない・互換 §4.6・§4.7）。schema_family=unknown",
    ));
    return ParseSummary { status: ParseStatus::Skipped, ... };
}
```

### Registry Parser との明示的併用

Amcache.hve を汎用 registry として扱いたい場合は、利用者が **明示的に** Registry Parser を起動します。両 Parser は独立して動作し、それぞれ異なる Event 群（source = `amcache` / `registry`）を生成します:

- **Amcache Parser**: `amcache_observation` Event。schema family 認識付き。
- **Registry Parser**: `registry_key_last_write` / `registry_observation` Event。`registry.hive_type = amcache` 属性付き。

呼出側がどちら（または両方）を起動するかを選ぶのが「明示的併用」（互換 §4.7）。

---

## 5. hive 構造の再利用（registry::hive module）

Amcache.hve は registry hive 形式そのものです。本 Parser は [`crate::registry::hive`] module の cell parser を **そのまま再利用** します:

| 再利用要素 | 役割 |
|---|---|
| `parse_base_block` | base block (4096 byte) の parse |
| `HiveBins` | hive bins data への access |
| `HiveBins::parse_key_node` | nk cell（key node）の parse |
| `HiveBins::parse_key_value` | vk cell（key value）の parse |
| `HiveBins::subkey_offsets` | subkey list（lf/lh/li/ri）の展開 |
| `HiveBins::value_list_offsets` | value list（vk offset 配列）の展開 |
| `decode_utf16le_lossy` | UTF-16LE byte → String 復元 |
| `registry_value_type_name` | REG_* 型の人間可読名 |
| `BASE_BLOCK_BYTES` / `REGF_MAGIC` | 定数 |
| `MAX_KEY_DEPTH` / `MAX_KEYS` / `MAX_VALUES` | 上限制約 |

これらを `pub` で公開してあるため、`use crate::registry::hive::...` で取り込めばそのまま使えます。Rust の module system が「共通構造の再利用」をクリーンに行わせる良い例です。

なお、Registry Parser と異なり、本 Parser は **LOG1/LOG2 transaction log replay を行いません**。これは次の理由によります:

- LOG replay の完全実装は複雑（HvLE 形式等は Microsoft が公式仕様を公開していない）
- Amcache.hve の LOG は多くの場合空か極小
- 利用者が LOG replay も含めた完全解析を望む場合は Registry Parser 側を使える（明示的併用）

---

## 6. schema family 認識の実装

schema family を判定するためには、root key の subkey 名前一覧が必要です。本 Parser は次の順で処理します:

```rust
// 1. root nk cell を parse
let root_nk = bins.parse_key_node(header.root_cell_offset)?;

// 2. root の subkey 名前一覧を集める
let names = collect_root_subkey_names(&bins, &root_nk);

// 3. 名前一覧から schema family を判定
let schema_family = detect_schema_family(&names);

// 4. supported でなければ Warning で skip
if !schema_family.is_supported() { ... return Skipped; }

// 5. supported なら root から再帰的に Event 生成
walk_subtree(&bins, header.root_cell_offset, ...);
```

`collect_root_subkey_names` は root の subkey list を展開し、各 subkey の nk cell を parse して key_name を集めます:

```rust
fn collect_root_subkey_names(bins: &HiveBins, root_nk: &KeyNode) -> Option<Vec<String>> {
    let mut visited: HashSet<u32> = HashSet::new();
    let offsets = bins.subkey_offsets(root_nk.subkey_list_offset, &mut visited);
    let mut names = Vec::with_capacity(offsets.len());
    for off in offsets {
        match bins.parse_key_node(off) {
            Ok(nk) => names.push(nk.key_name.clone()),
            Err(_) => continue,  // 読めない subkey は schema 判定から外す
        }
    }
    Some(names)
}
```

注意点として、root subkey の parse が `collect_root_subkey_names` と `walk_subtree` の両方で発生します（2回 parse する）。これは schema family が未サポートの時に Event を1件も生成しないことを保証するためです。効率上の小さな無駄ですが、正確性を優先しました。

---

## 7. 観測型 Event の設計

各 key について、本 Parser は次の2種類の `amcache_observation` Event を生成します:

1. **key 自体の観測**: key が存在すること・last_write timestamp・subkey/value 数等
2. **各 value の観測**: value が存在すること・data 型・data 本体

両方とも同じ Event type `amcache_observation` です。key と value で別 Event type を分けないのは、Amcache では「その情報が観測された」という事実が本質で、key か value かは属性（`amcache.value_name` の有無等）で区別できるからです。

### Event 属性

各 Event は次の属性を持ちます（互換 §5 必須 field + 補助情報）:

| 属性名 | 内容 |
|---|---|
| `amcache.schema_family` | `win10-22h2-win11-24h2-inventory` / `win8-8.1-legacy` |
| `amcache.key_path` | full key path（例: `Root\InventoryApplicationFile\<sha1>`） |
| `amcache.key_name` | 当該 key の名前 |
| `amcache.value_name` | （value Event のみ）value 名 |
| `amcache.value_type` | （value Event のみ）REG_* 型の数値 |
| `amcache.value_type_name` | （value Event のみ）REG_SZ 等の人間可読名 |
| `amcache.value_data` | （value Event のみ）data 本体 |
| `amcache.is_file_metadata_key` | InventoryApplicationFile / InventoryApplication 配下なら `true` |
| `amcache.last_write_filetime` | 親 key の last_write (FILETIME) |
| `amcache.hive_major_version` / `amcache.hive_minor_version` | hive format version（通常 1.5） |
| `amcache.interpretation_limitation` | `"record existence only; not direct evidence of process start"` |
| `amcache.reference_spec` | `AMCACHE_REFERENCE` 定数 |
| `amcache.parser_version` | `PARSER_VERSION` 定数 |

### file metadata 判定

`InventoryApplicationFile` 配下の file entry key は SHA-1 hash のような長い文字列で、その配下に `CompanyName`・`FileName`・`FileVersion` 等の value を持ちます。これらは forensic 調査で特に重要なので、`amcache.is_file_metadata_key` 属性を `true` にして目印を付けます。

判定は key_path の中に `InventoryApplicationFile` または `InventoryApplication` という segment が含まれるかで行います（key 名前だけでなく path 全体を見る）:

```rust
pub fn is_file_metadata_path(key_path: &str) -> bool {
    key_path
        .split('\\')
        .any(is_inventory_file_metadata_key)
}
```

これで深い階層（`Root\InventoryApplicationFile\<sha1>`）の value でも正しく `true` になります。

---

## 8. 部分成功・決定性・Provenance 到達

### 部分成功（規範 §9.2・§21-5）

中間 cell の破損・空き cell・循環参照は Issue 化し、前後の正常 cell から継続します。これは Registry Parser と同じ設計です:

- depth 上限 (`MAX_KEY_DEPTH = 512`) へ到達 → `PARTIAL_RECORD_BOUNDARY` Issue + Partial
- key 数上限 (`MAX_KEYS = 2_000_000`) へ到達 → `PARTIAL_RECORD_BOUNDARY` Issue + Partial + Abort
- value 数上限 (`MAX_VALUES = 10_000_000`) へ到達 → `PARTIAL_RECORD_BOUNDARY` Issue + Partial
- 循環参照（訪問済み nk offset）→ 何もせず return（無限 loop 回避）
- nk / vk cell parse 失敗 → `MALFORMED_INPUT` Issue + Partial

境界を特定できない破損（base block 不正等）だけ `Skipped` へ倒します。

### 決定性

Event ID は [`Event::compute_id`]（規範 §12.3）で決定的に生成します。同じ入力なら常に同じ Event ID になります。これは:

- `provenance.source_ordinal`（walk 順の通し番号）が同じ
- `event_ordinal`（同一 record から複数 Event を生成する場合の番号）が同じ
- attributes が `BTreeMap`（key は UTF-8 byte 順・規範 §13.2）

だからです。acceptance test で「2回実行して同一 Event ID set」を検証しています（`amc_acceptance_12_4`）。

### Provenance 到達

各 Event の `provenance.record_locator` は `ByteRange { start, end }` で、hive bins data 先頭からの相対 offset + size です。これで利用者が元 cell へ直接 access できます（互換 §12-3）。

```rust
let record_locator = RecordLocator::ByteRange {
    start: nk.cell_offset as u64,
    end: nk.cell_offset as u64 + nk.cell_size as u64,
};
```

---

## 9. 合成 fixture と acceptance test

### 合成 hive fixture

本 Phase では実 Windows 環境の Amcache.hve を使わず、`tests/common/mod.rs` の `RegistryFixtureBuilder`（`RegistryKeySpec` / `RegistryValueSpec`）で **合成 hive** を構築します。Amcache.hve は registry hive 形式そのものなので、Registry Parser 用の fixture ビルダがそのまま使えます。

Win10 22H2 / Win11 24H2 Inventory schema を模した fixture（`standard_amcache_fixture`）:

```rust
common::RegistryKeySpec {
    name: "Root".to_string(),
    subkeys: vec![
        common::RegistryKeySpec {
            name: "InventoryApplicationFile".to_string(),
            subkeys: vec![
                common::RegistryKeySpec {
                    name: "000061e800b0c814fa2da1c8df6f48501bd43a4d78cd2151"
                        .to_string(),  // SHA-1 風 key 名
                    values: vec![
                        common::RegistryValueSpec::sz("CompanyName", "Microsoft Corporation"),
                        common::RegistryValueSpec::sz("FileName", "notepad.exe"),
                        common::RegistryValueSpec::sz("FileVersion", "10.0.22621.1"),
                    ],
                    ..
                },
                ..
            ],
            ..
        },
        common::RegistryKeySpec {
            name: "DeviceCensus".to_string(),
            values: vec![common::RegistryValueSpec::sz("OSName", "Windows 11 Pro")],
            ..
        },
    ],
    ..
}
```

この fixture は実 Windows の生成物ではないため、fixture 管理方針へは「合成（hand-crafted, MS-RRMF + Amcache Inventory schema 準拠）」として記録します。

### acceptance test（互換 §12）

`crates/parsers/tests/acceptance_tests.rs` へ Amcache 版の acceptance test 8条件を追加しました:

1. `amc_acceptance_12_1_valid_fixture_emits_expected_events`
2. `amc_acceptance_12_2_corrupt_inputs_do_not_panic`
3. `amc_acceptance_12_3_provenance_reaches_original_record`
4. `amc_acceptance_12_4_parser_is_deterministic_across_runs`
5. `amc_acceptance_12_5_fixture_metadata_recorded`
6. `amc_acceptance_12_6_reference_spec_revision_recorded`
7. `amc_acceptance_12_7_unknown_schema_emits_issue`
8. `amc_acceptance_12_8_event_type_does_not_overstate_observation`

加えて、縦割りテスト `amc_vertical_slice_amcache_to_case_jsonl` で「Amcache のみで analyze → Case JSONL + Manifest が生成される」ことを検証します（Phase 4 前半の LNK・Prefetch・USN・EVTX・Registry 縦割りと同じ経路）。

---

## 10. 既存 framework の再利用

本 Parser は Phase 4 前半で実装した framework をそのまま使います。新 trait や新 sink は作りません:

| 再利用要素 | 由来 |
|---|---|
| `ArtifactParser` trait | `framework.rs`（Phase 4 前半） |
| `ParseSink` trait | `framework.rs` |
| `ParseSummary` / `ParseStatus` | `framework.rs` |
| `ParseContext::make_provenance` | `framework.rs` |
| `EventStoreSink` | `sink.rs`（Parser → EventStore の結合） |
| `artifact_issue` / `record_issue` helper | `issue.rs`（規範 §9.3） |
| Issue code 定数（`UNSUPPORTED_VERSION_CODE` 等） | `issue.rs` |
| `filetime_to_datetime` | `lnk/filetime.rs`（Phase 4 前半） |
| `registry::hive::*` | `registry/hive.rs`（Phase 4 後半 Registry） |
| `RegistryFixtureBuilder` | `tests/common/mod.rs`（Phase 4 後半 Registry） |

このように、Phase 4 で積み上げた framework・既存 Parser の実装・テストヘルパがすべて再利用可能で、Amcache 固有の部分（schema 認識・観測型 Event・fallback 禁止）へ集中できる設計です。

### probe の設計

`ArtifactParser::probe` は Evidence が本 Parser の対象形式か識別します。本 Parser は次のように判定します:

```rust
fn probe(&self, evidence: &EvidenceItem) -> ProbeResult {
    // 1. VerifiedSnapshot 以外は対象外
    if evidence.integrity_status != IntegrityStatus::VerifiedSnapshot {
        return ProbeResult::NotThisFormat;
    }
    // 2. file 名が Amcache.hve（case-insensitive）でなければ対象外
    let name = ...;
    if !name.eq_ignore_ascii_case("Amcache.hve") {
        return ProbeResult::NotThisFormat;
    }
    // 3. 先頭 magic が regf なら Probable（Confirmed ではない）
    if buf == REGF_MAGIC {
        ProbeResult::Probable
    } else {
        ProbeResult::NotThisFormat
    }
}
```

`Confirmed` ではなく `Probable` にしているのは、registry hive 全般と重複するためです。呼出側が Registry Parser と使い分ける設計（明示的併用・互換 §4.7）を尊重しています。

---

## まとめ

Amcache Parser は3つの新しい課題を扱いました:

1. **schema family 認識**: Win10 22H2 / Win11 24H2 Inventory schema と Win 8/8.1 legacy schema を root subkey 名前から判定。未知は Warning Issue のみ。
2. **観測型 Event**: `amcache_observation` のみ生成。process start へは断定しない。`interpretation_limitation` 属性へ制約を明記。
3. **Generic Registry 自動 fallback 禁止**: 未知 schema でも Registry Parser へ逃さない。利用者が明示的に Registry Parser を起動する「明示的併用」で使い分ける。

既存の registry hive cell parser・framework・テストヘルパを再利用し、Amcache 固有の論理（schema・観測型・fallback 禁止）へ集中できました。次は **Jump Lists Parser**（互換 §4.5）で Phase 4 全 Parser の完成です。
