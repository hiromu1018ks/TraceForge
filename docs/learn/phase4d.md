# Phase 4 後半 学習ノート: EVTX Parser

> 対象読者: Phase 4 後半 USN Journal Parser（phase4c.md）を読み終えた人。Rust で `trait` / `Result` / `enum` / `match` を一通り書けるレベル。

Phase 4 後半は残り4種の Parser を順次実装します。本ノートはその3つ目、**EVTX Parser** を解説します。EVTX は Windows Vista 以降の event log 形式で、フォレンジックにおいて最も重要な証拠源の1つです。ここでは **binxml というバイナリ XML 形式の decoder** と **partial chunk recovery** という新しい課題を扱います。

---

## 1. EVTX とは何か

### Windows Event Log

Windows はシステム・セキュリティ・アプリケーションのイベントを「event log」として記録します。Windows Vista（2007年）以降、この形式が **EVTX** です。古い `.evt`（Windows XP まで）とは全く別の形式です（本 Parser は `.evt` を Unsupported とします、互換 §4.2）。

各 event は次のような XML 構造を持ちます:

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{...}"/>
    <EventID>4624</EventID>
    <Channel>Security</Channel>
    <Computer>WORKSTATION1</Computer>
    <TimeCreated SystemTime="2026-08-10T01:15:20Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>
```

フォレンジックでは「誰がいつログインしたか」「どのプロセスが起動したか」「サービスが作られたか」などを追跡するため、EVTX は最もよく使われる証拠です。

### なぜ binxml なのか

テキスト XML をそのまま file へ書くと size が肥大化します。Windows は event を **BinXml** と呼ばれるバイナリ表現へ圧縮して格納します。同じ文字列（Provider 名・Channel 名など）は hash table で共有され、テンプレート化された XML 構造に値を埋め込む形式で記録されます。

本 Parser は **純 Rust で binxml decoder を実装** します（外部依存 crate を増やさない、PROMPT.md 制約）。

---

## 2. EVTX file の3階層構造

EVTX file は次の3階層から成ります。

```
┌─────────────────────────────┐
│ file header (4096 byte)     │  magic "ElfFile\x00"・chunk_count・flags・CRC32
├─────────────────────────────┤
│ chunk 0 (65536 byte)        │  magic "ElfChnk\x00"・chunk header・records
│   ├── chunk header (512B)   │  record_id 範囲・free_space_offset・CRC32
│   └── records 領域           │  record0 + record1 + ...
├─────────────────────────────┤
│ chunk 1 (65536 byte)        │
├─────────────────────────────┤
│ ...                         │
└─────────────────────────────┘
```

各 record は次の構造です:

```
┌────────────────────────┐
│ magic 0x2a 0x2a (2B)    │
│ size (4B, i32 LE)       │  record 全体の byte 長（magic を含まない）
│ record_id (8B, u64 LE)  │  通番
│ timestamp (8B, FILETIME)│
│ binxml...               │  size - 24 byte
│ size copy (4B)          │  先頭 size と同じ値（整合性検証用）
└────────────────────────┘
```

本 Parser はこの3階層を **file header → chunk → record → binxml** の順に降りて解析します（`evtx/header.rs`・`evtx/chunk.rs`・`evtx/record.rs`・`evtx/binxml.rs`）。

---

## 3. CRC-32 による整合性検証

EVTX は各所へ CRC-32 checksum を持つ:

- file header（offset 124）: header 全体の CRC
- chunk header（offset 496 と 504）: chunk header の CRC（2個）
- chunk records（offset 52）: records 領域の CRC

本 Parser は `evtx/crc32.rs` で **IEEE 802.3 polynomial（0xEDB88320）の純 Rust 実装** を提供します。CRC は初回 `0xFFFFFFFF`・最終 XOR `0xFFFFFFFF` の標準アルゴリズムです:

```rust
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}
```

CRC が不一致でも解析を諦めません。Warning issue を発し、partial recovery を試みます（後述）。

---

## 4. partial recovery: 破損があっても前後の正常 record を救う

### 3つの破損パターン

EVTX は record-stream 型（USN と同じ枠組み）。破損が起きうる3箇所と対応:

| 破損箇所       | 対応                                                                  |
|---------------|----------------------------------------------------------------------|
| chunk magic   | その chunk を解析対象外へ。Warning を出して次 chunk へ進む           |
| chunk checksum| Warning を出しつつ、records の解析を試みる（chunk が部分的に壊れても record が生きている可能性があるため） |
| record 破損   | 当該 record を Issue 化し、次の record magic（0x2a2a）を探索して継続 |

最後の「次 record magic の探索」が本 Phase の新しい工夫です。USN Parser は `record_length` で次 record の境界が分かりましたが、EVTX では size が矛盾している record を skip するために **byte 列を走査して次の magic を探す** 必要があります（`find_next_record_magic`）。

### 生成済み Event は破棄しない

USN Parser と同じ設計: Event を1件ずつ `sink.emit_event()` へ流すため、後で壊れた record が見つかっても **それまでに流れた Event は残り続けます**（規範 §9.2）。これが sink 型 interface の価値です。

---

## 5. binxml decoder: token 列から XML tree へ

### binxml の基本構造

binxml は「token」と呼ばれる1 byte の識別子が並ぶバイナリ形式:

| token | 意味 |
|-------|------|
| 0x00  | EndOfStream |
| 0x01  | EndElement（`</tag>`） |
| 0x02  | CloseStartElement（`>`） |
| 0x03  | OpenStartElement（`<tag` の開始） |
| 0x04  | CloseEmptyElement（`/>`） |
| 0x05  | Value（text content） |
| 0x06  | Attribute（属性） |
| 0x0C  | TemplateInstance |
| 0x0D  | NormalSubstitution |
| 0x0E  | ConditionalSubstitution |
| 0x0F  | FragmentHeader |

要素名・属性名は **hash(4byte) + count(2byte) + UTF-16LE 文字列** の形で格納されます。値の型（string/int/filetime等）も1 byte で識別されます。

### template instance: XML 骨格 + 実行時値

XML の構造（どの要素にどの属性があるか）は同じ Provider + EventID ならほぼ共通です。binxml はこれを「template」として切り出し、各 record は template へ substitution（値）を埋め込む形をとります:

```
record binxml:
  FragmentHeader (0x0F 01 00)
  TemplateInstance (0x0C):
    version(1) template_id(4) definition_offset(4)
    [inline definition if offset==0]:
      next_offset(4) template_id(4) size(4)
      [token stream: XML 骨格 + 0x0D/0x0E substitution markers]
    num_substitutions(4)
    [substitution values...]
```

本 Parser は次のように処理します:

1. template 定義（token stream）を parse → XmlNode 木へ（`decode_template_instance`）
2. substitution 配列を読む
3. XmlNode 木の中の `Substitution` placeholder を実際の値で置換（`apply_substitutions`）
4. 木を walk して EventContent（event_id・provider・channel・computer・event_data）を抽出（`extract_event_content`）

### 値型の豊富さ

binxml の Value は型付きで、文字列だけではありません:

| type | 意味 |
|------|------|
| 0x01 | StringType（UTF-16LE） |
| 0x07 | Int32Type |
| 0x0d | BoolType |
| 0x11 | FileTimeType（u64 FILETIME） |
| 0x14 | WStringType（UTF-16LE） |
| 0x0f | GuidType（16 byte Windows GUID） |
| 0x13 | SidType（可変長 SID） |

本 Parser は主要な型を取り出し、EventData 値として型情報を保持します（`EventDataValue` enum）。文字列化もできるため、`evtx.event_data.<name>` 属性へは文字列表現で格納します。

---

## 6. typed mapping: Event ID 単独では断定しない

### 5種の typed event

互換 §4.2 は最低限の typed mapping を定める:

| Event ID | Channel / Provider                                | event type      |
|---------:|---------------------------------------------------|-----------------|
|     4624 | Security / Microsoft-Windows-Security-Auditing    | `login`         |
|     4625 | Security / Microsoft-Windows-Security-Auditing    | `login_failure` |
|     4688 | Security / Microsoft-Windows-Security-Auditing    | `process_start` |
|     4689 | Security / Microsoft-Windows-Security-Auditing    | `process_stop`  |
|     7045 | System   / Service Control Manager                | `service_create`|

### 3条件の同時検証（必須）

> 「Event ID だけで mapping してはならない。channel・provider・required field を同時に検証する」（互換 §4.2）

なぜ Event ID だけではダメなのでしょうか？ 理由は2つ:

1. **同じ EventID が別 Provider で使われる**: 例えば EventID=1 は多くの Provider が使います。Sysmon の 1 は process create ですが、別 Provider の 1 は別意味です。
2. **改ざん耐性**: ログの改ざんや誤設定で channel が書き換えられている可能性があります。必須 field の検証まで含めることで、偽造 event を typed mapping へ誘導しにくくします。

本 Parser は `mapping.rs` で次の3条件を **すべて** 満たすときだけ typed event type を返します:

```rust
pub fn map_event_type(content: &EventContent) -> &'static str {
    let event_id = content.event_id?;          // 条件1: Event ID が既知
    let channel = content.channel?;
    let provider = content.provider_name?;
    // 4624/4625/4688/4689: Security + MS-Windows-Security-Auditing
    if matches!(event_id, 4624 | 4625 | 4688 | 4689) {
        if !eq_ascii_ci(channel, "Security") { return EVENT_LOGGED_TYPE; }       // 条件2
        if !eq_ascii_ci(provider, "Microsoft-Windows-Security-Auditing") {
            return EVENT_LOGGED_TYPE;
        }
        if !has_required_security_fields(event_id, content) {                    // 条件3
            return EVENT_LOGGED_TYPE;
        }
        return match event_id { 4624 => LOGIN_TYPE, /* ... */ };
    }
    EVENT_LOGGED_TYPE  // 検証失敗時は汎用 event_logged へ戻す
}
```

### PowerShell / Sysmon Operational は汎用へ

互換 §4.2 は PowerShell Operational・Sysmon Operational の対応を Required として定めますが、これらは typed mapping しません。channel + raw field を保持しつつ、汎用 [`EVENT_LOGGED_TYPE`]（`event_logged`）を生成します。後段の Correlation で型付けする余地を残すためです。

---

## 7. Provenance と「元レコードへ到達できる」

USN と同じ設計: 各 Event の `record_locator` へ **record 先頭からの byte range** を設定します（`RecordLocator::ByteRange { start, end }`）。byte range は file 全体での絶対 offset で、file header (4096) + chunk_index * 65536 + records 領域内 offset で計算されます:

```rust
let record_offset_in_file =
    chunk_offset_in_file + CHUNK_RECORDS_OFFSET as u64 + offset as u64;
let record_locator = RecordLocator::ByteRange {
    start: record_offset_in_file,
    end: record_offset_in_file + 2 + header.size as u64,
};
```

これにより Timeline 上の Event から「snapshot のこの byte 位置」へ正確に辿れます。解析者が「なぜこの Event が生成されたのか」を検証するとき、snapshot の該当 offset を hex dump して確認できます。

---

## 8. 合成 fixture と acceptance test

### binxml も自前で構築

本 Phase の fixture は **file header → chunk → record → binxml** の全階層を hand-craft します（`tests/common/mod.rs`）。binxml もテスト用 builder（`BinXmlBuilder`）で構築:

```rust
let mut builder = BinXmlBuilder::new();
builder.start_event(&EventContentSpec {
    provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
    event_id: 4624,
    channel: "Security".to_string(),
    computer: "WS1".to_string(),
    event_data: vec![ev_data("TargetUserName", "alice")],
    ...
});
let binxml = builder.finish();
```

この builder は **literal-only**（substitution を使わない）形式で binxml を生成します。実 Windows 環境の EVTX は substitution を使うのが普通ですが、本 Phase の検証（decoder 正確性・typed mapping・partial recovery）には literal-only で十分です。

### acceptance test 8条件（互換 §12）

`evtx_tests.rs` と `acceptance_tests.rs` の `evtx_acceptance_12_*` で、互換 §12 の8条件を EVTX 版で検証します:

| 条件 | 検証内容 |
|---|---|
| §12-1 | 5種の typed event + PowerShell/Sysmon の generic event 計7件を生成 |
| §12-2 | truncated / bad magic / 短すぎる file で panic しない |
| §12-3 | Provenance の `record_locator` が元 record の byte range を指す |
| §12-4 | 同一入力で同一 Event ID（決定性） |
| §12-5 | fixture SHA-256 lowercase hex 64 桁 |
| §12-6 | `evtx.reference_spec`・`evtx.parser_version` を属性へ記録 |
| §12-7 | Legacy .evt を `UNSUPPORTED_VERSION` Issue へ記録（黙殺しない） |
| §12-8 | assertion は Observed。channel + provider 検証を経ない typed mapping はない |

加えて **3 OS 世代** (Win7/Win10/Win11 相当の computer 名) と **4 channel** (Security/System/PowerShell Operational/Sysmon Operational) の組み合わせを独立テストで検証します。

### EVTX 単体でも縦割りが通る

LNK・Prefetch・USN と同じ経路が EVTX でも通ります（`evtx_vertical_slice_evtx_to_case_jsonl`）。EVTX Parser が生成した Event が EventStore へ蓄積され、Timeline 順へ整列し、Case JSONL + Manifest へ出力されるまでを1関数で完結させます。

---

## 9. Legacy .evt を弾く

Windows XP までの `.evt` は EVTX とは別形式です。本 Parser は file 先頭 4 byte を見て、Legacy `.evt` の magic（`LfLe`）なら **Unsupported** として `TF-W-PARSER-UNSUPPORTED-VERSION` Issue へ記録します（互換 §4.2・§12-7: 黙って無視しない）。

```rust
fn probe(&self, evidence: &EvidenceItem) -> ProbeResult {
    // ...
    if buf == EVTX_FILE_MAGIC {
        return ProbeResult::Confirmed;
    }
    if buf[0..4] == [0x4c, 0x66, 0x4c, 0x65] {
        // Legacy .evt magic（"LfLe"）
        return ProbeResult::NotThisFormat;
    }
    ProbeResult::NotThisFormat
}
```

parse 時にも file header の magic 検証で `MagicMismatch` error へ分岐し、同じ Unsupported Issue を発します。

---

## 10. 必須 field 欠落は Event 化せず Issue 化

互換 §5 は EVTX の必須 field として **provider・channel・record ID・Event ID・computer・event time・raw data** を定めます。本 Parser はこれらが欠けている record を Event 化せず、Issue 化します（`MISSING_REQUIRED_FIELD_CODE`）:

```rust
fn build_event(parsed: &ParsedRecord, ...) -> Option<Event> {
    if parsed.header.event_record_id == 0 { return None; }
    if parsed.header.timestamp_filetime == 0 { return None; }
    let event_id = parsed.content.event_id?;
    let provider = parsed.content.provider_name.as_deref()?;
    let channel = parsed.content.channel.as_deref()?;
    // ... Event 構築
}
```

呼出側で `None` を受けたら `MISSING_REQUIRED_FIELD` Issue を発行します:

```rust
if let Some(event) = build_event(...) {
    sink.emit_event(event)?;
} else {
    sink.emit_issue(record_issue(
        MISSING_REQUIRED_FIELD_CODE,
        IssueSeverity::Warning,
        ...,
        "EVTX record の必須 field 欠落のため Event 化せず",
    ))?;
}
```

「Field が無いから record ごと捨てる」のではなく、「何が欠けていたか」を記録に残すことで、解析者は欠落の有無を知ることができます（規範 §9.3: 安定 code・黙殺禁止）。

---

## まとめ

Phase 4 後半の EVTX Parser で次を作りました:

- **3階層構造の解析**（`evtx/`）: file header (4096B) → chunk (65536B) → record → binxml。
- **CRC-32 実装**（`crc32.rs`）: 純 Rust・外部依存追加なし。file/chunk/records の各 checksum 検証。
- **binxml decoder**（`binxml.rs`）: 純 Rust で token stream から XML tree を構築。template instance・substitution・主要な値型（String/Int/FileTime/Guid/SID 等）を扱う。
- **typed mapping 5種**（`mapping.rs`）: 4624/4625/4688/4689/7045。Event ID 単独ではなく channel + provider + 必須 field を同時検証。検証失敗時は汎用 `event_logged` へ戻す（規範 §7.1）。
- **partial recovery**（`mod.rs`）: chunk magic 不一致・checksum 不一致・record 破損のいずれでも Warning を発しつつ可能な限り継続。record 破損時は次 magic を探索。
- **Legacy .evt を弾く**（互換 §4.2）: Unsupported 扱い・Issue へ記録。
- **合成 fixture + acceptance test**: binxml も含めて hand-craft。互換 §12 の8条件を EVTX 版で検証。3 OS 世代・4 channel を網羅。縦割り（EVTX → Case JSONL + Manifest）も確認。

Phase 4 前半で据えた framework（`ParseSink`・`ParseSummary`・panic 捕捉・`EventStoreSink`）が、複雑な binxml decoder を載せても破綻せず動くことを確認しました。次のステップは残り3種（Registry・Amcache・Jump Lists）です。Registry は hive 構造と LOG1/LOG2 replay、dual view という新しい課題があります。
