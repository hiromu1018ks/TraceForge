# Phase 4 学習ノート: Parser framework と LNK Parser

> 対象読者: Rust で `trait` / `Result` / `Iterator` / `enum` を一通り書けるレベルの初学者。Phase 3 を読み終えた人。

Phase 4 は **Parser 群** を実装するフェーズです。Windows フォレンジックで集めた証拠ファイル（LNK・Prefetch・EVTX 等）を読み解き、Timeline で追える「Event」へ変換します。本ノートは Phase 4 の前半、**Parser framework + LNK Parser** を解説します。ここを完成させると、LNK 1種だけで「解析 → Case JSON + Manifest」まで通る縦割りスライス（M2）が達成できます。

---

## 1. Parser とは何をするものか

### 証拠ファイルは「そのままでは読めない」

Windows の `.lnk`（ショートカット）ファイルは、独自のバイナリ形式（[MS-SHLLINK]）で書かれています。中身を `cat` で見ても文字化けします。EVTX・Prefetch・Registry hive も同様で、どれも Microsoft が定めた構造に従って byte 列を解読しなければなりません。

この「byte 列 → 意味のあるデータ」の変換を行うのが **Parser** です。TraceForge では各形式に1つの Parser を作ります（LNK・Prefetch・EVTX・USN・Registry・Amcache・Jump Lists の7種）。

### Parser が出力する「Event」とは

Parser は証拠ファイルの中身を読み、**Event**（規範 §7.1）へ変換します。Event は「いつ・どこで・何が観測されたか」を1行で表す単位で、Timeline の1項目になります。

例えば LNK ファイルには作成時刻・アクセス時刻・更新時刻が記録されています。Parser はこれらをそれぞれ1つの Event へ変換します。ただし、**「この時刻にユーザーが target を開いた」と断定してはいけません**（規範 §7.1・互換 §4.4）。LNK に時刻が記録されている事実だけを観測 Event として残します。

---

## 2. なぜ「全 Event を `Vec` で返さない」のか

### 問題: 大量の Event を一度にメモリへ載せると OOM する

EVTX ログ1つから数十万 Event が生成されることがあります。Parser が `Vec<Event>` で全件を返す設計だと、メモリ不足（OOM）で解析が crash する危険があります。Phase 3 の Event Store と同じ問題です（規範 §21-6）。

### 解決: sink 型 interface

TraceForge の Parser は **Event を1件ずつ sink へ流し込みます**（規範 §9.1）。`Vec` で全件を返しません。

```rust
// ❌ 禁止: 全 Event を Vec で返す
fn parse(&self, snapshot: ...) -> Vec<Event> { ... }

// ✅ 正しい: sink へ1件ずつ流す
fn parse(&self, snapshot: ..., sink: &mut dyn ParseSink) -> ParseSummary { ... }
```

`ParseSink` は「Event を受け取る出口」の trait です（`framework.rs`）:

```rust
pub trait ParseSink {
    fn emit_event(&mut self, event: Event) -> Result<(), SinkError>;
    fn emit_issue(&mut self, issue: Issue) -> Result<(), SinkError>;
}
```

Parser は1件 Event を作るたびに `sink.emit_event(event)` を呼びます。sink の中身は呼出側が自由に決められます:

- **EventStoreSink**: Event Store（Phase 3）へ直接書き込む sink。100万 Event でもメモリを圧迫しません。
- **CollectorSink**（テスト用）: `Vec` へ溜めて、あとで assertion を書くための sink。

この設計の利点は「Parser がメモリ管理を知らなくてよい」ことです。Parser は1件ずつ流すことに集中し、メモリ上限への対応は sink 側（EventStoreSink）へ任せます。

---

## 3. Parser 契約（ArtifactParser trait）

全 Parser は [`ArtifactParser`] trait（規範 §9.1）を実装します:

```rust
pub trait ArtifactParser {
    fn parser_id(&self) -> &'static str;       // 例: "traceforge-lnk"
    fn parser_version(&self) -> &'static str;  // SemVer
    fn artifact_type(&self) -> ArtifactSource;  // 例: Lnk

    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult;
    fn parse(&self, snapshot: &mut dyn ReadSeek,
             context: &ParseContext, sink: &mut dyn ParseSink) -> ParseSummary;
}
```

各メソッドの役割:

| メソッド | 役割 |
|---|---|
| `parser_id` / `parser_version` | Provenance・Manifest へ記録される。Event ID の hash へも入る（規範 §12.3） |
| `artifact_type` | LNK・EVTX 等の種別（Schema §3.4） |
| `probe` | この Evidence が自分の扱える形式か識別する（規範 §11） |
| `parse` | snapshot を読み、Event と Issue を sink へ1件ずつ流す |

`probe` は「このファイルは LNK か？」を判定します。LNK Parser なら HeaderSize と CLSID を見て判定します。

`parse` の第1引数は `&mut dyn ReadSeek`（`Read + Seek`）です。Parser は元の証拠ファイルではなく、**不変 snapshot**（Phase 2）を読みます（規範 §5.5）。これにより、解析中に元ファイルが書き換えられても結果が変わりません。

### ParseSummary で結果を報告する

`parse` の戻り値は [`ParseSummary`]（規範 §9.2）です:

```rust
pub struct ParseSummary {
    pub status: ParseStatus,  // Complete / Partial / Skipped / Failed
    pub records_seen: u64,
    pub events_emitted: u64,
    pub issues_emitted: u64,
    pub bytes_consumed: u64,
}
```

- **Complete**: 全 record を正常に解析した。
- **Partial**: 中間 record が破損したが、安全な境界で継続できた。生成済み Event は破棄しない（規範 §9.2）。
- **Skipped**: 未対応形式・未対応 version で解析しなかった。
- **Failed**: 解析を続けられない致命的失敗。

---

## 4. panic 境界: 入力起因の異常で abort しない

### 破損ファイルで panic してはいけない

フォレンジックツールは **壊れたファイル・悪意あるファイル** を読まされます。もし Parser が `unwrap()` で panic したら、解析全体が crash します。これは許されません（規範 §9.4）。

Parser 実装者は境界検証で `Result` を返すべきですが、人間はミスをします。そこで **最終安全網** として [`run_parser_catching_panic`]（`framework.rs`）を用意します:

```rust
pub fn run_parser_catching_panic(
    parser: &dyn ArtifactParser,
    snapshot: &mut dyn ReadSeek,
    context: &ParseContext,
    sink: &mut dyn ParseSink,
) -> ParseSummary {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        parser.parse(snapshot, context, sink)
    }));
    match result {
        Ok(summary) => summary,
        Err(panic_payload) => {
            // panic を Fatal Issue へ変換して記録する。
            sink.emit_issue(/* TF-F-PARSER-PANIC, severity: Fatal */);
            ParseSummary::failed()
        }
    }
}
```

[`std::panic::catch_unwind`] は panic を捕捉して `Result` へ変換します。これにより、Parser 内部で予期せぬ panic が起きても、呼出側は `ParseStatus::Failed` + Fatal Issue として処理できます。最終的に process 全体は Exit Code 10（規範 §17.2）で停止します。

> **補足**: `catch_unwind` は全ての panic を捕捉できるわけではありません（`abort` 設定時や一部 FFI panic）。Rust の既定 `unwind` 動作を前提とします。

---

## 5. Parse Issue: 安全な message で「完全ではない理由」を記録する

### 巨大値・制御文字をそのまま message へ入れてはいけない

Parser が破損 record へ遭遇したら、[`Issue`]（Schema §5.6）へ「どの record が壊れていたか」を記録します。ただし規範 §9.3 は **message へ Evidence 起因の巨大値や未 escape の制御文字をそのまま含めてはならない** と求めます。

例えば、壊れた LNK の生 byte 列をそのまま message へ入れると、Manifest が巨大化し、制御文字で terminal が壊れる危険があります。

### sanitize_issue_message で安全化する

`issue.rs` の [`sanitize_issue_message`] がこれを行います:

1. C0/C1 制御文字・ESC を `\xXX` 形式へ escape。
2. [`MAX_ISSUE_MESSAGE_BYTES`]（512 byte）を超える場合は切り詰めて `...(truncated)` を付ける。

Parser 実装者は `sanitize_issue_message(&format!("record {i} が破損: {raw}"))` を呼べば安全です。

### 安定した Issue code

各 Issue には **安定した code** を付けます（規範 §9.3）。code は Manifest へ記録され、分析者が grep する対象になります。変更すると互換性が壊れるので、`const` で固定します:

```rust
pub const TRUNCATED_RECORD: &str = "TF-W-PARSER-TRUNCATED-RECORD";
pub const PANIC_FATAL: &str = "TF-F-PARSER-PANIC";
pub const MISSING_REQUIRED_FIELD: &str = "TF-W-PARSER-MISSING-REQUIRED-FIELD";
```

命名規則は `TF-<SEV>-<PARSER>-<REASON>`（`<SEV>` = W/R/F = Warning/Recoverable/Fatal）。

---

## 6. LNK 形式の概要（[MS-SHLLINK]）

LNK は Windows のショートカットファイル形式です。Microsoft が [MS-SHLLINK] 仕様で公開しています。主な構造:

```text
1. Shell Link Header (76 byte 固定)
   - HeaderSize, CLSID, Flags, FileAttributes
   - CreationTime / AccessTime / WriteTime (FILETIME)
   - FileSize, IconIndex, ShowCommand, HotKey, Reserved

2. LinkTargetIDList (Flags に HasLinkTargetIDList があれば)
   - shell namespace item ID の列

3. LinkInfo (Flags に HasLinkInfo があれば)
   - LocalBasePath / CommonPathSuffix（target の path 情報）

4. StringData (Flags に応じて)
   - NAME / RELATIVE_PATH / WORKING_DIR / ARGUMENTS / ICON_LOCATION

5. ExtraData (可変長 block の列)
   - TrackerData / EnvironmentVariableData / PropertyStoreData 等
   - TerminalBlock (0x00000000) で終端
```

### FILETIME 変換

Header の3 timestamp（Creation/Access/Write）は **FILETIME** 形式です。FILETIME は 1601-01-01 00:00:00 UTC からの 100 ナノ秒間隔を表す 64 bit 符号なし整数で、0 は「時刻未設定」を意味します。

`lnk/filetime.rs` の `filetime_to_datetime` が UTC instant へ変換します。1601 年と 1970 年（Unix epoch）の差は 11_644_473_600 秒です:

```rust
const WINDOWS_EPOCH_DIFF: i64 = 11_644_473_600;
fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 { return None; }  // 未設定
    let intervals = filetime as i64;
    let seconds = intervals.div_euclid(10_000_000);
    let unix_seconds = seconds.checked_sub(WINDOWS_EPOCH_DIFF)?;
    DateTime::<Utc>::from_timestamp(unix_seconds, /* nanos */)
}
```

### LinkFlags で読む section が変わる

Header の Flags field は「どの section が存在するか」を示す bit 列です。例えば:

- bit0 (`HasLinkTargetIDList`): LinkTargetIDList section がある。
- bit7 (`IsUnicode`): StringData が UTF-16LE（真）か ANSI（偽）か。

Parser は Flags を見て、存在する section だけを読みます。

---

## 7. timestamp を観測 Event へ

### 「開いた」と断定しない（規範 §7.1・互換 §4.4）

LNK の Header には CreationTime・AccessTime・WriteTime があります。これらは「ショートカットの metadata に記録された時刻」であって、「ユーザーが target を開いた時刻」ではありません。

例えば、ショートカットを copy すると timestamp も一緒に移動します。なので、timestamp だけから「ユーザーがこの時刻に target を開いた」と断定すると誤判定になります。

TraceForge はこれを **`lnk_timestamp`** という観測型 Event として記録します:

```rust
// event_type は "lnk_timestamp"。実行や open を断定しない。
event.event_type = EventType::new("lnk_timestamp");
event.assertion = AssertionKind::Observed;
```

attributes へ `lnk.timestamp_field` = "creation"/"access"/"write" を入れて、どの timestamp か分かるようにします（互換 §4.4: timestamp kind と元 field 名を保持）。

### 1 LNK から最大3 Event

1つの LNK ファイルには最大3つの timestamp があります。Parser は各 timestamp で1 Event ずつ生成します（合計3 Event）。全て 0（未設定）の場合は、`Unknown` time で1 Event だけ生成し、header の観測を記録します。

各 Event の Event ID は決定的に計算されます（規範 §12.3）。timestamp が異なれば Event ID も異なります。

---

## 8. 合成 fixture と acceptance test

### なぜ「合成 fixture」を使うのか

acceptance test（互換 §12）では、正常 fixture から期待 Event が生成されることを検証しなければなりません。ただし、実 Windows 環境の LNK ファイルを調達するのは手間がかかります（Win 7 SP1 / 10 22H2 / 11 24H2 の実環境生成物が必要）。

Phase 4 では **[MS-SHLLINK] 仕様へ準拠した hand-crafted 合成 fixture** を使います（`tests/common/mod.rs` の `build_lnk_fixture`）。これは仕様へ合致する byte 列を Rust コードで構築するもので、実行するたびに同一 bytes が生成されます（決定性あり）。

実 Windows fixture は Phase 8（品質保証とリリース）で調達し、合成 fixture とすり合わせます。

### fixture メタデータの記録（互換 §12-5）

各 fixture には次を記録します（`acceptance_tests.rs` の `acceptance_12_5`）:

- **SHA-256**: 64 文字 lowercase hex。`tf_core::hash::sha256_hex` で計算。
- **生成方法**: hand-crafted, [MS-SHLLINK] 準拠。
- **生成 OS**: 合成（Windows 由来ではない）。

これらは将来の release 記録へ反映します。

### acceptance 条件（互換 §12）

LNK Parser は次を満たします（`acceptance_tests.rs`）:

| # | 条件 | テスト |
|---|---|---|
| 1 | 正常 fixture から期待 Event を生成 | `acceptance_12_1` |
| 2 | truncated・invalid・unknown version で panic しない | `acceptance_12_2` |
| 3 | Provenance が元 record へ到達する | `acceptance_12_3` |
| 4 | 1 thread と複数 thread で出力が一致 | `acceptance_12_4`（Parser 単体の決定性。完全 Golden は Phase 8） |
| 5 | fixture SHA-256・生成 OS・取得方法を記録 | `acceptance_12_5` |
| 6 | 外部仕様 revision（[MS-SHLLINK]）を記録 | `acceptance_12_6` |
| 7 | 非対応 field・version を黙って無視しない | `acceptance_12_7` |
| 8 | Event type を断定しない | `acceptance_12_8` |

---

## 9. M2 縦割り: LNK だけで Case JSON + Manifest まで通す

### なぜ早期に縦割りを通すのか

roadmap §3.2「早期の縦割りスライス」は、Parser 全種完成を待たず LNK 1種で **`analyze` → Event Store → Timeline → JSON Case 出力 → Manifest** までを早期に通すことを求めています（M2）。これにより、決定性・再現性・Provenance の設計欠陥を初期に検出できます。

もし Phase 4 全 Parser 完成まで縦割りを後回しにすると、Event ID・source ordinal・Timeline sort 等の設計ミスが後発見になり、手戻りが大きくなります。

### M2 の流れ

`acceptance_tests.rs` の `m2_vertical_slice_lnk_to_case_json_and_manifest` が1つのテスト関数でこの流れを完結させます:

```text
1. build_lnk_fixture: 合成 LNK bytes を生成
2. tf_evidence::snapshot: snapshot 作成 + SHA-256 計算 + EvidenceItem 構築
3. LnkParser::parse + EventStoreSink: Event を EventStore へ逐次保存
4. EventStore::commit: commit marker を書く
5. tf_store::output::write_jsonl: Timeline 順で JSONL 出力（Case + Evidence + Artifact + Event + Manifest）
```

出力 JSONL は Schema §6 の順序（case → evidence → artifact → event → issue → match → finding → manifest）へ並びます。Event 行は Timeline 順（UTC timestamp 昇順、同一 timestamp は Event ID 昇順）になります。

### EventStoreSink が Parser と EventStore を結ぶ

`sink.rs` の [`EventStoreSink`] が [`ParseSink`] trait を実装し、Parser が流した Event を直接 [`EventStore::store_event`] へ渡します。これにより Parser と EventStore が「sink 型 interface」で結合し、100万 Event でもメモリを圧迫しません（規範 §21-6）。

---

## 10. 今後の拡張点

Phase 4 はまだ前半です。残り6種（Prefetch・USN・EVTX・Registry・Amcache・Jump Lists）を順次追加します。各 Parser は [`ArtifactParser`] trait を実装すれば、framework・sink・EventStore をそのまま再利用できます。

### record-stream 型 Parser への拡張

LNK は1ファイル1レコードですが、EVTX や USN は1ファイルに多数の record が入ります。これらの Parser では record 毎に [`ParseSink::emit_event`] を呼び、中間 record の破損は [`Issue`] へ記録して次 record へ進みます（規範 §9.2）。framework はこの「部分成功」をサポートします。

### limit framework との統合

Phase 2 の limit framework（`tf_evidence::limit`）は Event 数・Issue 数に上限を設けます。将来、`EventStoreSink` へ [`LimitTracker`] を渡し、`emit_event` の直前に上限を検査する拡張を想定しています。これにより Parser 側は limit を意識せず、sink が limit 到達を検知して安全に停止します。

---

## まとめ

Phase 4 前半では次を作りました:

- **Parser framework**（`framework.rs`）: `ArtifactParser` trait・`ParseSink` trait・`ParseSummary`・panic 捕捉。
- **Parse Issue helper**（`issue.rs`）: `sanitize_issue_message`・安定 code 定数。
- **EventStoreSink**（`sink.rs`）: Parser → EventStore の橋渡し。
- **LNK Parser**（`lnk/`）: [MS-SHLLINK] 準拠。timestamp を観測 Event へ。
- **合成 fixture と acceptance test**: 互換 §12 の8条件を検証。
- **M2 縦割り**: LNK だけで Case JSON + Manifest まで通ることを確認。

次のステップは残り6 Parser の実装です。framework が据わっているので、各形式の byte 列解読に集中できます。
