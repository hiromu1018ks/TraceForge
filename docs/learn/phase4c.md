# Phase 4 後半 学習ノート: USN Journal Parser

> 対象読者: Phase 4 後半 Prefetch Parser（phase4b.md）を読み終えた人。Rust で `trait` / `Result` / `enum` / `match` を一通り書けるレベル。

Phase 4 後半は残り5種の Parser を順次実装します。本ノートはその2つ目、**USN Journal Parser** を解説します。USN Journal は NTFS が記録する「ファイルシステム変更のジャーナル」で、フォレンジックでは「いつ・どのファイルが作られた/削除された/名前が変わった」を知る強力な証拠です。ここでは初の **record-stream 型** Parser として、framework の「部分成功」が本格的に活躍する姿を扱います。

---

## 1. USN Journal とは何か

### NTFS の「変更ログ」

Windows の NTFS ファイルシステムは、ボリューム上のファイルへ加えられた変更（作成・削除・リネーム・データ追記・属性変更等）を **シーケンシャルなログ** として記録する仕組みを持っています。これが **USN Journal (Update Sequence Number Journal)** です。ログは各ボリュームの `C:\$Extend\$UsnJrnl:$J` という Alternate Data Stream（通常は見えない）へ蓄積されます。

各レコードは **USN（Update Sequence Number）** と呼ばれる通番を持ち、基本的に単調増加します。新しい変更ほど大きい USN になります。

### なぜフォレンジックで重要か

「マルウェアが落下した時刻」「ログが消された痕跡」「設定ファイルが書き換えられた時刻」などを調べるとき、USN Journal は時間軸での event-by-event の追跡を可能にします。例えば次のような調査ができます:

- `mimikatz.exe` が作成された USN record を見つける → 落下時刻が分かる
- `Security.evtx` の USN record で `FILE_DELETE` reason を見つける → ログ消去の痕跡
- 同じ file reference で `RENAME_OLD_NAME` → `RENAME_NEW_NAME` が連続する → リネーム事件の復元

ただし **USN record の存在は「ファイルシステム変更の観測」であり、「絶対に作成された」という断定ではない** ことに注意が必要です（規範 §7.1・互換 §4.3）。ジャーナルが無効化されていたり、ローテーションで古い record が消えていることもあるからです。本 Parser は観測型 Event として扱います（後述）。

---

## 2. $J ストリームの構造

### レコードがひたすら並ぶ

USN Journal の `$J` ストリームは、ヘッダを持たず **レコードがただ連続して並ぶ** 構造です（Phase 4 前半の LNK や Prefetch とは違います）。各レコードは先頭8 byteの **USN_RECORD_COMMON_HEADER** を持ち、これで「自分自身の長さ」と「バージョン」を宣言します:

```
┌────────────────────────────────┐  offset 0
│ USN_RECORD_COMMON_HEADER (8B)  │   RecordLength(4) / MajorVersion(2) / MinorVersion(2)
├────────────────────────────────┤
│ V2/V3/V4 固有部                 │   file reference / parent / USN / 時刻 / reason / ...
├────────────────────────────────┤
│ FileName (V2/V3 のみ)           │   UTF-16LE・null 終端
└────────────────────────────────┘
                          ← 次のレコードはここから（offset = 直前の RecordLength の累積）
```

Parser は「COMMON_HEADER を読む → RecordLength 分を1レコードとして処理 → 次のレコードへ」というループを回します。これが **record-stream 型** の基本形です。

### バージョンが3つある

`MajorVersion` で V2 / V3 / V4 を切り分けます（互換 §4.3）:

| version | 主な使われ所                                 | file reference 幅 | filename |
|---|---|---|---|
| 2 | 従来の NTFS（ほとんどの Windows）             | 64 bit            | あり     |
| 3 | 128-bit file reference を使うボリューム       | **128 bit**       | あり     |
| 4 | 整合性 (integrity) stream 等の range tracking | 128 bit           | **なし** |

V3・V4 の `FILE_ID_128` は16 byte すべてを保持し、**絶対に切り詰めません**（互換 §4.3）。V2 と V3 で「同じ MFT 番号」を指していても表現が違うため、本 Parser は比較可能な文字列（`v2:<16桁 hex>` / `v3v4:<32桁 hex>`）へ正規化して扱います（`FileReference::as_comparison_key`）。

V4 は **filename を持ちません**。range tracking（どの範囲が変更されたか）だけを記録します。後述するように、filename は USN Event の必須 field なので、V4 単独では Event 化せず「record は認識したが Event 化しない」扱いにします（互換 §5 必須 field 欠落）。

---

## 3. record-stream 型と部分成功

### 最初の本格的な record-stream 型 Parser

Phase 4 前半の LNK・Prefetch は「1ファイル = 1レコード系」の形式でした。一方 USN $J は **1ファイルに数百〜数百万レコード** が並びます。この違いが framework の設計へ一番効くのが **部分成功** です（規範 §9.2・§21-5）。

> **規範 §9.2**: 1レコードの破損は Issue として出力し、次レコードの境界を安全に特定できる場合だけ継続する。境界を安全に特定できない場合、その ArtifactInstance を `Partial` で終了する。生成済み Event を破棄してはならない。

つまり「真ん中のレコードが壊れていても、前後の正常レコードからは Event を生成し続ける」のが求められます。本 Parser は次のように実装します:

```rust
loop {
    // 1. COMMON_HEADER (8 byte) を読む。EOF なら正常終端。
    // 2. RecordLength が異常（小さすぎ/大きすぎ）なら Partial 終了。
    // 3. 未対応 MajorVersion なら RecordLength 分を skip して Warning → 継続。
    // 4. 対応版なら RecordLength 分を1レコード処理 → 継続。
}
```

特に重要なのが **「境界が分からない破損」と「境界が分かる破損」の区別** です:

- **境界が分かる**: RecordLength は読めたが、宣言した長さまで bytes が無い（truncated）・RecordLength が上限を超える → **Partial 終了**（次のレコードがどこから始まるか分からないため）
- **境界が分かる**: レコード内の field（filename offset 等）が不正 → **そのレコードだけ Issue 化して skip、次へ継続**

### 「生成済み Event を破棄しない」の実現

本 Parser は Event を1件生成するたびに `sink.emit_event()` へ流します（`Vec` で溜めない、規範 §9.1）。したがって「後で壊れたレコードが見つかったから、それまでの Event を捨てる」という事態が **構造上起きません**。Framework 側の設計がそのまま部分成功の保証へ繋がっています。

---

## 4. rename 結合: 3条件をすべて満たすときだけ

### OLD_NAME と NEW_NAME

Windows はファイルのリネームを2つの USN record で記録します:

- `USN_REASON_RENAME_OLD_NAME`（reason bit `0x00001000`）: 古い名前
- `USN_REASON_RENAME_NEW_NAME`（reason bit `0x00002000`）: 新しい名前

同じファイルのリネームなら、この2つは **同一 file reference・近接 USN** になるはずです。本 Parser はこれを **1つの観測 Event へ結合** します（互換 §4.3・`combine.rs`）。

ただし、安全側へ倒すため、結合は **3条件をすべて満たすときだけ** にします:

1. **同一 file reference**: OLD_NAME 候補と NEW_NAME 候補の `file_reference` が完全一致
2. **近接 USN**: USN の差が 0 または 1（同一トランザクション or 直後）
3. **対応 reason**: OLD_NAME 候補の reason が `RENAME_OLD_NAME`、次レコードが `RENAME_NEW_NAME`

1つでも欠ければ **独立した Event** として扱います（規範 §7.1: 断定禁止）。例えば OLD_NAME の後に別ファイルの変更が挟まった場合、OLD_NAME 単独の Event になります。

```rust
fn try_combine_rename(old: &UsnRecord, new: &UsnRecord) -> Option<UsnObservation> {
    if new.reason & flags::RENAME_NEW_NAME == 0 { return None; }   // 条件3
    new.file_name.as_ref()?;                                       // 両方 filename 必須
    if old.file_reference != new.file_reference { return None; }   // 条件1
    let delta = (new.usn - old.usn).abs();
    if delta > PROXIMATE_USN_DELTA { return None; }                // 条件2
    Some(UsnObservation::combined_rename(old.clone(), new.clone()))
}
```

### なぜ「近接」を「差1」までにするのか

実際の Windows では OLD_NAME / NEW_NAME は **同じ USN** を持つことがほとんどです。しかし稀に別のトランザクションが間に挟まり、USN が1ずれることがあります。本 Parser は安全側（結合しすぎない側）へ「差1 まで」を許容し、差2 以上は別変更の可能性があるとして結合しません。過剰に結合すると、無関係な2ファイルを同一イベントへ混ぜる危険があるためです。

---

## 5. path reconstruction: host へ聞きに行かない

### 同一ストリーム内の mapping だけ

USN record には「ファイル自身の名前」と「親ディレクトリの file reference」がありますが、親ディレクトリの **名前は入っていません**。親の名前を知るには、別途そのディレクトリの USN record が必要です。

ここで「host の MFT へ問い合わせて親の名前を取ってくる」実装にすると、**host 環境依存・非再現・証拠性の弱化** に繋がります（互換 §4.3）:

> USN path reconstruction は、同じ Evidence set 内に安全に利用できる親 directory mapping がある場合だけ行う。取得できない親を host filesystem から検索してはならない。

本 Parser は `$J` ストリーム内で収集した `file_reference → (name, parent_reference)` の mapping（`path.rs`）だけを使い、解決できない親が現れたらそこで止めて **部分的な path** を返します。

```rust
// 子→親の順に名前を集める
let mut components = vec![self_name];
for _ in 0..MAX_DEPTH {
    let Some(entry) = self.name_map.get(&current_ref) else { break; };
    components.push(entry.name.clone());
    current_ref = entry.parent.clone();
}
components.reverse();  // 親→子（NTFS の左から右）へ反転
Some(WindowsPathValue::new(components.join("\\")))
```

`Docs\note.txt` のような完全 path が構築できるときもあれば、親が mapping に無ければ `note.txt` 単独になります。どちらも正しい観測事実です。深さ上限（32段）でループも防ぎます。

---

## 6. 観測型 Event: 「作成した」と断定しない

### usn_change_observed

USN record には `USN_REASON_FILE_CREATE`（`0x00000100`）や `USN_REASON_FILE_DELETE`（`0x00000200`）といった bit があります。これをそのまま `file_created` / `file_deleted` 型 Event へ変換したくなりますが、**それは禁止されています**（規範 §7.1・互換 §4.3）。

理由は、USN record は「ジャーナルサービスが観測した変更ログ」であり、「実際に作成された」という事実とは微妙にズレるからです:

- ジャーナルが一杯でローテーションされ、古い record が消えているかもしれない
- ジャーナルが無効化されていた期間は記録が無い
- 同一ファイルが複数回の変更を1レコードへまとめられることがある

したがって本 Parser は **`usn_change_observed`** という観測型 Event type だけを生成します:

```rust
event_type: EventType::new(USN_CHANGE_OBSERVED_EVENT_TYPE),  // "usn_change_observed"
assertion:  AssertionKind::Observed,
```

「ファイルが作成された」と断定するのは、他の証拠（EVTX のオブジェクトアクセス監査等）との Correlation で Finding を作る段階です。Parser は観測した事実だけを残します。

### reason は属性として残す

断定型 Event にしない代わりに、`reason` bit field は **flag 名の配列** として属性へ残します（`reason.rs`）:

```json
"usn.reason": 256,
"usn.reason_flags": ["FILE_CREATE"]
```

既知 bit 以外の「未知 bit」も黙って捨てず、`usn.reason_unknown_bits` 属性へ OR 和で残します（互換 §12-7: 黙殺しない）。将来の Windows で新しい reason bit が追加されても、情報が失われません。

---

## 7. V4 の取扱: filename 無しを Event 化しない

V4 は range tracking 情報だけを持ち、filename を持ちません。本 Parser は V4 を「record としては認識するが Event 化しない」扱いにします（互換 §5 必須 field 欠落）:

```rust
fn build_event(observation: &UsnObservation, ...) -> Option<Event> {
    let first = observation.first();
    first.file_name.as_ref()?;   // filename 無し（V4 only）なら None
    // ... Event 構築
}
```

V4 の range tracking 情報は、もし将来 V2/V3 のレコードと結合して Event 化する経路ができたときのために、`UsnRecord.range_tracking` フィールドへ保持しています。本 Phase の範囲では単独 Event にはしません。

### 結合ロジックも filename 必須

`combine.rs` の OLD_NAME 候補化でも filename の存在を条件にします。V4 のみで `RENAME_OLD_NAME` が立っていても候補化しない（filename が無いため結合の意味がない）設計です。

---

## 8. 未知 MajorVersion の安全 skip

将来の Windows で V5 や V6 が追加される可能性があります。本 Parser は **既知形式として推測しない** 方針（規範 §9.2・互換 §12-7）で、未知 MajorVersion を処理します:

1. COMMON_HEADER を読み、MajorVersion が 2/3/4 以外なら **未対応** と判定
2. **RecordLength が安全な範囲** なら、その分を skip して次レコードへ進む
3. 同時に `TF-W-PARSER-UNSUPPORTED-VERSION` Issue を Warning で記録

```rust
if !is_supported_major_version(header.major_version) {
    skip_bytes(snapshot, header.record_length - COMMON_HEADER_BYTES as u64)?;
    sink.emit_issue(record_issue(
        UNSUPPORTED_VERSION_CODE,
        IssueSeverity::Warning,
        ...,
        &format!("未対応 MajorVersion {} を skip した", header.major_version),
    ));
    continue;  // ← 次のレコードへ
}
```

「既知形式として推測しない」が重要なのは、推測して誤った Event を出すと Timeline の信頼性が損なわれるからです。未対応は未対応として Issue へ残し、解析者へ「ここには未知の形式があった」ことを伝えます。

---

## 9. 合成 fixture と acceptance test

### 合成 USN fixture ビルダ

Phase 4 前半・Prefetch と同様、本 Phase も **合成（hand-crafted）fixture** で検証します（実 Windows 環境の採取は Phase 8）。`tests/common/mod.rs` のヘルパーを拡張し、V2/V3/V4 各1レコードを構築できるようにしました:

- `build_usn_v2_record`: 64 bit file reference + filename
- `build_usn_v3_record`: 128 bit file reference + filename（切り詰めなし）
- `build_usn_v4_record`: 128 bit file reference + range tracking（filename 無し）
- `usn_reason` module: テスト用 reason bit 定数

各レコードは Microsoft の `USN_RECORD_V2` / `V3` / `V4` 構造体（`winioctl.h`・`ntifs.h`）の byte 並びへ厳密に合わせて構築します。

### acceptance test 8条件（互換 §12）

`acceptance_tests.rs` の `usn_acceptance_12_*` で、互換 §12 の8条件を USN 版で検証します:

| 条件 | 検証内容 |
|---|---|
| §12-1 | V2/V3 各2件以上を含む fixture から期待 Event を生成 |
| §12-2 | truncated / invalid length / unknown version で panic しない |
| §12-3 | Provenance の `record_locator` が元 record の byte range を指す |
| §12-4 | 同一入力で同一 Event ID（決定性） |
| §12-5 | fixture SHA-256 lowercase hex 64 桁 |
| §12-6 | `usn.reference_spec`・`usn.parser_version` を属性へ記録 |
| §12-7 | 未知 MajorVersion を `UNSUPPORTED_VERSION` Issue へ記録（黙殺しない） |
| §12-8 | `usn_change_observed` のみで `created` / `deleted` 等の断定語を含まない |

加えて **rename 結合・非結合** と **path reconstruction（解決/未解決）** を独立テスト（`usn_tests.rs`）で検証します。

### USN 単体でも縦割りが通る

Phase 4 前半の M2（LNK だけで Case JSON + Manifest まで通る）と同じ経路が、USN でも通ります（`usn_vertical_slice_usn_to_case_jsonl`）。USN Parser が生成した Event が EventStore へ蓄積され、Timeline 順へ整列し、Case JSONL + Manifest へ出力されるまでを1関数で完結させます。Framework の再利用性を示す重要な検証です。

---

## 10. 128-bit file reference を切り詰めない

V3 / V4 の `FILE_ID_128` は16 byte（128 bit）の配列です。これを V2 互換の64 bit へ切り詰めて格納したくなりますが、**それは互換 §4.3 で明示的に禁止** されています:

> USN_RECORD_V3: 128-bit file reference を切り詰めず取得

理由は、128 bit の上位 bit にも意味がある（例えば NTFS リフレッシュや refs では高位が使われる）ため、切り詰めると異なるファイルが同じ参照へ潰れてしまうからです。本 Parser は16 byte すべてを `FileReference::V3V4([u8; 16])` で保持し、文字列表現も32桁の lowercase hex（`v3v4:01020304...`）で切り詰めません（`record.rs`）。

---

## 11. Provenance と「元レコードへ到達できる」

互換 §12-3 は「Event の Provenance が元 record へ到達できること」を求めます。本 Parser は各 Event の `record_locator` へ **USN record 先頭からの byte range** を設定します:

```rust
let record_locator = RecordLocator::ByteRange {
    start: first.record_offset,                              // ストリーム先頭からの offset
    end:   first.record_offset + header.record_length as u64,
};
```

これにより、Timeline 上の Event から「$J ストリームのこの byte 位置」へ正確に遡れます。解析者が「なぜこの Event が生成されたのか」を検証するとき、snapshot の該当 offset を直接 hex dump して確認できます。rename 結合時は **最初の（OLD_NAME 側の）レコード位置** を基準にします。

---

## まとめ

Phase 4 後半の USN Journal Parser で次を作りました:

- **USN $J 解析**（`usn/`）: USN_RECORD_COMMON_HEADER で V2/V3/V4 を判定。record-stream 型。
- **128-bit file reference 保持**（`record.rs`）: V3/V4 を切り詰めず16 byte で保持。
- **rename 結合**（`combine.rs`）: 同一 file reference + 近接 USN + 対応 reason の3条件すべてで結合。1つでも欠ければ独立 Event。
- **path reconstruction**（`path.rs`）: 同一ストリーム内の mapping のみ。host 検索禁止。深さ上限でループ回避。
- **部分成功**（`mod.rs`）: 中間レコード破損は Issue 化して前後の正常 record から Event を生成。境界不明だけ Partial 終了。
- **観測型 Event**: `usn_change_observed`。`file_created` 等の断定型にしない（規範 §7.1）。
- **未知 MajorVersion の安全 skip**: `TF-W-PARSER-UNSUPPORTED-VERSION` Issue へ記録。
- **合成 fixture + acceptance test**: 互換 §12 の8条件を USN 版で検証。縦割り（USN → Case JSONL + Manifest）も確認。

Phase 4 前半で据えた framework（`ParseSink`・`ParseSummary`・panic 捕捉・`EventStoreSink`）が、初の record-stream 型 Parser で本格的に「部分成功」を支えました。次のステップは残り4種（EVTX・Registry・Amcache・Jump Lists）です。EVTX はまた別の record-stream 型（binxml チャンク）で、partial chunk recovery が新しい課題になります。
