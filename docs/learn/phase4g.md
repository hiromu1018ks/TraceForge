# Phase 4 後半 学習ノート: Jump Lists Parser

> 対象読者: Phase 4 後半 Amcache Parser（phase4f.md）を読み終えた人。Rust で `trait` / `Result` / `enum` / `match` / 再帰関数を一通り書けるレベル。

Phase 4 後半は残り1種の Parser を実装します。本ノートはその最後、**Jump Lists Parser** を解説します。Jump Lists は Windows 7 以降で導入された「最近使った application・file」の履歴で、スタートメニューやタスクバーの右クリックへ表示される項目の元データです。ここでは **CFB container 解析**・**DestList stream 解析**・**内包 LNK の ArtifactInstance 化** という3つの新しい課題を扱います（互換 §4.5）。これで Phase 4 全 Parser（LNK / Prefetch / USN / EVTX / Registry / Amcache / Jump Lists の7種）が完成します。

---

## 1. Jump Lists とは何か

### 役割

Windows 7 以降、OS は各ユーザ・各 application 毎に「最近開いた file」「よく使う application」の履歴を保持します。これを Jump List と呼びます。例:

- エクスプローラーのタスクバーアイコンを右クリック → 「最近使った項目」
- スタートメニューの application の項目 → ピン留めした項目

フォレンジックでは「どの file が最近開かれたか」「どの application が利用されていたか」を調べる手がかりになります。

### 2 種類の Jump List file

Windows は Jump List データを2種類の file 形式で保存します:

| 形式 | 拡張子 | 内容 |
|---|---|---|
| AutomaticDestinations | `.automaticDestinations-ms` | OS が自動で記録した最近使った項目。CFB container 形式。 |
| CustomDestinations | `.customDestinations-ms` | ユーザが明示的に pin 等で追加した項目。独自 binary 形式。 |

両者とも `%APPDATA%\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` または `CustomDestinations` フォルダへ保存されます。file 名は `<AppID>.automaticDestinations-ms` のように application 固有の ID（AppID）を持ちます。

### 内包する LNK file

両形式とも内部へ **複数の LNK file**（[MS-SHLLINK] 形式・Phase 4 前半で実装済み）を内包します。各 LNK file が1つの Jump List entry（1つの最近使った項目）を表します。

---

## 2. CFB container の構造（AutomaticDestinations）

### Compound File Binary とは

`.automaticDestinations-ms` は **CFB（Compound File Binary）** と呼ばれる Microsoft の古い container 形式です（[MS-CFB]）。1つの file の中へ複数の「stream（子 file のようなもの）」を格納できます。古い `.doc` 形式や `.xls` 形式も CFB でした。

イメージとしては「1つの file の中に小さな仮想 file system がある」感じです:

```text
.automaticDestinations-ms file（CFB container）
├── stream "DestList"   ・・・Jump List 全体の metadata（最終利用時刻等）
├── stream "1"          ・・・1番目の entry（LNK file の中身）
├── stream "2"          ・・・2番目の entry（LNK file の中身）
└── stream "3"          ・・・3番目の entry（LNK file の中身）
```

stream 名の数字（"1", "2", ...）が entry の ID で、`DestList` stream が各 entry の timestamp や metadata を持ちます。

### CFB の階層構造

CFB file は次の4層構造を持ちます:

```text
┌───────────────────────────┐
│ Header (512 byte)          │  signature・sector size・各種 chain の先頭
├───────────────────────────┤
│ Sectors (512 byte 単位)    │  ─ FAT sectors: どの sector がどの sector 続きか
│                            │  ─ Directory sectors: stream の名前一覧
│                            │  ─ Mini FAT sectors: 小 stream 用の管理表
│                            │  ─ Stream data sectors: stream の実データ
└───────────────────────────┘
```

**FAT**（File Allocation Table）は「sector N の次の sector は M です」という対応表です。これを辿って1つの stream の全 byte 列を再構築します。

### 小さな stream の特別扱い: Mini stream

CFB は効率のため、**4096 byte 未満の小さな stream** を特別な領域（mini stream）へまとめて格納します。LNK file は通常 4096 byte 未満なので、ほとんどの内包 LNK は mini stream へ入ります。

mini stream の実体も FAT chain で管理され、その中を 64 byte 単位（mini sector）で分割して各 stream を格納します。どの mini sector がどの stream かは **Mini FAT** で管理されます。

本 Parser は次の3層を辿ります:

1. FAT chain を辿って directory entry 一覧を取得
2. 各 stream について「通常 stream か mini stream か」を size で判定
3. mini stream の場合は Mini FAT を経由して byte 列を復元

### 実装上の安全性

CFB 解析で一番怖いのは**循環参照**です。悪意のある file が「sector 0 の次は sector 1・sector 1 の次は sector 0」のような無限 loop を仕込むと、Parser が無限ループへ陥ります。本 Parser は `HashSet<u32>` で「既に訪問した sector」を管理し、再訪を検出した時点で打ち切ります（規範 §9.4: panic せずに安全に終了）。

---

## 3. DestList stream の構造

### DestList が持つ情報

`DestList` stream は Jump List 全体の metadata と各 entry の timestamp を保持します:

- 最終 revision 番号（FILETIME）
- 各 entry 毎:
  - stream 名（"1", "2", ...・対応する内包 LNK を指す）
  - 最終利用時刻（FILETIME）
  - 作成時刻（FILETIME）
  - 最終更新時刻（FILETIME）

これらは「利用者がいつその項目を開いたか」の手がかりになります。ただし **Jump List への記録は「開いた」ことの直接観測ではなく、あくまで「Jump List にその entry が観測された」だけ** です（規範 §7.1・互換 §4.5）。これは後述の「観測型 Event」へ直結します。

### version の違い

DestList は Windows の version 毎に形式が微妙に異なります:

| DestList version | 主な採用 | 主な相違 |
|---|---|---|
| 1 | Windows 7 SP1 | entry 固定部 74 byte |
| 3 | Windows 10 22H2 | entry 固定部 80 byte（field 追加） |
| 4 | Windows 11 24H2 | v3 とほぼ同じ（version 値のみ相違） |

本 Parser は v1・v3・v4 を対応済みとし、**未知 version は Warning Issue のみ** で container 全体を誤解析しません（互換 §4.5）。未知 version を既知形式として推測すると metadata を破損する可能性があるためです。

---

## 4. CustomDestinations の構造

`.customDestinations-ms` は CFB ではなく独自の binary 形式です。おおまかに次のような構造を持ちます:

```text
[16 byte file header]
[category 0]
  ├── category type (4 byte)
  ├── entry count (4 byte)
  └── entries...
       └── entry point type (4 byte = 0x3) + LNK bytes
[category 1]
  ...
[terminator (4 byte = 0x0)]
```

各 category は「最近使った項目」「ピン留め」等の分類を表します。各 entry は LNK file を丸ごと含みます。

本 Parser は各 category を順に読み、各 entry の LNK bytes を既存の [`crate::lnk`] machinery（header / idlist / linkinfo / stringdata / extradata）で解析します。これにより **LNK 再利用** が実現でき、Jump Lists Parser 固有の実装は container 解析部分だけに集中できます。

---

## 5. 内包 LNK の ArtifactInstance 化（重要）

### 「物理 Evidence として登録しない」とは

Phase 4 前半の LNK Parser は standalone の `.lnk` file を1つの EvidenceItem として扱いました。Jump Lists の内包 LNK は **standalone の file ではなく container の中へ埋め込まれた bytes** です。これを standalone LNK と同じように別 Evidence へ登録してしまうと:

- 元の Jump List Evidence との関係が失われる
- Provenance chain が切れる（どの Jump List に由来するか分からない）
- 二重解析の危険がある

そのため本 Parser は内包 LNK を **Jump List Evidence 内の ArtifactInstance** として扱い、新しい物理 Evidence へ登録しません（互換 §4.5・T4-072）。

### Provenance の記録方法

内包 LNK の「どこにあるか」を Provenance へ記録します:

- **stream 名**（例: "1"）を [`RecordLocator::LogicalPath`] へ
- **stream 内の offset**・**file 上の byte offset** を属性へ

これにより、後から「この Event は Jump List の stream "1" から来た」と辿ることができます。

### 別 Event type を生成しない

LNK header の timestamp（CreationTime・AccessTime・WriteTime）があっても、Jump Lists Parser は `lnk_timestamp` Event を生成しません。代わりに `jump_list_observation` Event 1件にまとめ、LNK 由来の値を属性として保持します。こうすることで:

- source（`ArtifactSource::JumpList` vs `ArtifactSource::Lnk`）が混同されない
- timeline へ現れる Event が Jump List 1件 = 1 Event と綺麗

---

## 6. 観測型 Event の方針（規範 §7.1・互換 §4.5）

### 「開いた」と断定しない

Jump List へ entry があるということは、Windows が「最近使った」と認識していたことを示します。しかし、それだけでは:

- 利用者が実際にその file を開いたか
- いつ開いたか（記録された timestamp ≠ 実操作時刻）
- 開いたのが誰か（同一ユーザとは限らない・共有環境の可能性）

を断定できません。そのため本 Parser が生成する Event type は `jump_list_observation`（観測）のみで、`file_opened`・`application_launched` 等の断定型は生成しません（規範 §7.1・互換 §4.5）。

各 Event には `jump_list.interpretation_limitation` 属性へ `"entry existence in jump list only; not direct evidence of opening/launching target"` と明示し、利用者（分析者）が過剰な解釈をしないようにします（互換 §5 必須 field「interpretation limitation」）。

---

## 7. 実装の全体像

### ファイル構成

```text
crates/parsers/src/jump_lists/
├── mod.rs        ・・・Parser 本体（ArtifactParser impl・Event 生成・probe）
├── cfb.rs        ・・・CFB container 解析（header・FAT・directory・MiniFAT）
├── destlist.rs   ・・・DestList stream 解析（v1/v3/v4・未知 version）
└── custom.rs     ・・・CustomDestinations 解析（category・entry・内包 LNK）
```

### Event 生成の流れ（AutomaticDestinations）

```text
snapshot bytes
   │
   ▼
parse_cfb(data)            ・・・CFB container 解析 → stream 一覧取得
   │
   ▼
parse_destlist(...)        ・・・"DestList" stream から entry metadata 取得
   │
   ▼
for each LNK stream:
   ├─ extract_lnk_from_bytes()  ・・・既存 lnk module で header / linkinfo / ... を読む
   ├─ make_event_time()         ・・・DestList 最終利用時刻 → EventTime
   ├─ attributes へ stream 名・offset・LNK 情報を記録
   ├─ RecordLocator::LogicalPath(["1"]) で stream 名を Provenance へ
   └─ sink.emit_event(event)   ・・・ParseSink へ1件ずつ流す
```

### Event 1件の属性（抜粋）

```json
{
  "jump_list.container_type": "automatic_destinations",
  "jump_list.app_id": "b9105685df489b5b",
  "jump_list.entry_index": 1,
  "jump_list.destlist_format_version": 3,
  "jump_list.stream_name": "1",
  "jump_list.destlist_last_used_filetime": 132548480000000000,
  "jump_list.lnk_target_path": "C:\\Windows\\System32\\notepad.exe",
  "jump_list.lnk_creation_filetime": 0,
  "jump_list.lnk_write_filetime": 132548480006000000,
  "jump_list.interpretation_limitation": "entry existence in jump list only; ...",
  "jump_list.reference_spec": "[MS-CFB] + [MS-DESTS] + [MS-SHLLINK]",
  "jump_list.parser_version": "1.0.0"
}
```

---

## 8. 部分成功と安全性（規範 §9.2・§21-5）

### 部分成功の例

Jump List file は複数 stream から成るため、1 stream が壊れても他は解析できます:

| 破損箇所 | 本 Parser の挙動 |
|---|---|
| CFB header・signature | Skipped（解析不可・Warning Issue） |
| DestList stream 未知 version | Partial・DestList 解析を skip し LNK stream のみ解析・Warning Issue |
| DestList stream truncated | Partial・読み取れた entry のみ解析・Warning Issue |
| 一部 LNK stream が壊れている | 当該 stream の attributes が default（0/None）・解析は継続 |
| CustomDestinations truncated | Partial・読み取れた entry のみ解析・Warning Issue |

### panic しない

いかなる破損入力でも panic しません（規範 §9.4・互換 §12-2）。境界検証で `Result` を返し、循環参照は `HashSet` で検出します。最終安全網として [`run_parser_catching_panic`] も指定済みです。

---

## 9. テストと acceptance（互換 §12）

### 単体テスト（`jump_lists/` module 内）

- `cfb.rs`: 最小 CFB container の解析・破損入力で panic しない
- `destlist.rs`: v1/v3/未知 version・truncated で panic しない
- `custom.rs`: 1 category / 1 entry・truncated で panic しない
- `mod.rs`: parser metadata・event_type・app_id 抽出・interpretation limitation

### 統合テスト（`tests/jump_lists_tests.rs`）

23 test。3 OS 世代（Win 7 SP1 / Win 10 22H2 / Win 11 24H2）の fixture・Provenance 到達・決定性・CustomDestinations・probe・vertical slice（→ EventStore）を検証します。

### Acceptance test（`tests/acceptance_tests.rs`）

10 test。互換 §12 の8条件（正常 fixture・truncated 耐性・Provenance 到達・決定性・SHA-256 記録・外部仕様 revision 記録・未知要素の記録・Event type 断定禁止）と、内包 LNK が物理 Evidence ではないことの検証、縦割り（→ Case JSONL + Manifest）を検証します。

### fixture の生成方法

全 fixture は合成（hand-crafted、[MS-CFB] + [MS-DESTS] + [MS-SHLLINK] 準拠）です。実 Windows 環境の生成物ではありません。fixture 管理方針（T0-012）へはその旨を記録します。

---

## 10. 残った課題・将来拡張

### Phase 4 共通検証（次回）

T4-090〜T4-092 で全 Parser の共通検証（thread 数 1/複数での一致・Provenance 到達の網羅的検証・fuzz target 作成）を実施します。これで Phase 4 が完全に完了します。

### 実 Windows 環境 fixture の調達

現状は全て合成 fixture です。互換 §12 を完全に満たすには、実 Windows 7 SP1 / 10 22H2 / 11 24H2 環境で採取した `.automaticDestinations-ms`・`.customDestinations-ms` が必要です（T0-013）。これらの実機 fixture で parser が意図通り動くかを検証するのは、Phase 4 共通検証または Phase 7（統合テスト）で実施します。

### property test / fuzz target

Jump Lists Parser への property test・fuzz target は Phase 4 共通検証（T4-092）で追加します。CFB の複雑な pointer chase は fuzzing で健壮性を確認する価値が高い領域です。

---

## 11. まとめ

Jump Lists Parser で **Phase 4 全 Parser が完成** しました（LNK / Prefetch / USN / EVTX / Registry / Amcache / Jump Lists の7種）。本 Parser で新しかったのは:

1. **CFB container 解析**: FAT・directory・MiniFAT の3層構造を辿る純 Rust 実装
2. **DestList version 認識**: v1/v3/v4 の違いを吸収し未知 version は Warning で安全 skip
3. **内包 LNK の ArtifactInstance 化**: 物理 Evidence へ登録せず Provenance chain を保つ
4. **CustomDestinations 独自形式**: category + entry 構造を走査し LNK を再利用
5. **観測型 Event の徹底**: `jump_list_observation` のみ・`interpretation_limitation` で過剰解釈を防止

Phase 4 前半で据えた framework（`ParseSink`・`ParseSummary`・panic 捕捉・`EventStoreSink`）が、複数 container 形式（CFB + 独自）を載せても破綻せず動くことを確認しました。次は **Phase 4 共通検証（T4-090〜T4-092）** で全 Parser の品質を横断的に保証し、Phase 4 を完了させます。
