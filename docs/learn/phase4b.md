# Phase 4 後半 学習ノート: Prefetch Parser

> 対象読者: Phase 4 前半（Parser framework + LNK）を読み終えた人。Rust で `trait` / `Result` / `enum` を一通り書けるレベル。

Phase 4 後半は残り6種の Parser を順次実装します。本ノートはその1つ目、**Prefetch Parser** を解説します。Prefetch は Windows の「実行履歴」を記録する仕組みで、フォレンジックでは「どのプログラムが動いたか」を知る最重要証拠の1つです。ここでは format version 17〜31 の読解と、Windows 10 以降の **MAM 圧縮** への対応を扱います。

---

## 1. Prefetch とは何か

### 「プログラムの起動を最適化する」記録

Windows はアプリの起動を速くするため、過去に起動したプログラムが読み込んだファイル（DLL や設定ファイル等）をあらかじめメモリへ読み込んでおく仕組みを持っています。これが **Prefetch** です。`C:\Windows\Prefetch\` の下に `.pf` ファイルとして蓄積されます。

各 `.pf` ファイルには、次のような情報が記録されます:

- **実行ファイル名**（例: `NOTEPAD.EXE`）
- **実行回数**（run count: 何度起動されたか）
- **最終実行時刻**（最大8個まで。最近の8回分）
- **ボリューム情報**（どのドライブから起動したか）
- **参照したファイル・ディレクトリの一覧**（読み込んだ DLL 等）

### なぜフォレンジックで重要か

「マルウェアが実行されたか」「不正なツールが動いたか」を調べるとき、Prefetch は直接の証拠になります。例えば `PSEXEC.EXE` や `MIMIKATZ.EXE` の `.pf` が残っていれば、それらが少なくとも1回は実行されたことが分かります。

ただし **Prefetch の存在は「実行痕跡が記録された」ことの観測** であり、「プロセスが起動した」と直接断定してはいけません（互換 §4.1）。この区別は後述する Event 設計へ反映されます。

---

## 2. Prefetch ファイルの構造

Prefetch のバイナリ形式は Microsoft が公式に公開しておらず、有志（libyal プロジェクト）がリバースエンジニアリングで文書化した仕様へ基づいて解析します。本 Parser は libyal の "Windows Prefetch File (PF) format" 文書へ従います。

### バージョンごとに構造が違う

Prefetch は Windows の世代ごとに format version が変わります:

| version | 主な OS |
|---|---|
| 17 | Windows XP / 2003 |
| 23 | Windows Vista / 7 |
| 26 | Windows 8 / 8.1 |
| 30 | Windows 10 |
| 31 | Windows 11 |

TraceForge は全バージョンへ対応します（互換 §4.1 で Required）。未知のバージョンは推測せず安全にスキップします。

### ファイルの全体構造

大きく4つのブロックで構成されます:

```
┌─────────────────────────────┐  offset 0
│ File header (84 byte)       │   version / signature / 実行ファイル名 / hash
├─────────────────────────────┤  offset 84
│ File information block      │   各ブロックへの offset / 実行時刻 / run count
├─────────────────────────────┤
│ File metrics array          │   参照ファイル一覧のメタデータ
├─────────────────────────────┤
│ Filename strings            │   参照ファイルのパス文字列（UTF-16LE）
├─────────────────────────────┤
│ Volumes information         │   ボリューム情報（デバイスパス・serial・作成時刻）
└─────────────────────────────┘
```

各ブロックの **絶対位置（offset）** は file information block の中へ書かれています。Parser はこの offset を読んで、対応するブロックへジャンプします。

### 「境界を安全に検証する」ことが Parser の仕事

Prefetch ファイルは破損していたり、意図的に offset を壊した攻撃データが来ることがあります。Parser は **絶対に panic しない** よう、すべての offset・長さのアクセスで範囲チェックを行います（規範 §9.4・互換 §12-2）。

```rust
// ❌ 危険: 範囲チェックなし
let value = u32::from_le_bytes(buf[offset..offset+4].try_into().unwrap());

// ✅ 安全: get() で範囲外なら None
let value = u32::from_le_bytes(buf.get(offset..offset+4)?.try_into().ok()?);
```

本 Parser の `metrics.rs`・`volume.rs`・`fileinfo.rs` はすべてこのパターンで書かれています。過大な offset や短すぎるデータは `None` へ変換され、安全にスキップされます。

---

## 3. MAM 圧縮: Windows 10 以降の追加課題

### MAM とは

Windows 10 以降、Prefetch ファイルは **MAM 圧縮** という形式で格納されます。MAM ファイルは次の構造です:

```
┌──────────────────────────┐
│ "MAM\x04" magic (4 byte) │   圧縮されている印
│ 圧縮前 size (4 byte)     │
├──────────────────────────┤
│ XPRESS Huffman 圧縮データ │   展開すると通常の Prefetch バイト列になる
└──────────────────────────┘
```

XPRESS Huffman（LZXPRESS Huffman）は、Microsoft が Windows 内部で使っている LZ77 + Huffman 圧縮です。本 Parser は **純 Rust で展開器を実装** し、新たな外部依存 crate を追加しませんでした（roadmap §9 のリスク対策・供給連鎖安全）。

### 「同じ Provenance chain」要件（互換 §4.1）

ここで重要な設計要件があります: **展開後のバイト列を別の Evidence として扱ってはいけません**。圧縮前と圧縮後で別々の証拠 ID を振ると、解析結果の追跡可能性が壊れるからです。

本 Parser の実装はシンプルです:

```rust
let pf_bytes: Vec<u8> = if is_mam(&raw) {
    decompress_mam(&raw)?   // 展開してバイト列を得るだけ
} else {
    raw                      // 非圧縮ならそのまま
};
// ↑ どちらの経路でも、同じ ParseContext（同じ Evidence ID）で Event を生成する
```

展開後の `pf_bytes` を新しい Evidence として登録する処理は一切ありません。Event の `provenance` は常に元の `.pf` ファイル（圧縮されたままの Evidence）を指します。これを `acceptance_tests.rs` の `pf_acceptance_mam_decompression_preserves_provenance_chain` で検証しています。

### XPRESS Huffman の実装範囲

`mam.rs` の展開器は次を扱います:

1. **256 バイトの Huffman 表** を読み、512 個のシンボル（0-255 がリテラル、256-511 がマッチ）の符号長を復元する
2. **canonical Huffman 復号器** を構築する
3. **ビットストリーム** を16-bit リトルエンディアン単位・MSB 先頭で読み、シンボルを復号する
4. リテラルならそのまま出力、マッチなら過去の出力へ戻ってコピー（LZ77）

本 Phase では **リテラルのみの圧縮データで round-trip テスト** を通しています。実 Windows 生成物（マッチを含む）での最終検証は、Phase 8 の fixture 収集時に行います（fixture 収集計画 §3.2）。テスト用の圧縮器（`common/mod.rs` の `compress_literal_only_xpress_huffman`）も実装し、展開器との往復一致を確認しています。

---

## 4. 観測型 Event: 「実行した」と断定しない

### Event type の選び方

Prefetch には実行時刻が記録されています。これをそのまま「プロセス起動（process_start）」Event に変換したくなりますが、**それは禁止されています**（互換 §4.1・規範 §7.1）。

理由は、Prefetch の記録が「実行された事実」ではなく「実行を最適化するために観測した痕跡」だからです。Prefetch サービスが無効化されていれば記録は残りませんし、記録が残っていても実際の起動時刻と厳密に一致するとは限りません。

そこで本 Parser は **`prefetch_execution_observed`** という観測型 Event type を使います:

```rust
// Event type は観測名（実行痕跡を観測した）
event_type: EventType::new("prefetch_execution_observed"),
// assertion は Observed（Parser は原則 Observed のみ生成）
assertion: AssertionKind::Observed,
```

「プロセスが起動した」と断定するのは、他の証拠（EVTX のプロセス起動ログ等）との Correlation で Finding を作る段階です。Parser は観測した事実だけを残します。この設計は LNK Parser の `lnk_timestamp` と同じ方針です（Phase 4 前半を参照）。

### 各実行時刻が1つの Event になる

バージョン 26 以降は最大8個の実行時刻（last run time）が記録されます。本 Parser は **時刻ごとに1つの Event** を生成します。Timeline 上で「最近8回の実行」がそれぞれ独立した項目として現れます。

```text
NOTEPAD.EXE  実行 #0  2026-08-11 10:00:00  ← Event 1
NOTEPAD.EXE  実行 #1  2026-08-11 11:30:00  ← Event 2
NOTEPAD.EXE  実行 #2  2026-08-11 14:15:00  ← Event 3
```

実行時刻が1つも記録されていない場合でも、Prefetch レコードの存在自体を1つの Unknown 時刻 Event として残します（観測事実を捨てないため）。

---

## 5. framework の再利用: Parser 本体は byte 列解読に集中

Phase 4 前半で作った framework（`ArtifactParser` trait・`ParseSink`・`ParseSummary`・panic 捕捉）は、そのまま Prefetch でも使います。Prefetch Parser が新規に作るのは **byte 列を解読する部分だけ** です。

### モジュール構成

```text
crates/parsers/src/prefetch/
├── mod.rs       Parser 本体（ArtifactParser 实现・Event 生成）
├── header.rs    ファイルヘッダ（84 byte）の解析・MAM 検出
├── fileinfo.rs  file information block（version 毎の差吸収）
├── metrics.rs   参照ファイル一覧の取得
├── volume.rs    ボリューム情報の取得
└── mam.rs       MAM 検出 + XPRESS Huffman 展開
```

### FILETIME 変換の再利用

Prefetch の実行時刻は Windows 標準の FILETIME（1601年からの100ナノ秒単位）です。これは LNK Parser と同じ形式なので、`crate::lnk::filetime::filetime_to_datetime` を **そのまま再利用** します。同じ変換ロジックを2箇所へ書く（コピペ）と、片方だけ修正されたときに不整合が起きます。共通関数へまとめるのは Rust の基本作法です。

---

## 6. Provenance と「元レコードへ到達できる」

互換 §12-3 は「Event の Provenance が元レコードへ到達できること」を求めます。本 Parser は各 Event の `record_locator` へ **実行時刻 FILETIME のバイト位置**（バージョンと run index で計算）を設定します。

```rust
// バージョン31の run time[0] は ヘッダ(84) + 44 = offset 128
let run_time_offset = run_time_byte_offset(header.format_version, i);
let record_locator = RecordLocator::ByteRange {
    start: run_time_offset,        // 128
    end: run_time_offset + 8,      // 136
};
```

これにより、Timeline 上の Event から「Prefetch ファイルのこのバイト位置」へ正確に遡れます。解析者が「なぜこの時刻が記録されたのか」を検証するとき、元の `.pf` ファイルの該当オフセットを直接確認できます。

---

## 7. 合成 fixture と acceptance test

### 合成 fixture ビルダ

Phase 4 前半と同様、本 Phase も **合成（hand-crafted）fixture** で検証します（実 Windows 環境の採取は Phase 8）。`tests/common/mod.rs` の `build_prefetch_fixture` が、指定したバージョン・実行時刻・参照ファイル・ボリューム情報から libyal 仕様準拠の `.pf` バイト列を構築します。

各バージョンの正常 fixture（2件以上）・MAM 圧縮 fixture・異常系（truncated・過大 offset・未知 version）を網羅し、互換 §12 の8条件すべてを検証します（`acceptance_tests.rs` の `pf_acceptance_12_*`）。

### Prefetch 単体でも縦割りが通る

Phase 4 前半の M2（LNK だけで Case JSON + Manifest まで通る）と同じ経路が、Prefetch でも通ります（`pf_vertical_slice_prefetch_to_case_jsonl`）。これは framework の再利用性を示す重要な検証です: 新しい Parser を追加しても、Event Store → Timeline → JSONL 出力の経路は一切変更なしで動きます。

---

## まとめ

Phase 4 後半の Prefetch Parser で次を作りました:

- **Prefetch format 解析**（`prefetch/`）: バージョン17〜31の header・file info・metrics・volume を境界安全に読む。
- **MAM 圧縮展開**（`mam.rs`）: 純 Rust の XPRESS Huffman 展開器。新依存 crate なし。展開後 bytes は同じ Evidence として扱う（Provenance chain 保持）。
- **観測型 Event**: `prefetch_execution_observed`。process_start へ断定しない。
- **未知 version の安全 skip**: `TF-W-PREFETCH-UNSUPPORTED-VERSION` issue へ記録。
- **合成 fixture + acceptance test**: 互換 §12 の8条件を Prefetch 版で検証。縦割り（Prefetch → Case JSONL + Manifest）も確認。

framework が据わっているおかげで、Parser 本体は「byte 列解読」と「Event 設計」に集中できました。次のステップは残り5種（USN Journal・EVTX・Registry・Amcache・Jump Lists）です。USN Journal は record-stream 型（1ファイルに多数 record）なので、framework の部分成功サポートが本格的に活躍します。
