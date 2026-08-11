# Phase 2 学習ノート: 証拠を安全に取り込むパイプライン

> 対象読者: Rust で `enum` / `struct` / `trait` / `Result` を一通り書けるレベルの初学者。Phase 1 を読み終えた人。

Phase 2 は **Evidence パイプライン** を実装するフェーズでした。`tf-evidence` crate へ、discovery（証拠の発見）→ snapshot（不変コピー作成）→ SHA-256（完全性計算）→ 識別（Artifact の種別判定）までの一連の流れを実装します。このノートでは、Phase 2 で何を作り、なぜそれが forensics ツールに必要なのかを解説します。

---

## 1. なぜ「元ファイルを直接読まない」のか

### forensics の鉄則: 証拠を変更してはならない

デジタルフォレンジックにおいて、最も重要な原則の1つは「証拠ファイルを解析中に変更してはならない」です。もし解析ツールが証拠ファイルへ書き込んだり、ファイルのタイムスタンプを変更したりすれば、その証拠は法廷での証拠能力を失う可能性があります。

TraceForge はこれを **snapshot 手順**（規範 §5.5）で徹底します。Parser は決して元ファイルを直接読みません。代わりに、元ファイルの不変コピー（snapshot）を作成し、それだけを解析します。

### snapshot 手順の全体像

```text
元ファイル ──読む──→ コピーしながらSHA-256計算 ──→ snapshot（不変）
    │                                              │
    └──before/after metadata比較───               └──Parser はこれを読む
```

手順（規範 §5.5）は次の9ステップです:

1. 元ファイルを読み取り専用 + symlink 非追跡で開く
2. サイズ・更新時刻・ファイル識別子を取得（**before**）
3. private な一時ディレクトリへ snapshot を新規作成
4. 固定長バッファで末尾まで読み、snapshot へ書きながら **同時に** SHA-256 を計算
5. snapshot を flush して読み取り専用で再 open
6. 元ファイルの metadata を再取得（**after**）
7. before ≠ after なら → `ChangedDuringSnapshot`（解析しない）
8. snapshot のサイズと SHA-256 を再検証
9. Parser と YARA-X には同一 snapshot を渡す

この手順により、「解析中に証拠が書き換えられた」ことを確実に検出できます。

---

## 2. source_locator: 場所に依存しない識別子

### 問題: ファイルを移動したら ID が変わってしまう

Phase 1 で、Evidence ID は SHA-256 で決定的に生成すると学びました。Evidence ID の hash 入力には `source_locator`（入力 root からの相対パス）が含まれます（規範 §5.6）。

ここで問題があります。もし絶対パス（`C:\cases\2026-01\Security.evtx` 等）を使ったら、証拠ファイルを別のディレクトリへ移動しただけで Evidence ID が変わってしまいます。同じ証拠なのに、移動前と移動後で別物扱いされてしまいます。

### 解決: 相対パス + 正規化

`source_locator` は入力 root からの **相対パス** です（規範 §5.2）。入力全体を別の場所へ移動しても、相対パスは変わらないため、Evidence ID も安定します。

正規化規則（規範 §5.2）:

| 規則 | 例 |
|---|---|
| separator は `/` へ | `evtx\Security.evtx` → `evtx/Security.evtx` |
| `.` と `..` は禁止（解決ではなく拒否） | `../evil` → Error |
| Unicode は NFC へ正規化 | `A`(U+0041) + ` ``(U+0300) → `À`(U+00C0) |
| 非 UTF-8 byte は `%XX`（大文字）で表現 | `0xFF` → `%FF` |
| 大文字小文字は変更しない | `Security.EVTX` → `Security.EVTX` |

NFC（Normalization Form C）は Unicode の正規化形式の1つで、「合成済み」形式へ統一します。これにより、見た目が同じ文字でも内部表現が異なる場合（例: `À` を1文字で表すか `A` + `̆` の2文字で表すか）を統一できます。

```rust
// crates/evidence/src/source_locator.rs
pub fn normalize_source_locator(relative: &str) -> Result<String, SourceLocatorError> {
    // 1. separator を / へ
    let unified = relative.replace('\\', "/");
    // 2. 絶対パス検出
    if unified.starts_with('/') { return Err(AbsolutePath); }
    // 3. NFC 正規化
    let nfc: String = unified.nfc().collect();
    // 4. . と .. を拒否
    for comp in nfc.split('/') {
        if comp == "." || comp == ".." { return Err(DotOrParentComponent); }
    }
    // 5. / で結合
    Ok(components.join("/"))
}
```

---

## 3. 決定的 discovery: 順序に依存しない

### filesystem の列挙順は当てにならない

OS の `readdir` が返すファイルの順序は、filesystem の実装（ext4、NTFS、FAT...）や状態によって変わります。もし発見順序が解析結果へ影響するとすれば、決定性が壊れます（規範 §13）。

TraceForge は全候補を集めてから `source_locator` の UTF-8 byte 昇順で sort します（規範 §5.3）。これにより、どの OS で走査しても同じ順序になります。

```rust
// crates/evidence/src/discovery.rs
outcome.files.sort_by(|a, b| a.source_locator.cmp(&b.source_locator));
```

### symlink は追跡しない

symlink を追跡すると、loop（自分自身へのリンク等）で無限再帰に陥る危険があります。TraceForge は既定で symlink を全て skip し、`TF-W-DISCOVERY-SYMLINK` Issue を記録します（規範 §2・§5.3）。

```rust
let meta = fs::symlink_metadata(&path)?;  // symlink 自体の metadata
if meta.is_symlink() {
    outcome.symlink_skipped.push(locator);
    continue;  // 追跡しない
}
```

`symlink_metadata` は symlink を **解決せず** symlink 自体の情報を返します。これで `is_symlink()` が true なら、そのエントリは symlink だと分かります。

---

## 4. snapshot: 同時 SHA-256 と before/after 検査

### コピーしながら SHA-256 を計算する

証拠の完全性を保証するため、snapshot を作りながら同時に SHA-256 を計算します（規範 §5.5-4）。これは「2回読む」（1回目はコピー、2回目は hash 計算）ことを避けるためです。2回読むと、間にファイルが変更される可能性があります。

```rust
// crates/evidence/src/snapshot.rs
let mut hasher = Sha256::new();
let mut buffer = vec![0u8; 64 * 1024];  // 64 KiB の固定長バッファ
loop {
    let n = source.read(&mut buffer)?;
    if n == 0 { break; }
    hasher.update(&buffer[..n]);          // SHA-256 へ追加
    snapshot_file.write_all(&buffer[..n])?; // snapshot へ書く
    total_copied += n as u64;
}
let sha256_hex = hex::encode(hasher.finalize());
```

### before/after 検査で書き換えを検出する

snapshot のコピー中に、別プロセス（や攻撃者）が元ファイルを書き換える可能性があります。これを検出するため、コピー前後でファイルの metadata を比較します（規範 §5.5-2/6/7）。

```rust
let before = FileIdentity::from_file(&source)?;  // コピー前
// ... コピー + SHA-256 ...
let after = FileIdentity::from_file(&source)?;   // コピー後

if before != after {
    return Err(ChangedDuringSnapshot { before, after });
    // この Evidence は解析しない
}
```

`FileIdentity` は size・更新時刻・ファイル識別子（Unix なら inode）の3要素を比較します。どれか1つでも変われば、snapshot 中に変更があったと判定します。

### VerifiedSnapshot 以外から Event を生成しない

`ChangedDuringSnapshot` や `SnapshotFailed` の Evidence からは、絶対に Event や YARA Match を生成してはなりません（規範 §5.5）。これにより、「解析中に変わった可能性のあるデータ」が分析結果へ混入することを防ぎます。

---

## 5. 入出力分離: 出力が入力を破壊しないように

### Exit Code 4 で安全に停止する

もし出力ファイルが入力ディレクトリの中にあると、解析結果を書き出すときに入力ファイルを上書きしてしまう危険があります。TraceForge は解析開始前にこれを検査し、Exit Code 4 で停止します（規範 §5.4）。

検査内容:
1. 出力が入力ディレクトリ配下 → 拒否
2. 出力 == 入力ファイル → 拒否
3. 出力が入力と hard link（同一 inode）→ 拒否
4. 出力先が symlink → 常時拒否（`--overwrite` でも）
5. 出力先が既存 + `--overwrite` 未指定 → 拒否

hard link 検出は、Unix では `(device_id, inode_number)` の比較で行います。hard link は同じ inode を共有するため、別名のファイルでも同一ファイルとして検出できます。

---

## 6. Artifact 識別: 拡張子だけでは判定しない

### 拡張子詐欺に騙されない

ファイルの拡張子は簡単に変更できます。`evil.exe` を `innocent.evtx` へリネームすれば、拡張子だけを見るツールは騙されます。

TraceForge は `filename / known path / magic bytes / header structure / parser probe` の組み合わせで識別します（規範 §11）。magic bytes とは、ファイル先頭にある固定バイト列のことで、多くの形式で「署名」として使われます（例: EVTX は `ElfFile\x01`、ZIP は `PK\x03\x04`）。

### ProbeResult の5値

probe は次の5値のいずれかを返します（規範 §11）:

| 値 | 意味 |
|---|---|
| `Confirmed` | この形式であることが確定（magic + structure の両方が一致） |
| `Probable` | この形式の可能性が高いが確定できない（拡張子だけ等） |
| `UnsupportedVersion` | 形式は識別したが対応外の version |
| `NotThisFormat` | この形式ではない |
| `Malformed` | 判定できないほど壊れている |

### 複数 Parser が Confirmed を返した場合

1つの Evidence に対して複数の Parser が `Confirmed` を返すことがあります。例えば `Amcache.hve` は Registry Parser と Amcache Parser の両方の対象です（規範 §5.1）。

この場合、互換性仕様書で許可された組み合わせ（Registry + Amcache）だけを実行し、それ以外は ambiguous として skip します（規範 §11）。

---

## 7. Resource limit: 黙って切り捨てない

### 2種類の limit

TraceForge は大規模な解析でも安全に動作するよう、2種類の limit を管理します（規範 §18）:

- **事前 limit**: 処理開始前に判定できるもの（ファイルサイズ、Rule 数等）
- **逐次 limit**: 1件ずつ増加するもの（Event 数、Match 数等）

逐次 limit は **1件追加する直前** に検査します。これにより、上限を超えてから「後から切り捨てる」のを防ぎます。

### limit 到達時の5動作

limit に到達した場合、次の5つを必ず行います（規範 §18）:

1. 安全な境界で停止する
2. `TF-W-LIMIT-*` Issue を出力する
3. Manifest の `complete` を `false` にする
4. strict limits でなければ Exit Code 1、strict limits なら Exit Code 6
5. **上限を超えた結果を黙って切り捨てない**

特に5番目が重要です。「100万 Event のうち最初の50万だけ出力して、残りを黙って捨てる」ような挙動は許されません。必ず Manifest へ「limit 到達により不完全である」ことを記録します。

---

## 8. Phase 2 の成果物まとめ

`crates/evidence/` に次の6モジュールを実装しました:

| モジュール | ファイル | 役割 |
|---|---|---|
| `source_locator` | `source_locator.rs` | 相対パスの正規化（§5.2） |
| `discovery` | `discovery.rs` | 決定的走査・symlink skip（§5.3） |
| `snapshot` | `snapshot.rs` | 不変コピー + SHA-256 + before/after 検査（§5.5） |
| `io_safety` | `io_safety.rs` | 入出力分離・overwrite 保護（§5.4） |
| `probe` | `probe.rs` | Artifact 識別 framework（§11） |
| `limit` | `limit.rs` | resource limit 管理（§18） |

テストは計79件（unit test 68 + acceptance test 11）。特に規範 §21 の受け入れ条件のうち、Phase 2 対象の4つ（§21-3・§21-4・§21-9・§21-10）を全て自動化 test で検証しています。

### 依存関係の追加

Phase 2 で追加した依存:
- `unicode-normalization`（NFC 正規化、規範 §5.2）
- `sha2`・`hex`（snapshot 中の同時 SHA-256、規範 §5.5）
- `tempfile`（dev-dependency、テスト用一時ディレクトリ）

### 次のフェーズへ

Phase 2 で「証拠を安全に取り込むパイプライン」が完成しました。Phase 3（Event Store と Timeline）では、Parser が生成した Event を決定的に永続化・反復する基盤を作ります。Phase 2 の snapshot と Evidence ID は、Phase 4 の Parser が Event を生成する際の前提となります。
