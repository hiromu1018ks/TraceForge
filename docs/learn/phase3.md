# Phase 3 学習ノート: Event Store と Timeline

> 対象読者: Rust で `enum` / `struct` / `trait` / `Result` / `Iterator` を一通り書けるレベルの初学者。Phase 2 を読み終えた人。

Phase 3 は **Event Store と Timeline** を実装するフェーズでした。`tf-store` crate へ、Parser が生成した Event を決定的に永続化し、時刻順に並べる基盤を実装します。このノートでは、Phase 3 で何を作り、なぜそれが forensics ツールに必要なのかを解説します。

---

## 1. なぜ「全 Event をメモリに載せない」のか

### 問題: 100万 Event を `Vec` で持つと OOM する

Windows フォレンジックでは、EVTX ログ1つから数万〜数十万の Event が生成されます。1つの Case で複数の Evidence を解析すると、轻松に100万 Event を超えます。

各 Event は JSON に直列化すると数百 byte 〜 数 KB になります。100万 Event × 1 KB = **約 1 GB**。これを `Vec<Event>` でメモリに載せると、メモリ不足（OOM）で解析が crash する可能性があります。

### 解決: Event Store へ逐次保存・逐次読取

TraceForge は **Event Store**（規範 §10）でこの問題を解決します。Event を1件生成するたびに **spool file**（不変のバイナリファイル）へ追記し、必要な時に1件ずつ読み出します。

```text
Parser ──1件ずつ──→ EventStore ──書込──→ spool file（不変）
                                            │
Timeline出力 ←──1件ずつ── EventStore ←──読出──┘
```

重要なのは、API が `Vec<Event>` を返さないことです。代わりに **`Iterator<Event>`** を返します。これにより、呼出側は1件ずつ処理でき、全件をメモリに保持する必要がありません（規範 §21-6）。

### spool file の形式

spool file は **length-delimited binary**（長さ区切りバイナリ）形式です:

```text
magic: "TFES"（4 byte）── TraceForge Event Store の識別子
format_version: 1（1 byte）
records: 繰り返し {
  record_kind: 1 byte
    0x01 = Event
    0x02 = Commit marker
  payload_len: 4 byte big-endian ── 次の payload の byte 数
  payload: payload_len byte ── Event なら canonical JSON の UTF-8 bytes
}
```

なぜ JSON 行（JSONL）ではなく length-delimited なのか？ → JSON が途中で壊れても、length prefix が一致しなければ**安全に境界を検出**できるからです。改行文字を含む文字列でも壊れません。

---

## 2. Event Store が満たす6つの要件

規範 §10 は Event Store に6つの要件を課します:

| # | 要件 | 実装 |
|---|---|---|
| 1 | Event ごとの Schema validation | `store_event` で EventTime の JSON Schema 検証 + 必須 field 確認 |
| 2 | Event ID 一意制約 | `BTreeSet<String>` で重複を検出 |
| 3 | commit marker | 専用の record kind（`0x02`）。無ければ未完了 Case |
| 4 | 決定的 iteration | Timeline 5 group 順 + Event ID で sort |
| 5 | 最終出力完了まで自動削除しない | `Drop` でファイルを残す |
| 6 | permission を所有者限定 | Unix では `0o600`（所有者のみ読み書き可能） |

### commit marker: 「完了」と「途中停止」の区別

解析中に停電や crash が起きた場合、spool file は途中で切れた状態で残ります。この「未完了」を検出する仕組みが **commit marker** です。

```text
全 Event 書込み完了 → commit() → commit marker を書く
                                  ↓
                 再開時に commit marker があれば「完了」
                 無ければ「途中で止まった未完了 Case」
```

EventStore を開いた時に commit marker が無ければ、その Case は信頼できません（規範 §10）。

### permission を所有者限定

Event Store には解析の過程（どの証拠からどの Event が生成されたか等）が全て記録されます。これは調査の秘密情報です。他のユーザーから読めないように、ファイル permission を所有者だけに制限します（規範 §10）。

- **Unix**: `0o600`（所有者のみ読み書き可能、グループ・他人はアクセス不可）
- **Windows**: 標準ライブラリでは ACL（アクセス制御リスト）を操作できません。親ディレクトリが user private（`tempfile` 等）であることを前提とします。

---

## 3. Timeline の5グループ: 時刻の確実性で並べる

### 問題: 「時刻が不明な Event」をどこに置くか

Phase 1 で学んだ通り、Event の時刻は単一の `DateTime<Utc>` ではなく、`EventTime` / `TemporalValue` で「時刻の意味」を保持します。これには4種類あります:

```rust
enum TemporalValue {
    UtcInstant { value: DateTime<Utc> },         // UTC で確定
    LocalTime { value, timezone: Option<String> }, // local time（timezone あり・なし）
    Range { start: Option, end: Option },         // 区間
    Unknown,                                       // 時刻不明
}
```

「2024-01-15T12:00:00 Asia/Tokyo」と「時刻不明」をどう並べるか？ 比較不能なものを無理に順序付けすると、誤った因果関係を暗示してしまいます。

### 解決: 5グループへ分けて、グループ内だけ順序付ける

規範 §6.3 は Timeline を次の5グループ順へ出力すると定めます:

```text
グループ1: UtcInstant および UTC へ確定変換できた時刻
グループ2: timezone 付きだが UTC へ変換できなかった LocalTime（DST 曖昧等）
グループ3: timezone 不明の LocalTime
グループ4: Range
グループ5: Unknown
```

各グループ内の並び:

| グループ | 並び順 |
|---|---|
| 1 | UTC timestamp 昇順 → 同一なら Event ID 昇順 |
| 2 | timezone 文字列 → local value → Event ID |
| 3 | local value → Event ID |
| 4 | start → end → Event ID（欠損境界は末尾） |
| 5 | Event ID 昇順のみ |

### グループをまたぐ因果関係を断定しない

これが最も重要です。グループ5（Unknown）の Event がグループ1（UTC）より「後」に並んでも、それは「時刻が後だった」という意味ではありません。**比較不能な時刻を、表示のために無理に順序付けしただけ**です（規範 §6.3）。

TraceForge は「時刻が不明な Event」の因果関係を勝手に推測しません。これが Phase 1 で学んだ「時刻の不確実性を隠さない」設計の具体形です。

### DST（サマータイム）の扱い

LocalTime で timezone が分かっていても、DST の境界では時刻の解釈が2通りになったり、存在しない時刻になったりします:

- **2024-11-03 01:30 America/New_York** → DST 切替で2通りに解釈可能（Ambiguous）
- **2024-03-10 02:30 America/New_York** → spring forward で存在しない時刻（NonExistent）

これらは UTC へ**確定変換できない**ため、グループ2へ留まります。一方、DST の無い `Asia/Tokyo` は常にグループ1へ昇格できます。

---

## 4. external merge sort: メモリに載りきらない時の sort

### 問題: 100万 Event を sort するには？

Timeline 順で Event を出力するには sort が必要です。しかし、100万 Event をメモリに載せて sort すると OOM のリスクがあります。

規範 §10 は「Timeline sort は memory 内 sort だけに依存してはならない」と明記しています。

### 解決: ファイルへ分割して sort する

**external merge sort**（外部マージソート）を使います:

```text
spool file（100万 Event）
    │
    ├── chunk 1（メモリに載る量）→ sort → run file 1
    ├── chunk 2（メモリに載る量）→ sort → run file 2
    └── ...（メモリ budget に応じて分割）
         │
         k-way merge（全 run file の先頭を比較して最小から取り出す）
         │
         Timeline 順の出力（Iterator で1件ずつ）
```

実装のポイント:

1. spool file のサイズが memory budget 以下 → in-memory sort（高速）
2. 超過時 → external merge sort へ切り替え（安全）

どちらの場合も `Iterator<Item = Event>` を返すため、呼出側は Vec を必要としません（規範 §21-6）。

### min-heap（最小ヒープ）による k-way merge

複数の run file を同時に開き、それぞれの先頭 Event を比較して最小のものから取り出します。この「最小を素早く見つける」データ構造が **min-heap**（最小ヒープ）です。

```text
run file 1 の先頭: 2026-01-01T00:00:00Z  ← 最小！
run file 2 の先頭: 2026-06-15T12:00:00Z
run file 3 の先頭: 2026-03-20T08:30:00Z
```

min-heap は「一番小さい要素」を O(log n) で取り出せます。取り出したら、その run file から次の Event を読んで heap へ戻します。これを全 run file が空になるまで繰り返します。

---

## 5. 最小出力: Event Store から Timeline 順へ streaming

### Schema §6 の出力順

JSONL 出力は Schema §6 が定める固定順に従います:

1. `case`（Case 情報）
2. `evidence`（evidence_id 昇順）
3. `artifact`（artifact_id 昇順）
4. **`event`（Timeline 順・EventStore から streaming）**
5. `issue`（規範 §9.3 順）
6. `match`（match_id 昇順）
7. `finding`（Severity 降順・finding_id 昇順）
8. `manifest`（必ず最終行）

Phase 3 では、event 行を EventStore の `iter_sorted()` から1件ずつ読み出し、逐次ファイルへ書き出します。これにより、100万 Event でも出力時に全件をメモリに保持しません。

### run metadata の分離（規範 §13.1）

Manifest には「解析の開始時刻」「終了時刻」「プロセス ID」などの **run metadata** が入ります。これらは実行のたびに変わるため、解析結果の同一性比較（golden test 等）から除外します（規範 §13.1）。

Event 行へこれらの run metadata が混入しないよう、Manifest へ分離して保持します。

---

## 6. Timeline filter / summary

### filter（F-009、F-030）

Timeline から特定の条件に合致する Event だけを取り出せます:

- **時刻範囲**: UTC instant グループのみへ適用（比較可能な時刻だけを絞り込む）
- **Event type**: 指定した種別の Event だけを表示
- **hostname**: 指定した host の Event だけを表示

### summary（F-009）

Timeline 全体の統計情報（各グループの件数等）を提供します:

```rust
struct TimelineSummary {
    utc_instant: u64,              // グループ1の件数
    local_time_with_timezone: u64, // グループ2
    local_time_unknown_timezone: u64, // グループ3
    range: u64,                    // グループ4
    unknown: u64,                  // グループ5
}
```

これにより、「解析結果の時刻の確実性」を一目で把握できます。

---

## 7. Phase 3 の成果物まとめ

`crates/store/` に次の5モジュールを実装しました:

| モジュール | ファイル | 役割 |
|---|---|---|
| `store` | `store.rs` | spool file EventStore（規範 §10） |
| `timeline` | `timeline.rs` | 5グループ順序・filter・summary（規範 §6.3） |
| `external_sort` | `external_sort.rs` | external merge sort（規範 §10） |
| `output` | `output.rs` | 最小 JSONL・Manifest 出力（Schema §6） |
| `error` | `error.rs` | Event Store と出力の Error 型 |

テストは計47件（unit test 39 + acceptance test 8）。特に規範 §21 の受け入れ条件のうち、Phase 3 対象の3つを全て自動化 test で検証しています:

- **§21-2**: timestamp 不明 Event の末尾 group 出力
- **§21-6**: 大規模 Event で Vec 不要（Iterator interface）
- **§21-8**: 同一 timestamp の Event ID 安定順

### 依存関係の追加

Phase 3 で追加した依存:
- `tf-core`（Phase 1 のコアデータモデルを再利用）
- `serde_json`（canonical JSON 直列化・復元）
- `chrono`（EventTime 復元時の DateTime parse）
- `thiserror`（Error 型 derive）
- `tempfile`（dev-dependency、テスト用一時ディレクトリ）

### 次のフェーズへ

Phase 3 で「Event を決定的に永続化・Timeline 順で反復する基盤」が完成しました。Phase 4（Parser 群）では、いよいよ実際の証拠形式（LNK・Prefetch・EVTX 等）を解析して Event を生成します。Parser が生成した Event は `ParseSink` 経由で EventStore へ逐次保存され、Timeline 順で出力されます。Phase 3 の EventStore と TimelineKey は、Phase 4 の Parser フレームワークの前提となります。
