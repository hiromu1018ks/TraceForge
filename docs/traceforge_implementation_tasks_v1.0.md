# TraceForge 実装タスクリスト v1.0

> Windows Forensic Timeline & Evidence Correlation Engine written in Rust

## 1. 文書情報

| 項目 | 内容 |
|---|---|
| 文書種別 | 実装タスクリスト |
| 製品 | TraceForge |
| バージョン | 1.0 |
| 対象 | v1.0 Stable までの実装タスク、検証タスク、トレーサビリティ |
| 規範性 | 非規範。開発管理上の計画文書。動作・形式の正本は各仕様書 |

フェーズ構成と完了条件の根拠は `traceforge_implementation_roadmap_v1.0.md` を参照する。

## 2. 凡例

- タスク ID: `T<phase>-<number>`。ID は変更しない。追加タスクは末尾へ採番する。
- 状態: `[ ]` 未着手 / `[~]` 進行中 / `[x]` 完了
- 参照列の略号: 製品 = 製品仕様書、規範 = 規範コア仕様書、Schema = Schema仕様書、互換 = 互換性仕様書
- 各タスクの「完了」は、コード実装 + 対応する自動 test の追加・合格を意味する。

---

## 3. Phase 0: プロジェクト基盤

### 3.1 Workspace とツール

- [x] T0-001 Cargo workspace 作成（`core` / `evidence` / `store` / `parsers` / `engines` / `findings` / `export` / `cli` の crate 分割案）
- [x] T0-002 `rust-toolchain.toml` で toolchain version を固定（互換 §11）
- [x] T0-003 CI 構築（fmt / clippy / test / doc の各 job）
- [x] T0-004 cargo-deny 導入（license 一覧・security advisory チェック、互換 §11）
- [x] T0-005 `Cargo.lock` をコミット対象とし、binary crate で pin を徹底（互換 §7・§11）

### 3.2 検証環境

- [x] T0-010 cargo-fuzz 雛形作成（F-025、製品 §13.1）
- [x] T0-011 criterion benchmark 雛形作成（F-026）
- [x] T0-012 fixture 管理方針の策定（配置、SHA-256・生成 OS・取得方法の記録形式、互換 §12-5）
- [x] T0-013 fixture 収集計画の開始（Win 7 SP1 / 10 22H2 / 11 24H2 実環境、互換 §4）

---

## 4. Phase 1: コアデータモデルと Schema

### 4.1 決定的 ID

- [x] T1-001 length-prefixed encoding の実装（規範 §12.2、null = `0xFFFFFFFF`、整数・enum・list の規則）
- [x] T1-002 SHA-256 lowercase hex ユーティリティ（Schema §2.1）
- [x] T1-003 ID 生成器（`tf-case/evidence/artifact/event/match/finding-v1:` prefix、規範 §12.1）
- [x] T1-004 Evidence ID 生成（field 順: literal・locator・size・sha256、規範 §5.6）
- [x] T1-005 Case ID 生成（evidence_id の byte 順 sort 連結、規範 §4.1）
- [x] T1-006 Artifact / Match / Finding ID 生成（規範 §12.4）
- [x] T1-007 Event ID 生成（12 field 順、event_ordinal 対応、規範 §12.3）
- [x] T1-008 ID 決定性 test（同一入力から同一 ID、message 変更で不変）

### 4.2 時刻モデル

- [x] T1-010 `TemporalValue` / `EventTime` 型実装（規範 §6.1）
- [x] T1-011 `TimePrecision` / `TimezoneSource` / `TimestampKind` enum（規範 §6.1、Schema §4）
- [x] T1-012 時刻変換規則実装（offset 変換、Case default / CLI override、元値保持、規範 §6.2）
- [x] T1-013 DST 処理（不存在時刻 Warning、2義的時刻は Range/LocalTime 保持、規範 §6.2）
- [x] T1-014 不明時刻の `Unknown` 化（現在時刻・mtime で補完禁止、規範 §6.2）
- [x] T1-015 IANA timezone 検証（Schema §8.3）
- [x] T1-016 時刻モデル property test（実在日付のみ、UTC 化の可逆的情報保持）

### 4.3 Event と Provenance

- [x] T1-020 `Event` 型実装（規範 §7.1、Schema §5.5）
- [x] T1-021 `AssertionKind`（Observed / Inferred、規範 §7.1）
- [x] T1-022 `ProcessRef` 型実装（規範 §7.2）
- [x] T1-023 `Provenance` / `RecordLocator` 型実装（規範 §7.3）
- [x] T1-024 `attributes` は `BTreeMap` 固定（規範 §13.2）

### 4.4 Windows path

- [x] T1-030 `WindowsPathValue` 型実装（規範 §8）
- [x] T1-031 `windows-path-v1` normalization profile 実装（6規則のみ、規範 §8）
- [x] T1-032 path 正規化 unit test（UNC 保持、case fold、`..` 解決、root 越え禁止）
- [x] T1-033 Evidence 内 path に `PathBuf` を使わないことの lint / review 規約（規範 §8）

### 4.5 Case・Schema 型

- [x] T1-040 `CaseMetadata` 型実装（規範 §4、Schema §5.2）
- [x] T1-041 `EvidenceItem` / `ArtifactInstance` 型実装（規範 §5.1、Schema §5.3–5.4）
- [x] T1-042 Issue 型実装（code・severity・scope、Schema §5.6、規範 §9.3）
- [x] T1-043 Match 型実装（correlation / sigma / yara_x、Schema §5.7）
- [x] T1-044 Finding 型実装（`created_at` 禁止、Schema §5.8、規範 §16）
- [x] T1-045 Manifest 型実装（規範 §20、Schema §5.9）

### 4.6 Schema 検証

- [x] T1-050 canonical JSON serializer（key の UTF-8 byte 順再帰 sort、最短 decimal、Schema §2.1）
- [x] T1-051 JSON Schema validator 導入（Schema §4–§8 の各 Schema）
- [x] T1-052 Case JSON 読み書き（top-level 固定、Schema §5.1）
- [x] T1-053 JSONL envelope（`schema_version` + `record_type`、Schema §6）
- [x] T1-054 version compatibility 規則実装（未知 field の扱い、major version 差 error、Schema §2.3）
- [x] T1-055 Schema fixture 整備（Schema §9 の9種: 最小 valid、全 field valid、必須欠落、major version 差、未知 enum、時刻特殊形、Manifest 欠落、未対応 operator、limit 0/負数）
- [x] T1-056 Schema validation test（全 fixture 合格、Schema §9）

### 4.7 設定

- [x] T1-060 TOML 設定 load（優先順位: CLI > explicit > default > built-in、Schema §8.1）
- [x] T1-061 built-in defaults 実装（Schema §8.2 の全値）
- [x] T1-062 設定 validation（`snapshot_mode=always` のみ、`follow_symlinks=true` は error、limit ≥ 1、Schema §8.3）
- [x] T1-063 resolved configuration の canonical JSON 化 + SHA-256（Schema §8.1）

### 4.8 Error と Exit Code

- [x] T1-070 Error 型階層と Exit Code 対応（規範 §17.2）
- [x] T1-071 Exit Code 優先順位ロジック（`10 > 6 > 5 > 4 > 3 > 2 > 1 > 0`、規範 §17.2）
- [x] T1-072 scope 付き strict mode（`--strict parser/rules/limits/all`、規範 §17.1）

---

## 5. Phase 2: Evidence パイプライン

### 5.1 Discovery

- [x] T2-001 `source_locator` 正規化（`/` separator、`.`/`..` 禁止、NFC、`%XX` escape、規範 §5.2）
- [x] T2-002 決定的列挙（UTF-8 byte 昇順 sort、filesystem 順非依存、規範 §5.3）
- [x] T2-003 symlink skip + `TF-W-DISCOVERY-SYMLINK` 記録（規範 §5.3）
- [x] T2-004 symlink loop 非追跡 test（規範 §21-10）
- [x] T2-005 recursive traversal（既定 ON、深度制限 `max_recursion_depth`、Schema §8.2）
- [x] T2-006 対象外入力の検出・拒否（disk image / container / archive 展開禁止、互換 §3）

### 5.2 Snapshot と hash

- [x] T2-010 read-only・symlink 非追跡 open（規範 §5.5-1）
- [x] T2-011 before/after メタデータ取得（size・mtime・file identity、規範 §5.5-2/6）
- [x] T2-012 private temporary directory への snapshot 作成（規範 §5.5-3、所有者限定権限 §10）
- [x] T2-013 固定長 buffer コピー + 同時 SHA-256（規範 §5.5-4）
- [x] T2-014 snapshot flush + read-only 再 open（規範 §5.5-5）
- [x] T2-015 `ChangedDuringSnapshot` / `SnapshotFailed` 処理（規範 §5.5-7、§5.5 終盤）
- [x] T2-016 snapshot size・SHA-256 再検証（規範 §5.5-8）
- [x] T2-017 `VerifiedSnapshot` 以外から Event/YARA Match を生成しない強制（規範 §5.5）
- [x] T2-018 snapshot 中書換 test で Event 非生成（規範 §21-3）
- [x] T2-019 Parser 読取 bytes と snapshot SHA-256 一致 test（規範 §21-4）

### 5.3 入出力分離

- [x] T2-020 出力 path の入力重複・hard link 検査（Exit Code 4、規範 §5.4）
- [x] T2-021 input directory 内 output 拒否 test（規範 §21-9）
- [x] T2-022 overwrite 既定禁止・`--overwrite` 時のみ通常 file 置換・symlink 常時拒否（規範 §5.4）

### 5.4 Artifact 識別

- [x] T2-030 probe framework（filename / known path / magic / header / parser probe、規範 §11）
- [x] T2-031 `ProbeResult` 5値実装（Confirmed / Probable / UnsupportedVersion / NotThisFormat / Malformed）
- [x] T2-032 複数 Confirmed の許可組合せ管理・ambiguous skip（規範 §11）
- [x] T2-033 Probable のみ既定 skip + Warning（規範 §11）
- [x] T2-034 Evidence → 複数 ArtifactInstance 対応（Amcache hive の例、規範 §5.1）

### 5.5 Resource limit

- [x] T2-040 limit framework（事前 limit は開始前、逐次 limit は追加直前検査、規範 §18）
- [x] T2-041 limit 到達時の5動作（停止・`TF-W-LIMIT-*`・`complete=false`・Exit Code・黙殺禁止、規範 §18）
- [x] T2-042 Schema §8.2 の全 limit 項目の適用点実装
- [x] T2-043 `max_snapshot_total_bytes` 管理（規範 §5.5、Schema §8.2）

---

## 6. Phase 3: Event Store と Timeline

### 6.1 Event Store

- [x] T3-001 length-delimited spool file Event Store 実装（規範 §10）
- [x] T3-002 書き込み時 Schema validation（規範 §10）
- [x] T3-003 Event ID 一意制約（規範 §10）
- [x] T3-004 commit marker（未完了 Case 判別、規範 §10）
- [x] T3-005 最終出力完了まで自動削除しない（規範 §10）
- [x] T3-006 permission を所有者限定（規範 §10）
- [x] T3-007 決定的 iteration（timestamp group + Event ID、規範 §10）
- [x] T3-008 external merge sort（memory budget 超過時、規範 §10）
- [x] T3-009 100万 Event で全件 `Vec` 不使用 test（規範 §21-6）

### 6.2 Timeline

- [x] T3-020 5 group 順序実装（規範 §6.3）
- [x] T3-021 group 内 sort（UTC 昇順 + Event ID、Range 欠損末尾、規範 §6.3）
- [x] T3-022 group をまたぐ因果順序の断定禁止（規範 §6.3）
- [x] T3-023 同一 timestamp の Event ID 安定順 test（規範 §21-8）
- [x] T3-024 不明時刻 Event の Timeline 末尾 group 出力 test（規範 §21-2）
- [x] T3-025 Timeline filter / summary（F-009、F-030）

### 6.3 最小出力（縦割り用）

- [x] T3-030 最小 JSON Case 出力（M2 用、正式版は Phase 7 へ引き継ぐ）
- [x] T3-031 最小 Manifest 出力（run metadata 分離、規範 §13.1）

---

## 7. Phase 4: Parser 群

### 7.1 Parser framework

- [x] T4-001 `ArtifactParser` trait + `ParseSink` trait 実装（sink 型 interface、`Vec` 全件返却禁止、規範 §9.1）
- [x] T4-002 `ParseSummary` / `ParseStatus` 実装（規範 §9.2）
- [x] T4-003 record 破損時の部分成功処理（境界特定可能なら継続、生成済み Event 破棄禁止、規範 §9.2）
- [x] T4-004 Parse Issue 仕様実装（安定 code、巨大値・未 escape 制御文字の排除、出力順、規範 §9.3）
- [x] T4-005 Parser 境界の panic 捕捉 → Fatal 記録 → Exit Code 10（規範 §9.4）
- [x] T4-006 破損中間 record 前後の部分 Event 保持 test（規範 §21-5）
- [x] T4-007 必須 field 欠落 record は Event 化せず Issue 化（互換 §5）

### 7.2 LNK Parser（M2 対象）

- [x] T4-010 Shell Link Header 解析（size・CLSID・flags・timestamps 検証、互換 §4.4）
- [x] T4-011 LinkTargetIDList 解析（境界検証、未知 item raw 保持、互換 §4.4）
- [x] T4-012 LinkInfo 解析（互換 §4.4）
- [x] T4-013 StringData 解析（互換 §4.4）
- [x] T4-014 ExtraData 解析（既知 block + 未知 block skip、互換 §4.4）
- [x] T4-015 timestamp kind と元 field 名の保持（互換 §4.4）
- [x] T4-016 LNK fixture + acceptance test（互換 §12）

### 7.3 Prefetch Parser

- [x] T4-020 format version 検出（17/23/26/30/31、互換 §4.1）
- [x] T4-021 executable 名・run count・run time・volume・参照 file/directory 取得（互換 §4.1・§5）
- [x] T4-022 MAM 圧縮展開（同一 Provenance chain、互換 §4.1）
- [x] T4-023 未知 version skip + `TF-W-PREFETCH-UNSUPPORTED-VERSION`（互換 §4.1）
- [x] T4-024 実行痕跡 Event 化（process start へ断定しない、互換 §4.1）
- [x] T4-025 Prefetch fixture + acceptance test（各 version 正常 2件以上、MAM、異常系、互換 §4.1）

### 7.4 USN Journal Parser

- [x] T4-030 `USN_RECORD_COMMON_HEADER` MajorVersion 検出（互換 §4.3）
- [x] T4-031 USN_RECORD_V2 解析（互換 §4.3）
- [x] T4-032 USN_RECORD_V3 解析（128-bit reference 切詰め禁止、互換 §4.3）
- [x] T4-033 USN_RECORD_V4 解析（range tracking、filename 非前提、互換 §4.3）
- [x] T4-034 rename OLD_NAME/NEW_NAME 結合（同一 reference + 近接 USN + 対応 reason、互換 §4.3）
- [x] T4-035 path reconstruction（同一 Evidence set 内のみ、host 検索禁止、互換 §4.3）
- [x] T4-036 未知 MajorVersion の安全 skip + Warning（互換 §4.3）
- [x] T4-037 USN fixture + acceptance test（互換 §12）

### 7.5 EVTX Parser

- [x] T4-040 file header / chunk / record 境界検証（互換 §4.2）
- [x] T4-041 binxml decoder 実装
- [x] T4-042 record ID・provider・channel・computer・Event ID・EventData/SystemData 保持（互換 §4.2・§5）
- [x] T4-043 typed mapping 5種（4624/4625/4688/4689/7045、channel+provider+必須 field 同時検証、互換 §4.2）
- [x] T4-044 PowerShell Operational / Sysmon Operational 対応（互換 §4.2）
- [x] T4-045 partial chunk・bad checksum・truncated record の部分回復（互換 §4.2）
- [x] T4-046 EVTX fixture + acceptance test（3 OS 世代、4 channel、異常系、互換 §4.2）

### 7.6 Registry Parser

- [x] T4-050 hive 構造解析（nk/vk 等、SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER.DAT/UsrClass.dat、互換 §4.7）
- [x] T4-051 LOG1/LOG2 transaction log replay（replay 成否と log hash 記録、互換 §4.7）
- [x] T4-052 dual view（base / recovered）と Provenance 記録（互換 §4.7）
- [x] T4-053 replay 不可時は `partial` 扱い（互換 §4.7）
- [x] T4-054 観測型 Event（`registry_observation` / `registry_key_last_write`、`registry_set/delete` 禁止、互換 §4.7）
- [x] T4-055 Registry fixture + acceptance test（互換 §12）

### 7.7 Amcache Parser

- [x] T4-060 Win10 22H2 / Win11 24H2 schema family 認識（互換 §4.6）
- [x] T4-061 key family と file/program metadata 保持（互換 §4.6・§5）
- [x] T4-062 `amcache_observation` Event（process start へ断定しない、互換 §4.6）
- [x] T4-063 未知 schema は Warning（Generic Registry へ自動 fallback 禁止、互換 §4.6）
- [x] T4-064 Registry Parser との明示的併用（互換 §4.7）
- [x] T4-065 Amcache fixture + acceptance test（互換 §12）

### 7.8 Jump Lists Parser

- [ ] T4-070 CFB container 解析（AutomaticDestinations、互換 §4.5）
- [ ] T4-071 DestList 解析（未知 version は Warning、互換 §4.5）
- [ ] T4-072 内包 LNK の ArtifactInstance 化（stream 名 + offset を Provenance、互換 §4.5）
- [ ] T4-073 CustomDestinations 解析（互換 §4.5）
- [ ] T4-074 Jump Lists fixture + acceptance test（3 OS 世代、互換 §4.5）

### 7.9 Parser 共通検証

- [ ] T4-090 各 Parser の thread 数 1/複数一致 test（互換 §12-4）
- [ ] T4-091 各 Parser の Provenance 到達 test（互換 §12-3）
- [ ] T4-092 全 Parser fuzz target 作成（F-025）

---

## 8. Phase 5: 検知エンジン

### 8.1 共通

- [ ] T5-001 Rule file 1回読み込み・raw bytes SHA-256・再読込禁止（規範 §14）
- [ ] T5-002 Rule directory 列挙順の正規化（UTF-8 byte 順、規範 §14）
- [ ] T5-003 Rule validation error の Exit Code 5 対応（規範 §17.2）

### 8.2 Sigma

- [ ] T5-010 Sigma YAML parser + TF-SIGMA-1.0 subset validator（互換 §6.1–6.2）
- [ ] T5-011 未対応要素含有 Rule の全体 skip（部分評価禁止、互換 §6.2、規範 §15.1）
- [ ] T5-012 logsource routing（category/product/service/definition、互換 §6.1）
- [ ] T5-013 selection / condition / quantifier 評価器（互換 §6.1）
- [ ] T5-014 string/field/list modifier（contains・startswith・endswith・cased・exists・all、互換 §6.1）
- [ ] T5-015 field mapping 実装（互換 §6.3 表、複数候補の OR 評価禁止）
- [ ] T5-016 Sigma match → Match 型変換（logsource_mapping 保持、Schema §5.7）
- [ ] T5-017 Sigma 未対応構文 skip test（規範 §21-12）

### 8.3 YARA-X

- [ ] T5-020 YARA-X crate pin + Cargo.lock checksum 記録（互換 §7）
- [ ] T5-021 `.yar`/`.yara` file・directory 再帰 load（互換 §7）
- [ ] T5-022 tags/meta/namespace/matched pattern identifier 保持（互換 §7、Schema §5.7）
- [ ] T5-023 compile error 時の file 全体無効化・他 file 継続（規範 §15.2）
- [ ] T5-024 Verified Snapshot のみ scan（実行・load 禁止、規範 §15.2）
- [ ] T5-025 `all / suspicious / explicit` mode（Schema §8.3、規範 §15.2）
- [ ] T5-026 suspicious mode の Evidence ID 解決（host path 推測 scan 禁止、規範 §15.2、§21-13）
- [ ] T5-027 `max_yara_scan_file_size_bytes` 適用（Schema §8.2）

### 8.4 Correlation

- [ ] T5-030 Correlation Rule YAML parser（anchor/alias/custom tag/duplicate key 禁止、Schema §7、規範 §14）
- [ ] T5-031 Correlation Rule Schema validation（Schema §7）
- [ ] T5-032 sequence / step / where / bind 評価器（Schema §7）
- [ ] T5-033 predicate operator 8種（eq/neq/contains/starts_with/ends_with/regex/exists/in、Schema §7）
- [ ] T5-034 `within` 両端含む・`max_correlation_window_seconds` 上限（規範 §14.1、Schema §8.3）
- [ ] T5-035 `partition_by`（case_id/hostname/user、規範 §14.1）
- [ ] T5-036 hostname 不明時の既定非 match（規範 §14.1）
- [ ] T5-037 不確実時刻の既定非 match・`allow_uncertain_time` 明示時のみ許可 + 記録（規範 §6.4）
- [ ] T5-038 null・型の厳密比較（暗黙変換禁止、規範 §14.1）
- [ ] T5-039 未対応 operator の Rule 全体 skip（規範 §14.1）
- [ ] T5-040 match 重複生成禁止・`max_matches` 打ち切り・Exit Code 1/5（規範 §14.2）
- [ ] T5-041 score 計算（base + adjustments、clamp、level 変換、規範 §14.3）
- [ ] T5-042 同一 Evidence 事実の二重加点防止（規範 §14.3）

---

## 9. Phase 6: Finding 統合と ATT&CK

- [ ] T6-001 Finding merger（match 喪失なし、規範 §16）
- [ ] T6-002 自動統合禁止（明示統合 rule のみ、規範 §16）
- [ ] T6-003 Finding 必須 field 実装（severity / confidence / 参照 ID 群、規範 §16）
- [ ] T6-004 `Observed evidence` と `Inference` の分離記述（規範 §16、製品 §10）
- [ ] T6-005 Finding から全元 Event・Evidence への参照検証 test（製品 §10）
- [ ] T6-006 ATT&CK STIX dataset の version pin・SHA-256・取得元記録（互換 §9）
- [ ] T6-007 Technique ID の dataset 存在検証（不在 ID は Rule validation error、互換 §9）
- [ ] T6-008 ATT&CK mapping 生成（Rule / Sigma tag / built-in / manual のみ、規範 §15.3）
- [ ] T6-009 ATT&CK mapping への dataset version + hash 記録（規範 §15.3）

---

## 10. Phase 7: Exporter と CLI

### 10.1 Exporter

- [ ] T7-001 Text exporter（制御文字・ESC の可視 escape、規範 §19.1）
- [ ] T7-002 JSON exporter（Case JSON Schema、Schema §5）
- [ ] T7-003 JSONL exporter（固定出力順、Manifest 必ず最終行、Schema §6）
- [ ] T7-004 CSV exporter（RFC 4180、formula injection 対策 + `csv_sanitized` 記録、規範 §19.2）
- [ ] T7-005 HTML exporter（offline、CSP 埋込、text node escape、外部 request なし、規範 §19.3）
- [ ] T7-006 Timesketch exporter（必須 field、変換不可 Event の除外 + summary 記録 + Exit Code 1、互換 §8）
- [ ] T7-007 JSON/JSONL 出力の UTF-8・LF・NaN/Infinity 禁止（規範 §19.4）
- [ ] T7-008 出力 injection test（CSV formula / terminal ESC / HTML script、規範 §21-11）
- [ ] T7-009 異 Schema major version の自動変換禁止（互換 §10）

### 10.2 CLI

- [ ] T7-020 CLI 骨格（`traceforge <COMMAND> [OPTIONS]`、製品 §12）
- [ ] T7-021 `analyze`（既定 read-only / recursive / SHA-256 / 外部通信なし、規範 §2）
- [ ] T7-022 `--no-hash` を提供しないことの確認（規範 §2）
- [ ] T7-023 `timeline`（表示・filter、製品 §12）
- [ ] T7-024 `correlate`（保存済み Event へ適用、製品 §12）
- [ ] T7-025 `sigma`（保存済み Event へ適用、製品 §12）
- [ ] T7-026 `yara`（明示 Evidence へ適用、製品 §12）
- [ ] T7-027 `export`（Case 変換、製品 §12）
- [ ] T7-028 `rules`（validate・一覧、製品 §12）
- [ ] T7-029 `inspect`（単一 Artifact の安全な概要、製品 §12）
- [ ] T7-030 `version`（tool・Schema・compatibility profile、製品 §12）
- [ ] T7-031 危険 option の警告と Manifest 記録（製品 §12）
- [ ] T7-032 Manifest 確定処理（全必須 field、規範 §20）
- [ ] T7-033 run metadata が分析 determinism へ影響しないことの test（規範 §20）
- [ ] T7-034 stdout = 解析結果、stderr = log、quiet で結果非抑制（規範 §19.1）

---

## 11. Phase 8: 品質保証とリリース

### 11.1 決定性・再現性

- [ ] T8-001 golden determinism test（threads 1/2/自動で canonical JSON byte 一致、規範 §13.3、§21-7）
- [ ] T8-002 分析レコード vs run metadata の同一性比較分離 test（規範 §13.1）
- [ ] T8-003 hash map iteration 順非依存 test（規範 §13.2）
- [ ] T8-004 regression test 基盤

### 11.2 耐性・安全性

- [ ] T8-010 破損 fixture 群での panic 非発生 test（製品 §13.2）
- [ ] T8-011 fuzz campaign 実施・corpus 蓄積（F-025）
- [ ] T8-012 解析中の入力変更を再現する integrity test（製品 §13.1）
- [ ] T8-013 resource limit test（到達時の `complete=false` 含む、規範 §21-14）
- [ ] T8-014 過大 allocation・無限 loop 対策 test（製品 §4.5）
- [ ] T8-015 path traversal 対策 test（製品 §4.5）

### 11.3 互換性・リリース

- [ ] T8-020 全 Required 対象の compatibility acceptance 最終確認（互換 §12 全 8 項目）
- [ ] T8-021 Timesketch import 検証（実 instance または公式 validator、互換 §8）
- [ ] T8-022 Schema validator での全 Golden output 検証（Schema §9）
- [ ] T8-023 benchmark 実測（測定条件付き、製品 §13.2）
- [ ] T8-024 README 例の実 fixture からの自動生成（製品 §13.2）
- [ ] T8-025 dependency・license・advisory 記録の生成（互換 §11）
- [ ] T8-026 参照外部仕様 revision の記録確認（`[MS-SHLLINK]` 等、互換 §12-6）
- [ ] T8-027 release gate checklist 実施（roadmap §8）

---

## 12. 規範 §21 受け入れ条件トレーサビリティ

| # | 受け入れ条件 | 対応タスク |
|---|---|---|
| 1 | timezone 不明 local time を UTC として出力しない | T1-012, T1-014, T8-001 |
| 2 | timestamp 不明 Event の保持と末尾 group 出力 | T1-014, T3-024 |
| 3 | snapshot 中の元 file 書換で Event を生成しない | T2-015, T2-018 |
| 4 | snapshot SHA-256 と Parser 読取 bytes の一致 | T2-019 |
| 5 | 破損中間 record 前後の部分 Event 保持 | T4-003, T4-006, T4-045 |
| 6 | 100万 Event で全件 `Vec` 不要求 | T3-001, T3-009, T4-001 |
| 7 | threads 1/2/自動で canonical 出力 byte 一致 | T8-001 |
| 8 | 同一 timestamp の Event ID 安定順 | T3-021, T3-023 |
| 9 | input directory 内 output 拒否 | T2-020, T2-021 |
| 10 | symlink loop 非追跡 | T2-003, T2-004 |
| 11 | CSV formula / terminal ESC / HTML script の安全出力 | T7-001, T7-004, T7-005, T7-008 |
| 12 | 未対応 Sigma 構文 Rule の全体 skip | T5-011, T5-017 |
| 13 | YARA-X suspicious mode の host path 推測 scan 禁止 | T5-026 |
| 14 | limit 到達時 `complete=false` | T2-041, T8-013 |
| 15 | JSON / JSONL / Rule / Config の Schema validation | T1-051, T1-056, T5-031, T8-022 |

## 13. 運用規則

- タスク完了時は checkbox を `[x]` とし、対象 Parser・機能の acceptance 記録（fixture SHA-256 等）を fixture 管理方針に従って残す。
- 仕様変更でタスクが無効化した場合は削除せず `~~取消線~~` と理由を残す。
- タスクの追加は各フェーズ末尾へ連番で行い、ID の再利用はしない。
- マイルストーン判定時は、対象フェーズのタスクがすべて `[x]` であることを確認する。
