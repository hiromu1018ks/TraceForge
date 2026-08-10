# TraceForge fixture 収集計画 v1.0（T0-013）

> Windows Forensic Timeline & Evidence Correlation Engine

## 1. 文書情報

| 項目 | 内容 |
|---|---|
| 文書種別 | fixture 収集計画 |
| 製品 | TraceForge |
| バージョン | 1.0 |
| 対象 | Phase 4（Parser 群）の acceptance test に必要な fixture の収集計画 |
| 規範性 | 非規範。開発管理上の計画文書。動作・形式の正本は各仕様書 |

Phase 0（T0-013）では実 Windows 環境の調達を要するため、本計画の文書化までを行う。
実収集は Phase 4 の各 Parser 実装着手時に随時実施する（roadmap §7: fixture 収集は
Phase 0 から全期間で並行実施）。管理方針は `tests/fixtures/README.md`（T0-012）に従う。

## 2. 対象 OS

互換性仕様書 §4（Artifact Compatibility Matrix）の対象 OS 3 世代を基本とする。

| OS | build | 主な位置づけ |
|---|---|---|
| Windows 7 SP1 | 7601 | レガシ形式（Prefetch v17 等）の検証 |
| Windows 10 22H2 | 19045 | 広く普及する世代。主要検証対象 |
| Windows 11 24H2 | 26100 | 最新世代。新 schema（Amcache 等）の検証 |

各 OS はクリーンインストール状態の VM を基本とし、意図した操作のみを行った
検証用環境を構築する。物理機は、VM では再現困難な形式が発生する場合に限り使用する。

## 3. 対象 artifact と収集要件

互換性仕様書 §4 の 7 種について、各 OS で正常系（複数バリエーション）と異常系を収集する。
各 Parser の acceptance test 完了条件（互換 §12 全 8 項目）を満たすため、
正常系は各 version につき 2 件以上、異常系（truncated / invalid length /
unknown version）を各 Parser につき 1 件以上とする。

### 3.1 LNK（互換 §4.4）

- 正常系: ショートカットの target 別（ローカル file / UNC / 実行 file）。
  ExtraData の種類（EnvironmentVariables / KnownFolderLocation 等）を網羅。
- 異常系: header size 不正・CLSID 不正・StringData の codepage 境界破損。
- 外部仕様: `[MS-SHLLINK]` revision を manifest の `reference.spec_revision` へ記録。

### 3.2 Prefetch（互換 §4.1）

- 正常系: version 17/23/26/30/31 を各 OS で採取。MAM 圧縮有無の両方。
- 異常系: 未知 version・header size 不正・MAM 展開失敗。
- 注意: version 17 は Win7、30/31 は Win10/11 で主流。MAM は Win10 以降。

### 3.3 EVTX（互換 §4.2）

- 正常系: 3 OS 世代 × 主要 channel（System / Security / Application /
  PowerShell Operational / Sysmon Operational / Microsoft-Windows-...）。
  typed mapping 対象の Event ID（4624/4625/4688/4689/7045）を含むこと。
- 異常系: chunk checksum 不正・truncated record・partial chunk。

### 3.4 USN Journal（互換 §4.3）

- 正常系: V2 / V3 / V4 を含む。rename 結合検証用に OLD_NAME/NEW_NAME 連続 record。
- 異常系: MajorVersion 未知・record length 不正・truncated。

### 3.5 Registry（互換 §4.7）

- 正常系: SYSTEM / SOFTWARE / SAM / SECURITY / NTUSER.DAT / UsrClass.dat の各 hive。
  LOG1/LOG2 の transaction log も併採取（dual view 検証）。
- 異常系: hive header 不正・LOG の replay 失敗を意図的に起こしたもの。

### 3.6 Amcache（互換 §4.6）

- 正常系: Win10 22H2 / Win11 24H2 の各 schema family。
- 異常系: 未知 schema（Generic Registry への自動 fallback 禁止の検証用）。

### 3.7 Jump Lists（互換 §4.5）

- 正常系: AutomaticDestinations（CFB + DestList + 内包 LNK）・
  CustomDestinations。3 OS 世代で採取。
- 異常系: DestList 未知 version・CFB 構造破損。

## 4. 収集手順の基本方針

各 artifact の収集手順は、Phase 4 で当該 Parser を実装する際に詳細化する。
本計画では共通方針のみ定める。

1. **再現性**: 収集環境の OS build・更新プログラム・操作手順を記録し、
   第三者が同一環境を再構築できること。
2. **合成優先**: 可能な限り合成（clean VM で意図的操作）により生成する。
   実環境由来の fixture は `anonymized = true` とし、個人識別情報を除去する。
3. **SHA-256 の即時記録**: 収集直後に SHA-256 を計算し、
   `manifest.toml` へ記録する（`tests/fixtures/README.md` §2）。
4. **外部仕様 revision の固定**: 各 artifact が依存する外部仕様
   （`[MS-SHLLINK]` 等）の revision を記録する（互換 §12-6）。

## 5. センシティブデータの扱い

- fixture に個人情報・実環境の識別情報が含まれる場合、必ずマスキングする
  （ユーザ名・ホスト名・ファイルパス・SID 等）。
- マスキングは、Parser の解析結果へ影響しない範囲で行う
  （例: ユーザ名を `USER01` へ一括置換し、path 構造は保持）。
- マスキング困難な実環境データはリポジトリへコミットせず、外部ストレージで管理し、
   リポジトリには manifest のみ残す（T0-012 §4）。

## 6. 収集タイムライン

| Phase | 収集目安 | 根拠 |
|---|---|---|
| 0（本計画） | 文書化のみ | T0-013。実環境調達を要するため |
| 1–3 | 対象外 | Parser 未実装のため fixture の期待値を定められない |
| 4 | 各 Parser 着手時に正常系 2 件以上・異常系 1 件以上 | 互換 §12（acceptance 全 8 項目）|
| 5–6 | 検知エンジン検証用に追加（Sigma/Correlation が hit する Event を含む EVTX 等） | 検知エンジンの acceptance |
| 8 | fuzz corpus・regression 用の変種を拡充 | 製品 §13.2（release gate）|

## 7. 検証記録の保存

収集した fixture と期待値は、`tests/fixtures/README.md` の配置規則に従い
リポジトリへ反映する。acceptance test の実行結果（通過状況）は、各 Parser の
タスク（T4-016 等）の完了報告で記録する。外部仕様 revision と dependency version の
最終確認は Phase 8（T8-026）で実施する。
