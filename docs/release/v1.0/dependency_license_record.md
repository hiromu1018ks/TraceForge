# Dependency・License・Advisory 記録（T8-025・互換 §11）

## 方針

互換性仕様書 §11 は各 release へ次を保存することを定める:

- `Cargo.lock`
- Rust toolchain version
- 直接・間接 dependency version
- dependency license 一覧
- parser・Sigma・YARA-X 関連 dependency の security advisory 確認結果

GPL等、配布形態へ影響する licenseを採用する場合は release 前に明示する。version range だけで再現性を主張してはならない。

## Rust toolchain

| 項目 | 値 |
|---|---|
| Rust | 1.97.1（`rust-toolchain.toml` 固定） |
| edition | 2024 |
| Cargo.lock | コミット済み（再現性を保証） |

## 直接依存（workspace）

`Cargo.toml` `[workspace.dependencies]` へ一元管理する各依存の version は `Cargo.lock` へ pin される。

| dependency | version | 用途 | 許可ライセンス |
|---|---|---|---|
| sha2 | 0.10 | SHA-256 digest（規範 §12・Schema §2.1） | MIT OR Apache-2.0 |
| hex | 0.4 | lowercase hex 変換 | MIT OR Apache-2.0 |
| serde | 1 | canonical JSON・Schema derive | MIT OR Apache-2.0 |
| serde_json | 1 | canonical JSON 構築・Case JSON | MIT OR Apache-2.0 |
| jsonschema | 0.23 | Schema 検証（Draft 2020-12・外部通信なし） | MIT OR Apache-2.0 |
| chrono | 0.4 | 時刻モデル（規範 §6・Schema §4） | MIT OR Apache-2.0 |
| chrono-tz | 0.10 | IANA timezone・DST 処理 | MIT OR Apache-2.0 |
| toml | 0.8 | TOML 設定 load（Schema §8） | MIT OR Apache-2.0 |
| thiserror | 1 | Error 型 derive（規範 §17） | MIT OR Apache-2.0 |
| proptest | 1 | property test | MIT OR Apache-2.0 |
| unicode-normalization | 0.1 | Unicode NFC 正規化（規範 §5.2） | MIT OR Apache-2.0 |
| yara-x | 1.19 | ファイルパターン scan（互換 §7） | BSD-3-Clause |
| regex | 1 | 正規表現 matcher（Schema §7 `regex` operator） | MIT OR Apache-2.0 |
| criterion | 0.5 | benchmark（dev-dependency） | MIT OR Apache-2.0 |
| tempfile | 3 | テスト用一時 directory（dev-dependency） | MIT OR Apache-2.0 |
| libfuzzer-sys | 0.4 | fuzz target（fuzz crate） | MIT OR Apache-2.0 |

## 各 crate の直接依存

`cargo tree --depth 1 --edges normal` の出力から抜粋:

### tf-cli（最終統合 point）

```
tf-cli v0.1.0
├── chrono v0.4.45
├── hex v0.4.3
├── serde_json v1.0.151
├── sha2 v0.10.9
├── tempfile v3.27.0
├── tf-core v0.1.0
├── tf-engines v0.1.0
├── tf-evidence v0.1.0
├── tf-export v0.1.0
├── tf-findings v0.1.0
├── tf-parsers v0.1.0
├── tf-store v0.1.0
└── thiserror v1.0.69
```

tf-cli は全 tf-* crate へ依存し、外部 CLI crate（clap 等）を使用しない。

## ラセンス検証（cargo-deny）

`cargo deny check licenses` の結果: **licenses ok**

許可ライセンス（`deny.toml` `[licenses] allow`）:

- MIT / MIT-0（MIT No Attribution）
- Apache-2.0 / Apache-2.0 WITH LLVM-exception
- BSD-2-Clause / BSD-3-Clause
- ISC
- Unicode-3.0 / Unicode-DFS-2016
- Zlib
- 0BSD
- CC0-1.0

copyleft（GPL 等）は配布形態へ影響するため、既定で拒否する。TraceForge 自体の license は別途決定するまで各 crate へ宣言しない（`private = { ignore = true }`）。

## security advisory 検証（cargo-deny）

`cargo deny check advisories` の結果: **advisories ok**

yara-x v1.19 の間接依存に起因する2件の advisory を例外登録する（`deny.toml` `[advisories] ignore`）:

| advisory ID | 対象 crate | 影響 | 例外の理由 |
|---|---|---|---|
| RUSTSEC-2023-0071 | rsa 0.9.10 | Marvin Attack（timing side-channel） | offline forensic tool では network timing 観測不可。yara-x v1.19.0 が間接依存（pe/macho/dotnet module の署名検証用） |
| RUSTSEC-2026-0222 | wasmtime 43.0.2 | type indices mixing（複数 engine 間の型混同） | yara-x 内部の単一 engine 使用のみ。yara-x v1.19.0 が wasmtime 43.0.2 へ hard-pin しており個別 update 不可 |

両 advisory とも本プロジェクトの脅威モデル（offline forensic tool・外部通信なし・信頼できない Rule は読込前に compile error 処理）へ影響しない。yara-x の更新で解消予定。

yanked crate は deny（再現性を損なうため）。unmaintained は workspace 直依存のみ error とし、transitive な停止報告は警告に留める。

## 結論

TraceForge v1.0 の依存は全て許可ライセンスへ適合し、security advisory は例外登録済みの2件を除いて問題ない。Cargo.lock への pin と cargo-deny により再現性と供給連鎖安全を担保する。
