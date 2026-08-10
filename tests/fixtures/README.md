# TraceForge fixture 管理方針（T0-012）

> 互換性仕様書 §12-5（fixture SHA-256・生成OS/build・取得方法・期待結果の記録）・
> §12-6（外部仕様 revision・dependency version の記録）に基づく運用規定。

本ディレクトリ `tests/fixtures/` は、Parser と検知エンジンの acceptance test
（互換 §12）で用いる fixture とそのメタデータを管理する。Phase 0 時点では方針と
ディレクトリ構造のみ定義し、実 fixture の収集は `docs/traceforge_fixture_collection_plan_v1.0.md`
（T0-013）に従い Phase 4 までに整備する。

## 1. 配置規則

```
tests/fixtures/
  <artifact_type>/              # lnk / prefetch / usn / evtx / registry / amcache / jump_lists
    <fixture_name>/             # 例: win10_22h2_calc_basic, win11_24h2_calc_mam
      <file>.<ext>              # fixture 本体（例: calc.lnk / NTUSER.DAT）
      manifest.toml             # 当該 fixture のメタデータ（§2）
      expected_events.jsonl     # Parser が生成すべき期待 Event 列（acceptance test 用）
    ...
  README.md                     # 本ファイル（方針）
```

- `artifact_type` は互換性仕様書 §4 の 7 種（Prefetch / EVTX / USN Journal / LNK /
  Jump Lists / Amcache / Registry）に対応するディレクトリ名へ 1:1 で対応させる。
- `fixture_name` は `<生成OS>_<内容>_<バリエーション>` 形式を推奨する
  （例: `win10_22h2_calc_basic`）。バージョン・圧縮有無・異常系を区別できること。
- 1 fixture = 1 ディレクトリ。複数 file を束ねる場合は同一ディレクトリへ格納し、
  `manifest.toml` の `files` で列挙する。

## 2. manifest.toml 記録形式

各 fixture ディレクトリへ必ず `manifest.toml` を配置する。互換 §12-5/6 の全項目を
過不足なく記録する。未設定項目は理由を添えて明記する（黙って省略しない）。

```toml
# fixture 一意名（ディレクトリ名と一致させる）
[fixture]
name = "win10_22h2_calc_basic"
artifact_type = "lnk"

# fixture 本体。1 directory に複数 file を束ねる場合は配列で列挙する。
[[files]]
path = "calc.lnk"
sha256 = "abcdef0123456789..."  # lowercase hex 64 桁
size_bytes = 1234

# 生成環境（互換 §12-5: 生成OS/build）
[origin]
generated_os = "Windows 10 22H2 (Build 19045.3803)"
generated_at = "2024-01-15"           # 任意。実環境の識別性があれば記録
acquisition_method = "デスクトップで calc.exe のショートカットを手動生成後、エクスプローラ経由で取得"
is_synthetic = true                   # true: 合成 / false: 実環境
anonymized = false                    # 実環境の場合はマスキング有無

# acceptance test の期待結果（互換 §12-5: 期待結果）
[test]
expected_events_path = "expected_events.jsonl"
expected_events_sha256 = "fedcba9876..."  # 期待 Event 列の SHA-256
notes = "全 3 Event を生成する。timestamp・path・provenance を検証する。"

# 外部仕様・依存（互換 §12-6: 検証した仕様revision・dependency version）
[reference]
spec_revision = "[MS-SHLLINK] v20240601"
dependency_version = "N/A"            # 外部 crate を使わない場合は N/A と明記
```

### 2.1 必須項目

次は省略不可。互換 §12（acceptance test）の前提となる。

- `fixture.name`, `fixture.artifact_type`
- `files[].path`, `files[].sha256`, `files[].size_bytes`
- `origin.generated_os`, `origin.acquisition_method`, `origin.is_synthetic`
- `test.expected_events_path`, `test.expected_events_sha256`
- `reference.spec_revision`

実環境由来の fixture（`is_synthetic = false`）は `origin.anonymized` も必須。

## 3. 期待 Event 列（expected_events.jsonl）

`expected_events.jsonl` は Parser が当該 fixture から生成すべき Event 列を
TraceForge JSONL envelope（Schema §6）形式で記録する。Phase 4 で Parser を実装する
際、Parser の出力と本 file を比較する acceptance test を作成する。

- 期待 Event 列自体の SHA-256（`test.expected_events_sha256`）を記録し、
  test の再現性を保証する。
- 期待値の改訂時は SHA-256 を再計算して manifest を更新する。

## 4. センシティブデータと .gitignore

- 本ディレクトリの fixture は **合成（synthetic）またはマスキング済み** のみ
  リポジトリへコミットする。実環境の生データはコミットしない。
- ルート `.gitignore` は `*.evtx`, `*.dmp`, `*.vmdk`, `*.raw`, `*.dd`, `*.img` を
  保護対象とし、誤コミットを防止する。
- 合成・マスキング済み fixture をコミットする必要が生じた場合のみ、対象 file を
  `.gitignore` の例外（`!tests/fixtures/.../<file>`）で明示的に許可する。
  例外追加時は、その file がセンシティブ情報を含まないことを review で確認する。
- 実環境 fixture は外部ストレージで管理し、リポジトリには manifest.toml のみを
  配置する（`files[].sha256` 等で実体を間接参照する）。

## 5. 更新運用

- fixture の追加・変更時は、必ず `manifest.toml` と `expected_events.jsonl` を
  同時に更新し、SHA-256 を再計算する。
- 仕様変更（Schema version 等）で期待 Event 列が変わる場合、`spec_revision` と
  `expected_events_sha256` を併せて更新する。
- 廃止 fixture はディレクトリごと削除し、git 履歴で追跡可能にする
  （タスク ID の再利用を禁止するのと同じ理由）。
