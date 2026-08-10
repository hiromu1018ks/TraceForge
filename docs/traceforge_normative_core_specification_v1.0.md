# TraceForge 規範コア仕様書 v1.0

## 1. 目的と適用範囲

本書はTraceForge v1.0の実装が守る動作を定義する。実装者は、本書に記載されていない動作を推測で補ってはならない。未定義の入力または未対応の形式は、対応済みとして処理せず、明示的にskipまたはerrorとする。

### 1.1 規範語

| 規範語 | 意味 |
|---|---|
| MUST / 必須 | 守らなければv1.0準拠ではない |
| MUST NOT / 禁止 | 実行してはならない |
| SHOULD / 推奨 | 特別な理由がない限り守る。守らない理由を文書化する |
| MAY / 任意 | 実装してもよい。実装有無を互換性仕様書へ記録する |

### 1.2 文書の優先順位

1. TraceForge Schema仕様書 v1.0
2. 本書
3. TraceForge 互換性仕様書 v1.0
4. TraceForge 製品仕様書 v1.0

Schemaと本書が矛盾する場合、出力形式についてはSchemaを優先し、動作については本書を優先する。矛盾そのものはrelease blockerとして修正する。

## 2. 既定の安全プロファイル

`traceforge analyze`は、optionを指定しなくても次の既定値を使用しなければならない。

| 項目 | 既定値 |
|---|---|
| Evidence open mode | read-only |
| Evidence snapshot | always |
| SHA-256 | mandatory |
| Directory traversal | recursive |
| Symlink | skipしてWarning |
| External network access | disabled |
| Output overwrite | disabled |
| Unknown timezone | UTCへ変換しない |
| Unsupported format/version | skipしてWarning |
| Unsupported rule syntax | rule全体をskipしてWarning |
| Parser panic | process全体をabortし、Exit Code 10 |
| Recoverable record error | 他recordの解析を継続 |
| Thread count | logical CPU数とresource limitから自動決定 |
| HTML dependencies | localに埋め込み、外部CDNを使用しない |

SHA-256はEvidence ID、Provenance、再現性に必要なため、v1.0の`analyze`は`--no-hash`を提供してはならない。

## 3. 正式パイプライン

実装は次の処理順を守らなければならない。

1. 設定を読み込み、CLIで上書きし、resolved configurationを確定する。
2. 入力と出力のpathを検証する。
3. Evidence候補を決定的な順序で列挙する。
4. 各Evidenceをread-onlyで開き、不変snapshotを作成しながらSHA-256を計算する。
5. Artifactを識別し、対応Parserへsnapshotを渡す。
6. ParserがEventとParse Issueをstreaming出力する。
7. Eventを決定的IDでEvent Storeへ保存する。
8. Event Storeを入力としてTimeline、Sigma、Correlationを実行する。
9. Evidence snapshotを入力としてYARA-Xを実行する。
10. Sigma、Correlation、YARA-XのmatchをFindingへ統合する。
11. 明示されたルールに基づきATT&CKをmappingする。
12. Analysis Manifestを確定し、指定形式へexportする。

Sigma、Correlation、YARA-Xは相互の入力を暗黙に変更してはならない。Finding Mergerだけがmatchを統合する。

## 4. Case

Caseは1回の分析単位である。

```rust
struct CaseMetadata {
    case_id: String,
    external_case_id: Option<String>,
    name: String,
    analyst: Option<String>,
    description: Option<String>,
    default_timezone: Option<String>,
    tags: Vec<String>,
}
```

### 4.1 Case ID

Case IDは常に次の決定的形式を使用する。利用者側の管理番号は`external_case_id`へ保存し、Case IDへ使用してはならない。

```text
tf-case-v1:<lowercase SHA-256 hex>
```

hash入力は、Evidence snapshot検証完了後の`evidence_id`をbyte順でsortし、後述のlength-prefixed encodingで連結したものとする。Case名、external case ID、analyst、実行時刻、絶対pathはhashへ含めてはならない。

Case metadataの`created_at`に相当する実行時刻は、分析結果ではなくAnalysis Manifestの`run_started_at`へ保存する。

## 5. Evidence、Artifact、Snapshot

### 5.1 モデル分離

物理ファイルと、そのファイルから検出されたArtifactを分離する。

```rust
struct EvidenceItem {
    evidence_id: String,
    source_locator: String,
    size: u64,
    sha256: String,
    integrity_status: IntegrityStatus,
    snapshot_locator: String,
}

struct ArtifactInstance {
    artifact_id: String,
    evidence_id: String,
    artifact_type: ArtifactSource,
    parser_id: String,
    parser_version: String,
    detection_reasons: Vec<String>,
}
```

1つのEvidenceから複数のArtifactInstanceを生成してよい。例としてAmcache hiveは`Registry`と`Amcache`の両Parser候補になり得る。

### 5.2 Source locator

`source_locator`は入力rootからの相対pathでなければならない。OS上の絶対pathを使用してはならない。

- separatorは`/`へ正規化する。
- `.`と`..`を含めてはならない。
- UnicodeはNFCへ正規化する。
- UTF-8へ変換できないbyteは、各byteを大文字hexの`%XX`で表現する。
- 大文字小文字は変更しない。

これにより、入力directory全体を別の場所へ移動してもIDが変化しない。

### 5.3 Discovery順序

Evidence候補は`source_locator`のUTF-8 byte列を昇順sortしてから処理する。filesystemが返す列挙順を使用してはならない。

入力root配下のsymlinkは既定で追跡せず、`TF-W-DISCOVERY-SYMLINK`を記録する。symlink追跡を有効にする高度なoptionを実装する場合も、root外への移動、loop、depth、file countを検査しなければならない。

### 5.4 入出力分離

出力pathは、入力fileそのもの、入力directory配下、または入力と同一file identityを持つhard linkであってはならない。該当する場合は解析開始前にExit Code 4で停止する。

既存出力を上書きしてはならない。利用者が`--overwrite`を指定した場合だけ、通常fileへの置換を許可する。出力先symlinkは常に拒否する。

### 5.5 Evidence Snapshot手順

Parserは元Evidenceを直接解析してはならない。次の手順で作成したsnapshotだけを解析する。

1. 元Evidenceをread-onlyかつsymlink非追跡で開く。
2. 開いたhandleから`size`、mtime、OS file identityを取得し、`before`として保持する。
3. Application管理下のprivate temporary directoryへ新規snapshot fileを作成する。
4. 元handleから固定長bufferで末尾まで読み、同じbytesをsnapshotへ書きながらSHA-256を計算する。
5. snapshotをflushし、以後read-onlyで再openする。
6. 元handleから`size`、mtime、OS file identityを再取得し、`after`として保持する。
7. `before`と`after`が異なる場合、snapshotを解析せず`IntegrityStatus::ChangedDuringSnapshot`としてEvidenceをskipする。
8. snapshotのsizeとSHA-256を再検証する。
9. ParserとYARA-Xには同一snapshotを渡す。

snapshot作成中にread error、disk full、hash errorが発生した場合、そのEvidenceは解析してはならない。Case全体はstrict modeでない限り継続する。

```rust
enum IntegrityStatus {
    VerifiedSnapshot,
    ChangedDuringSnapshot,
    SnapshotFailed,
}
```

`VerifiedSnapshot`以外のEvidenceからEventまたはYARA Matchを生成してはならない。

### 5.6 Evidence ID

Evidence IDは次の形式とする。

```text
tf-evidence-v1:<lowercase SHA-256 hex>
```

hash入力fieldは次の順とする。

1. literal `TRACEFORGE-EVIDENCE-ID-V1`
2. `source_locator`
3. decimal `size`
4. lowercase `sha256`

各fieldは§12.2のlength-prefixed encodingで連結する。

## 6. 時刻モデル

### 6.1 必須型

Eventは単一の必須`DateTime<Utc>`を持ってはならない。次の表現を使用する。

```rust
enum TemporalValue {
    UtcInstant {
        value: DateTime<Utc>,
    },
    LocalTime {
        value: NaiveDateTime,
        timezone: Option<String>,
    },
    Range {
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    },
    Unknown,
}

struct EventTime {
    value: TemporalValue,
    original: Option<String>,
    kind: TimestampKind,
    precision: TimePrecision,
    timezone_source: TimezoneSource,
    uncertainty_ms: Option<u64>,
}
```

`TimePrecision`は最低限`Nanosecond / Microsecond / Millisecond / Second / Minute / Day / Unknown`を持つ。

`TimezoneSource`は最低限次を持つ。

```text
ArtifactDefined
ExplicitOffset
CaseDefault
CliOverride
Inferred
Unknown
```

### 6.2 変換規則

- ArtifactがUTCを定義する場合だけ`UtcInstant`を使用する。
- 入力がoffsetを持つ場合、UTCへ変換し、元文字列とoffsetを保持する。
- local timeでtimezoneが不明の場合、`LocalTime { timezone: None }`を使用する。
- `--timezone`またはCase defaultを適用した場合、UTCへ変換した派生時刻を使用できるが、`timezone_source`と元local timeを必ず保持する。
- 存在しないDST local timeは変換せずWarningとする。
- DSTにより2通りに解釈できるlocal timeは、明示的な選択がない限りRangeまたはLocalTimeのまま保持する。
- 時刻を取得できないEventは`Unknown`とする。現在時刻やfile mtimeで補完してはならない。

### 6.3 Timeline順序

Timelineは次のgroup順に出力する。

1. `UtcInstant`およびUTCへ確定変換された時刻
2. timezone付きだがUTCへ変換できなかった`LocalTime`
3. timezone不明の`LocalTime`
4. `Range`
5. `Unknown`

Group 1はUTC timestamp昇順、同一timestampはEvent ID昇順とする。Group 2と3は`timezone`、local value、Event IDの順とする。Rangeはstart、end、Event IDの順とし、欠損境界は末尾とする。UnknownはEvent ID順とする。

Groupをまたぐ因果順序をTraceForgeが断定してはならない。

### 6.4 Correlation時刻規則

時間windowを使用するCorrelationは、比較可能なUTC instant同士だけを既定で対象とする。timezone不明、Unknown、開区間Rangeをruleが暗黙にmatchさせてはならない。

Ruleが不確実時刻を許可する場合、Rule内に`allow_uncertain_time: true`と最大許容誤差を明記し、match reasonへその事実を記録する。

## 7. EventとProvenance

### 7.1 Event

```rust
struct Event {
    id: String,
    time: EventTime,
    source: ArtifactSource,
    event_type: EventType,
    assertion: AssertionKind,
    hostname: Option<String>,
    user: Option<String>,
    path: Option<WindowsPathValue>,
    program: Option<String>,
    process: Option<ProcessRef>,
    message: String,
    attributes: BTreeMap<String, serde_json::Value>,
    provenance: Provenance,
}
```

```rust
enum AssertionKind {
    Observed,
    Inferred,
}
```

Parserは原則として`Observed`だけを生成する。`Inferred`はCorrelation、Sigma adapter、または明示されたinference componentだけが生成できる。

Event type名が実際の行為を断定する場合、Evidenceがその行為を直接支持しなければならない。Registry snapshotのkey存在やlast-writeだけから`RegistrySet`または`RegistryDelete`を生成してはならず、`RegistryObservation`等の観測型を使用する。

### 7.2 Process

```rust
struct ProcessRef {
    pid: Option<u64>,
    ppid: Option<u64>,
    process_guid: Option<String>,
    parent_process_guid: Option<String>,
    image_path: Option<WindowsPathValue>,
    command_line: Option<String>,
}
```

親子process correlationはGUID、PIDとboot/session context、またはEvidenceが明示するparent fieldを使用する。process名だけで親子関係を断定してはならない。

### 7.3 Provenance

```rust
struct Provenance {
    evidence_id: String,
    artifact_id: String,
    source_locator: String,
    source_sha256: String,
    parser_id: String,
    parser_version: String,
    record_locator: RecordLocator,
    source_ordinal: u64,
}
```

`RecordLocator`は`RecordId / ByteOffset / ByteRange / LogicalPath / SourceOrdinal`のいずれかを必ず持つ。Parserがより強いlocatorを取得できない場合だけ`SourceOrdinal`を使用する。

## 8. Windows pathとEntity

解析host上のpathには`PathBuf`を使用してよいが、Evidence内に記録されたWindows pathへ`PathBuf`を使用してはならない。

```rust
struct WindowsPathValue {
    original: String,
    comparison_key: Option<String>,
    normalization_profile: String,
    normalization_notes: Vec<String>,
}
```

既定normalization profile `windows-path-v1`は次だけを行う。

- `/`を`\`へ変換する。
- 重複separatorを1つにする。ただしUNC先頭`\\`は保持する。
- ASCII drive letterを大文字へ変換する。
- 比較keyだけをUnicode case foldする。
- `.` componentを削除する。
- rootを越えない`..`を解決する。

環境変数展開、drive mapping、8.3名展開、Volume GUID変換、device path変換は、Case固有mappingが明示された場合だけ行う。path一致は同一fileの証明ではなく、`PathEquivalent`という関係として扱う。

## 9. Parser契約

### 9.1 必須interface

Parserは全Eventを`Vec`で返してはならない。次のsink型interfaceを使用する。

```rust
trait ArtifactParser {
    fn parser_id(&self) -> &'static str;
    fn parser_version(&self) -> &'static str;
    fn artifact_type(&self) -> ArtifactSource;

    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult;

    fn parse(
        &self,
        snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary;
}

trait ParseSink {
    fn emit_event(&mut self, event: Event) -> Result<(), SinkError>;
    fn emit_issue(&mut self, issue: ParseIssue) -> Result<(), SinkError>;
}
```

`ReadSeek`は`Read + Seek`を表すproject内trait aliasとしてよい。

### 9.2 部分成功

```rust
struct ParseSummary {
    status: ParseStatus,
    records_seen: u64,
    events_emitted: u64,
    issues_emitted: u64,
    bytes_consumed: u64,
}

enum ParseStatus {
    Complete,
    Partial,
    Skipped,
    Failed,
}
```

1 recordの破損は`ParseIssue`として出力し、次recordの境界を安全に特定できる場合だけ継続する。境界を安全に特定できない場合、そのArtifactInstanceを`Partial`で終了する。生成済みEventを破棄してはならない。

### 9.3 Parse Issue

各Issueは、安定したcode、severity、Evidence ID、Artifact ID、record locator、短いmessageを持つ。messageへEvidenceの巨大な値または未escape制御文字をそのまま含めてはならない。

同一Issueの出力順は、`evidence_id`、`artifact_id`、`source_ordinal`、`code`の順とする。

### 9.4 Panic

入力起因の異常をpanicで処理してはならない。Parser境界ではpanicを検出して内部Fatal errorとして記録し、processをExit Code 10で停止する。panic後に解析結果を正常結果として出力してはならない。

## 10. Event StoreとStreaming

RuntimeのCaseへ`Vec<Event>`を保持してはならない。Eventは次のいずれかへ逐次保存する。

- transaction付きembedded database
- length-delimited spool file
- 同等の耐障害性を持つtemporary event store

Event Storeは次を満たさなければならない。

- EventごとのSchema validation
- Event IDによる一意制約
- 途中停止時に未完了Caseと判別できるcommit marker
- timestamp groupとEvent IDによる決定的iteration
- 最終出力完了まで自動削除しない
- permissionを所有者だけに制限する

Timeline sortはmemory内sortだけに依存してはならない。入力がmemory budgetを超える場合、Event Storeのindexまたはexternal merge sortを使用する。

## 11. Artifact識別

Artifact typeは拡張子だけで決定してはならない。`filename / known path / magic / header / parser probe`を使用する。

`probe`は次のいずれかを返す。

```text
Confirmed
Probable
UnsupportedVersion
NotThisFormat
Malformed
```

複数Parserが`Confirmed`を返した場合、互換性仕様書で許可された組み合わせだけを実行する。それ以外はambiguousとしてskipする。`Probable`だけの場合、既定では解析せずWarningとする。

## 12. 決定的ID

### 12.1 共通形式

IDはUUIDまたは乱数で生成してはならない。次のprefixを使用する。

```text
tf-case-v1:
tf-evidence-v1:
tf-artifact-v1:
tf-event-v1:
tf-match-v1:
tf-finding-v1:
```

suffixはlowercase SHA-256 hexとする。

### 12.2 Length-prefixed encoding

hash対象の各fieldを次の形式でUTF-8 bytesへ変換する。

```text
4 byte unsigned big-endian length
field bytes
```

nullは長さ`0xFFFFFFFF`、空文字列は長さ0として区別する。整数は符号なしdecimal ASCII、enumはSchemaで定義したlowercase文字列、listは要素数を先頭fieldとしてから各要素を同じ形式でencodeする。

### 12.3 Event ID

Event IDのhash fieldは次の順とする。

1. literal `TRACEFORGE-EVENT-ID-V1`
2. Schema version
3. Evidence ID
4. Artifact ID
5. Parser ID
6. Parser version
7. canonical Record Locator
8. source ordinal
9. Event type
10. Assertion kind
11. canonical EventTime
12. 同一source recordから複数Eventを生成する場合の`event_ordinal`

message、hostname等はIDへ含めない。Parserの表示文変更だけでIDが変わることを防ぐためである。Eventの意味が変わるParser変更はParser versionを上げなければならない。

### 12.4 Artifact、Match、Finding ID

- Artifact IDはEvidence ID、artifact type、Parser ID、Parser versionから生成する。
- Match IDはRule ID、Rule content SHA-256、順序付きEvent ID listから生成する。
- Finding IDはFinding type、Rule content SHA-256 list、sort済みEvent ID list、sort済みEvidence ID listから生成する。

## 13. 再現性

### 13.1 分析レコード

同一結果でなければならない対象は次のとおりである。

- Evidence inventoryの分析field
- Artifact inventory
- Events
- Parse Issues
- Sigma/YARA-X/Correlation matches
- Findings
- ATT&CK mappings
- resolved configuration digest

次はrun metadataであり、同一性比較から除外する。

- run started/finished time
- OS process ID
- temporary directory
- elapsed time
- CPU/RAM usage

### 13.2 並列処理

worker threadはEvent IDやsource ordinalを共有counterの到着順で割り当ててはならない。source ordinalは元formatのrecord順から各Parserが決定する。

最終record順は各Schemaで指定されたsort keyに従う。thread数、filesystem列挙順、hash map iteration順に依存してはならない。順序が出力へ影響するmapには`BTreeMap`または明示sortを使用する。

### 13.3 Golden test

同一fixtureを`--threads 1`、`--threads 2`、自動thread数で解析し、run metadataを除くcanonical JSONがbyte単位で一致しなければreleaseしてはならない。

## 14. Correlation Rule

RuleはSchema仕様書のCorrelation Rule Schemaへ適合しなければならない。

すべてのCorrelation、Sigma、YARA-X Rule fileは1回だけbytesとして読み込み、そのraw bytesのSHA-256を計算し、同じbytesをparseまたはcompileしなければならない。評価中にRule fileを再読込してはならない。Rule directoryの列挙順は正規化相対pathのUTF-8 byte順とする。

YAML anchor、alias、custom tagはv1.0では禁止する。検出したRule file全体をvalidation errorとする。

### 14.1 評価の既定値

- 同一Case内だけを評価する。
- hostnameが両Eventに存在する場合は同一hostnameだけをmatchさせる。
- 一方だけhostname不明の場合は既定でmatchさせない。
- path比較はRule指定のnormalization profileを使用する。
- `within`の境界は両端を含む。
- sequenceの同一timestampはTimeline順ではなくRule条件で明示しない限り順序不明とする。
- nullは空文字列と等しくない。
- 型が違う値を暗黙変換しない。
- Ruleの未対応operatorが1つでもあればRule全体をskipする。

### 14.2 Match数

同じRule、同じ順序付きEvent ID listからmatchを複数生成してはならない。組み合わせ数が上限へ達した場合、そのRuleの評価を打ち切り、分析をincompleteとしてExit Code 1にする。strict rules modeではExit Code 5とする。

### 14.3 Confidence

Confidenceは0.0以上1.0以下へclampする。Ruleはbase scoreと加減点の理由を明示する。同一のEvidence事実を異なるArtifact表示から二重加点してはならない。

Levelは次に固定する。

```text
0.00 <= score < 0.50  low
0.50 <= score < 0.80  medium
0.80 <= score <= 1.00 high
```

## 15. Sigma、YARA-X、ATT&CK

### 15.1 Sigma

Rule全体が互換性仕様書の対応subset内にある場合だけ評価する。未対応modifier、condition、correlation、filterが含まれるRuleを部分評価してはならない。

Sigma field mapping、logsource mapping、case sensitivity、engine version、Rule SHA-256をAnalysis Manifestへ記録する。

### 15.2 YARA-X

YARA-XはVerified Snapshotだけをscanする。scan対象を実行、load、shell openしてはならない。

Rule compile errorが1件でもあるRule fileは、そのfile全体を無効とする。他の正常Rule fileはstrict rules modeでない限り継続できる。Rule file SHA-256とYARA-X engine versionを記録する。

`suspicious` modeは、Event内Windows pathではなく、FindingまたはCorrelationが参照するEvidence IDからsnapshotを解決する。Evidence IDへ解決できないpathを推測でlocal filesystemからscanしてはならない。

### 15.3 ATT&CK

ATT&CK mappingはCorrelation Rule、Sigma tag、built-in mapping、またはmanual mappingからのみ生成する。Technique名とIDに加えて、使用したATT&CK dataset versionとSHA-256を記録する。

## 16. Finding

Findingは次を保持する。

- 決定的Finding ID
- title、description
- Severity
- Confidenceと加減点理由
- Event ID list
- Evidence ID list
- Sigma/YARA-X/Correlation Match ID list
- Rule IDとRule SHA-256
- ATT&CK mapping
- `Observed evidence`と`Inference`を分けた説明

Finding Mergerは、同じEventまたはEvidenceを参照するという理由だけで異なるFindingを自動統合してはならない。統合ruleが明示されている場合だけ統合する。

## 17. Error、Warning、Exit Code

### 17.1 Scope付きstrict mode

```text
--strict parser
--strict rules
--strict limits
--strict all
```

bare `--strict`は`--strict all`と同じ意味とする。

### 17.2 Exit Code

| Code | 意味 |
|---:|---|
| 0 | 完全成功。Warning、skip、limit到達なし |
| 1 | Caseは生成されたがWarning、partial、skip、limit到達あり |
| 2 | CLIまたは設定error |
| 3 | 入力pathまたはEvidence discovery error |
| 4 | 出力作成、安全検証、overwrite error |
| 5 | Rule validationまたはstrict rules error |
| 6 | strict parserまたはstrict limits error |
| 10 | TraceForge内部Fatal errorまたはpanic |

複数errorがある場合は、数値が大きいcodeではなく、`10 > 6 > 5 > 4 > 3 > 2 > 1 > 0`の優先順位を使用する。

## 18. Resource Limit

既定値はSchema仕様書のConfiguration Schemaに定義する。file sizeやRule数など事前に判定できるlimitは処理開始前に検査し、Event数やmatch数など逐次増加するlimitは1件追加する直前に検査しなければならない。

limit到達時は次を行う。

1. 対象処理を安全な境界で停止する。
2. `TF-W-LIMIT-*` Issueを出力する。
3. Analysis Manifestの`complete`をfalseにする。
4. strict limitsでなければExit Code 1、strict limitsならExit Code 6とする。
5. 上限を超えた結果を黙って切り捨ててはならない。

## 19. Output safety

### 19.1 Textとlog

Evidence由来のC0/C1制御文字とESCは可視escapeへ変換する。解析結果はstdout、logはstderrへ出力する。`quiet`は解析結果を抑制してはならない。

### 19.2 CSV

RFC 4180形式でquoteする。cellの最初の非空白文字が`=`, `+`, `-`, `@`, tab, carriage returnのいずれかの場合、先頭へ単一quoteを付け、`csv_sanitized=true`をManifestへ記録する。

### 19.3 HTML

すべてのEvidence由来文字列をtext nodeとしてescapeする。`innerHTML`へ連結してはならない。Content Security Policyを埋め込み、scriptはstatic local contentだけを許可する。外部通信を行わない。

### 19.4 JSONとJSONL

UTF-8、改行`\n`を使用する。JSONLは1物理行1objectとし、string内改行をescapeする。NaNとInfinityを出力してはならない。

## 20. Analysis Manifest

Manifestは最低限次を保持する。

- TraceForge version、build commit、target
- Schema version、compatibility profile version
- run start/end time
- resolved configurationとSHA-256
- input rootの表示用情報
- Case ID
- Evidence、Event、Issue、Match、Finding件数
- parser ID/version一覧
- Rule ID/file/hash一覧
- Sigma/YARA-X engine version
- ATT&CK dataset version/hash
- timezone assumptions
- resource limitと到達状況
- partial/skip/failure一覧
- `complete: true/false`
- Exit Code

run timeをEvent ID、Finding ID、分析内容のdeterminismへ影響させてはならない。

## 21. 受け入れ条件

v1.0準拠実装は最低限次のtestを自動化しなければならない。

1. timezone不明local timeをUTCとして出力しない。
2. timestamp不明Eventを保持し、Timeline末尾groupへ出力する。
3. snapshot中に元fileを書き換えるtestでEventを生成しない。
4. snapshot SHA-256とParserが読んだbytesのSHA-256が一致する。
5. 破損した中間recordの前後で、安全な境界がある場合に部分Eventを保持する。
6. Parserが100万Eventを生成してもParser APIが全件`Vec`を要求しない。
7. thread数1、2、自動でcanonical分析出力がbyte単位一致する。
8. 同一timestampのEvent順がEvent IDで安定する。
9. input directory内へのoutputを拒否する。
10. symlink loopを追跡しない。
11. CSV formula、terminal ESC、HTML script文字列を安全に出力する。
12. 未対応Sigma構文を含むRule全体をskipする。
13. YARA-X suspicious modeがEvidence IDへ解決できないhost pathをscanしない。
14. limit到達時にManifestを`complete=false`とする。
15. JSON、JSONL、Correlation Rule、ConfigurationがSchema validationに成功する。
