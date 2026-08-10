# TraceForge 互換性仕様書 v1.0

## 1. 目的

本書はTraceForge v1.0が「対応している」と表明できる範囲を定義する。Parserや外部連携が存在するだけではSupportedと表明してはならない。対応表の必須testを満たした対象だけをSupportedとする。

本書は開発進捗表ではない。`Required`は製品仕様上の完成条件、`Optional`は実装してよい追加対象、`Unsupported`はv1.0が意図的に扱わない対象を意味する。

## 2. 対応状態の意味

| 状態 | 意味 |
|---|---|
| Required | v1.0 Stableで必須。fixture、negative test、Golden testをすべて通す |
| Optional | 実装した場合は同じ品質基準を満たし、Manifestへ明記する |
| Unsupported | 解析せずWarningまたはvalidation errorにする |
| Pass-through | 意味解釈せずraw attributesとして保持する |

`Required`対象でも、未知version、破損、必須field欠落を既知形式として推測してはならない。

## 3. 共通Compatibility Profile

Profile ID:

```text
TF-WIN-1.0
```

対象入力:

- 取得済みstandalone Evidence file
- 取得済みdirectory tree
- Windows 7 SP1以降で生成された、下表の対応形式

対象外入力:

- raw disk image
- E01、VHD/VHDX、AFF等のdisk container
- live Windows APIからの直接収集
- memory dump
- network packet capture
- archive fileの自動展開
- password付きまたは暗号化container

対象外入力を検出した場合、内包fileを推測で探索してはならない。

## 4. Artifact Compatibility Matrix

### 4.1 Prefetch

| 対象 | 状態 | 必須動作 |
|---|---|---|
| Format version 17 | Required | executable名、run count、利用可能なrun time、volume、参照file/directoryを安全に取得 |
| Format version 23 | Required | 同上 |
| Format version 26 | Required | 同上 |
| Format version 30 | Required | 同上 |
| Format version 31 | Required | 同上 |
| MAM圧縮Prefetch | Required | 展開後bytesを別Evidenceと誤認せず、同じProvenance chainで解析 |
| 未知version | Unsupported | `TF-W-PREFETCH-UNSUPPORTED-VERSION`でskip |

Prefetchの存在は「そのhost上で実行痕跡が記録された」ことを示すEventとして扱う。直接観測したprocess start Eventへ変換してはならない。

必須fixture:

- 各versionの正常sampleを最低2件
- MAM圧縮sample
- zero-length、truncated header、過大offset、重複run time、最大run count
- fixtureごとのSHA-256と期待Event JSON

### 4.2 EVTX

| 対象 | 状態 | 必須動作 |
|---|---|---|
| Standalone `.evtx` file | Required | file/chunk/record境界検証、record ID、provider、channel、computer、Event ID、EventData、SystemData保持 |
| Windows Logs: Security/System/Application | Required | 汎用Eventとして保持 |
| PowerShell Operational | Required | channelとraw fieldを保持し、対応field mappingを適用 |
| Sysmon Operational | Required | provider/channelを確認して対応field mappingを適用 |
| Localized message rendering | Optional | resource DLLなしでもraw XML/dataを失わない |
| Legacy `.evt` | Unsupported | EVTXとして解析しない |

最低限のtyped mapping:

| Event ID | Channel/Provider条件 | Event type |
|---:|---|---|
| 4624 | Security | login |
| 4625 | Security | login_failure |
| 4688 | Security | process_start |
| 4689 | Security | process_stop |
| 7045 | System / Service Control Manager | service_create |

Event IDだけでmappingしてはならない。channel、provider、required fieldを同時に検証する。

必須fixture:

- Windows 7 SP1、Windows 10 22H2、Windows 11 24H2で保存したEVTX
- Security、System、PowerShell Operational、Sysmon Operational
- partial chunk、bad checksum、truncated record、unknown Event ID
- 破損record前後の正常recordを保持するpartial recovery test

### 4.3 USN Journal

Microsoftが公開している`USN_RECORD_COMMON_HEADER`のMajorVersionで形式を判定する。

| 対象 | 状態 | 必須動作 |
|---|---|---|
| USN_RECORD_V2 | Required | record length、reason、timestamp、file reference、parent reference、nameを検証して取得 |
| USN_RECORD_V3 | Required | 128-bit file referenceを切り詰めず取得 |
| USN_RECORD_V4 | Required | range tracking情報を保持し、filenameがない前提で処理 |
| 未知MajorVersion | Unsupported | record lengthが安全な場合だけskipしWarning |

V2、V3、V4の存在はMicrosoftの公開構造と整合させる。参照:

- https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v3
- https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v4
- https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-usn_record_common_header

Renameの`OLD_NAME`と`NEW_NAME`は、同一file reference、近接USN、対応reasonを満たす場合だけ1変更として結合する。結合できない場合は独立したObserved Eventとして保持する。

USN path reconstructionは、同じEvidence set内に安全に利用できる親directory mappingがある場合だけ行う。取得できない親をhost filesystemから検索してはならない。

### 4.4 LNK

| 対象 | 状態 | 必須動作 |
|---|---|---|
| Shell Link Header | Required | size、CLSID、flags、attributes、timestamps、file size等を検証 |
| LinkTargetIDList | Required | 境界検証し、未知itemをraw保持またはskip |
| LinkInfo | Required | local/network target情報を取得 |
| StringData | Required | name、relative path、working directory、arguments、icon location |
| ExtraData | Required | 既知blockを解析し、未知blockを安全にskip |

Normative format referenceはMicrosoft `[MS-SHLLINK]` revision 10.0またはrelease時にpinした後継revisionとする。

```text
https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
```

LNK timestampはtimestamp kindと元field名を保持する。LNKの存在やtimestampだけから「利用者がその時刻にtargetを開いた」と断定してはならない。

### 4.5 Jump Lists

| 対象 | 状態 | 必須動作 |
|---|---|---|
| AutomaticDestinations | Required | CFB container境界、DestList、内包LNKを解析 |
| CustomDestinations | Required | entry境界と内包LNKを解析 |
| Windows 7 SP1生成fixture | Required | targetとentry metadataを保持 |
| Windows 10 22H2生成fixture | Required | 同上 |
| Windows 11 24H2生成fixture | Required | 同上 |
| 未知DestList version | Unsupported | container全体を誤解析せずWarning |

内包LNKは新しい物理Evidenceとして登録せず、Jump List Evidence内のArtifactInstanceとして扱い、compound stream名とoffsetをProvenanceへ保存する。

### 4.6 Amcache

| 対象 | 状態 | 必須動作 |
|---|---|---|
| Windows 10 22H2 `Amcache.hve` | Required | 認識したkey familyとfile/program metadataを保持 |
| Windows 11 24H2 `Amcache.hve` | Required | 同上 |
| Windows 8/8.1 family | Optional | 対応宣言する場合は専用fixtureが必要 |
| 未知schema | Unsupported | Generic Registry parserへ自動fallbackせずWarning |

Amcache recordの存在を直接的なprocess startへ変換してはならない。`amcache_observation`として保持し、実行を示す別EvidenceとのCorrelationでのみ実行Findingを作成する。

### 4.7 Registry

| 対象 | 状態 | 必須動作 |
|---|---|---|
| SYSTEM | Required | key/value、last-write、control set contextを保持 |
| SOFTWARE | Required | key/value、last-writeを保持 |
| SAM | Required | parse可能なmetadataを保持。secret復号は対象外 |
| SECURITY | Required | parse可能なmetadataを保持。secret復号は対象外 |
| NTUSER.DAT | Required | user hiveとして保持 |
| UsrClass.dat | Required | user contextを保持 |
| Amcache.hve | Required | Amcache Parserと明示的に併用可能 |
| `.LOG1` / `.LOG2` transaction log | Required | replayの成否と使用log hashを記録 |
| RegBack等の別copy | Pass-through | 別Evidenceとして扱う |

transaction logが存在する場合、次の両方を保存する。

- base hiveだけのview
- 安全にreplayできた場合のrecovered view

どちらのviewからEventを生成したかをProvenanceへ記録する。logが存在するのにreplayできない場合、Registry Artifactは`partial`とし、完全解析と表明してはならない。

Registry snapshotのkey/value存在は`registry_observation`、last-writeは`registry_key_last_write`として表現する。transaction log等で操作が直接確認できない限り`registry_set`または`registry_delete`を生成してはならない。

## 5. Artifact共通必須field

| Artifact | 必須field |
|---|---|
| Prefetch | executable、format version、run count、各run time、source locator |
| EVTX | provider、channel、record ID、Event ID、computer、event time、raw data |
| USN | major/minor version、USN、reason、file reference、parent reference、record locator |
| LNK | header、flags、取得できた各timestampと意味、target情報、source locator |
| Jump List | container type、entry ID、AppID由来source name、内包LNK provenance |
| Amcache | schema family、key path、取得field、interpretation limitation |
| Registry | hive type、view、key path、value name/data、last-write、replay status |

必須fieldを形式上取得できないrecordはEvent化せず、Parse Issueを生成する。

## 6. Sigma Compatibility Profile

Profile ID:

```text
TF-SIGMA-1.0
```

TraceForgeはSigma RuleをSIEM queryへ変換せず、Normalized Eventに対してsubsetを評価する。

### 6.1 Required

| 要素 | 対応 |
|---|---|
| Metadata | `title`, `id`, `status`, `description`, `references`, `tags`, `level`, `falsepositives` |
| Logsource | `category`, `product`, `service`, `definition`のrouting |
| Selection | scalar、list、map |
| Condition | `and`, `or`, `not`, parentheses |
| Quantifier | `1 of`, `all of`, wildcard selection names |
| String modifier | `contains`, `startswith`, `endswith`, `cased` |
| Field modifier | `exists` |
| List modifier | `all` |

### 6.2 Unsupported in TF-SIGMA-1.0

次を含むRuleはRule全体をskipする。

- Sigma Correlation Rule
- Sigma Filter specification
- `base64`, `base64offset`, `expand`, `fieldref`, numeric compare、CIDR、regex、UTF-16/wide、windash modifier
- placeholder expansion
- backend固有extension
- aggregationまたはtimeframeを必要とするcondition

未対応要素を無視して残りだけ評価してはならない。

Sigmaの対応基準:

- https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html
- https://sigmahq.io/docs/basics/log-sources.html

### 6.3 Field mapping

最低限次をmappingする。

| Sigma field | TraceForge field |
|---|---|
| `EventID` | `attributes.evtx.event_id` |
| `Channel` | `attributes.evtx.channel` |
| `Provider_Name` | `attributes.evtx.provider` |
| `Computer` | `hostname` |
| `Image` / `NewProcessName` | `process.image_path.original` |
| `CommandLine` / `ProcessCommandLine` | `process.command_line` |
| `ParentImage` | `attributes.process.parent_image` |
| `ParentCommandLine` | `attributes.process.parent_command_line` |
| `User` / `SubjectUserName` | `user`または明示raw field |
| `TargetFilename` | `path.original` |

同名fieldが複数候補を持つ場合、logsourceごとのmapping tableを選び、全候補をORで評価してはならない。

## 7. YARA-X Compatibility Profile

Profile ID:

```text
TF-YARAX-1.0
```

| 対象 | 状態 |
|---|---|
| YARA-X Rust API | Required |
| `.yar` / `.yara` single file | Required |
| rule directory再帰load | Required |
| tags、meta、namespace | Required |
| matched pattern identifier | Required |
| external variable | Unsupported |
| process memory scan | Unsupported |
| live process attach | Unsupported |
| archive自動展開 | Unsupported |

TraceForge releaseは使用するYARA-X crateの完全versionとCargo.lock checksumをManifestへ記録する。`latest`を互換性識別子として使用してはならない。

Reference:

```text
https://virustotal.github.io/yara-x/docs/api/rust/
```

## 8. Timesketch Compatibility Profile

Profile ID:

```text
TF-TIMESKETCH-1.0
```

各JSONL Eventは最低限次を持つ。

```text
message
datetime
timestamp_desc
traceforge_event_id
traceforge_source
traceforge_event_type
traceforge_evidence_id
```

Reference:

```text
https://timesketch.org/guides/user/import-from-json-csv/
```

`datetime`へ変換できないtimezone不明local time、Range、UnknownはTimesketch Eventとして出力してはならない。除外件数とEvent IDをexport summaryへ記録し、Exit Code 1とする。利用者が明示timezoneを指定してUTCへ確定変換したEventは出力できる。

出力filenameは`.jsonl`で終わらなければならない。import testは実際のTimesketch instanceまたはversion固定の公式import validatorで実施する。

## 9. MITRE ATT&CK Compatibility Profile

Profile ID:

```text
TF-ATTACK-1.0
```

Enterprise ATT&CK STIX dataを使用する。Release時に次を固定する。

- ATT&CK release version
- STIX bundle SHA-256
- 取得元URL
- 取得日

Technique/Sub-technique IDがdatasetに存在しないRuleはvalidation errorとする。名称はIDからdatasetで解決し、Rule内の自由記述名を正本として使用してはならない。

Reference:

```text
https://attack.mitre.org/
https://attack.mitre.org/techniques/enterprise/
```

## 10. Output Compatibility

| Format | Required compatibility |
|---|---|
| Text | UTF-8 terminal。制御文字を可視escape |
| JSON | TraceForge Case JSON Schema 1.0.0 |
| JSONL | TraceForge JSONL Schema 1.0.0 |
| CSV | RFC 4180、UTF-8、formula injection対策 |
| HTML | offline、CSP、外部requestなし |
| Timesketch | TF-TIMESKETCH-1.0 |

`export`は異なるSchema major versionを自動変換してはならない。明示的migration componentがある場合だけ変換し、変換前後のSchema versionをManifestへ記録する。

## 11. DependencyとLicense

各releaseは次を保存する。

- `Cargo.lock`
- Rust toolchain version
- 直接・間接dependency version
- dependency license一覧
- parser、Sigma、YARA-X関連dependencyのsecurity advisory確認結果

GPL等、配布形態へ影響するlicenseを採用する場合はrelease前に明示する。version rangeだけで再現性を主張してはならない。

## 12. Compatibility acceptance test

対象をSupportedと表明する前に次をすべて満たす。

1. 正常fixtureから期待Eventを生成する。
2. truncated、invalid length、unknown versionでpanicしない。
3. Provenanceが元recordへ到達する。
4. 1 threadと複数threadの出力が一致する。
5. fixture SHA-256、生成OS/build、取得方法、期待結果を記録する。
6. 外部仕様を使う対象は、検証した仕様revisionまたはdependency versionを記録する。
7. 非対応field・構文・versionを黙って無視しない。
8. Format固有の意味を越えてEvent typeを断定しない。

Required対象が1つでもこの条件を満たさないbuildはv1.0 Stableとしてreleaseしてはならない。
