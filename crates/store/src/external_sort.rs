//! External merge sort（規範 §10: memory budget 超過時の Timeline sort）。
//!
//! Timeline sort は memory 内 sort だけに依存してはならない（規範 §10）。
//! 入力が memory budget を超える場合は、spool file を複数の sorted run file へ
//! 分割し、k-way merge で出力する。
//!
//! アルゴリズム:
//!
//! 1. EventStore から格納順に Event を読む
//! 2. memory budget いっぱいまで chunk を蓄積する
//! 3. chunk を [`TimelineKey`] で sort し、run file へ書く
//! 4. 全 chunk について繰り返す
//! 5. 全 run file を同時に開き、min-heap で先頭要素が最小のものから取り出す（k-way merge）

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use tf_core::canonical::to_canonical_string;
use tf_core::event::Event;

use crate::error::StoreError;
use crate::store::{EventIter, SortedEventIter};
use crate::timeline::TimelineKey;

/// spool file の size が memory budget 以下なら in-memory sort、超過時は external sort。
/// この判定により、小規模 Case では高速に、大規模 Case では安全に sort する（規範 §10）。
pub(crate) fn sorted_iter(
    store: &crate::store::EventStore,
    memory_budget_bytes: usize,
) -> Result<SortedEventIter, StoreError> {
    let file_size = std::fs::metadata(store.path())?.len() as usize;
    if file_size <= memory_budget_bytes {
        in_memory_sorted(store.iter()?)
    } else {
        external_merge_sort(store.path(), store.iter()?, memory_budget_bytes)
    }
}

/// in-memory sort 版。Vec へ蓄えて sort するが、iterator で消費するため
/// 呼出側は Vec を要求しない（規範 §21-6: API が Vec を要求しない）。
fn in_memory_sorted(iter: EventIter) -> Result<SortedEventIter, StoreError> {
    let mut events: Vec<Event> = iter.collect::<Result<_, _>>()?;
    events.sort_by(|a, b| TimelineKey::from_event(a).cmp(&TimelineKey::from_event(b)));
    Ok(SortedEventIter::from_memory(events.into_iter()))
}

/// external merge sort 版。
///
/// run file は spool file と同じ directory（所有者限定 permission が及ぶ前提）へ
/// `<spool>.sort-run-<N>` として作成する。merge 完了または drop 時に削除する。
fn external_merge_sort(
    spool_path: &Path,
    iter: EventIter,
    memory_budget_bytes: usize,
) -> Result<SortedEventIter, StoreError> {
    let parent = spool_path.parent().ok_or_else(|| {
        StoreError::ExternalSort("spool file の親 directory が取得できない".into())
    })?;
    let run_prefix = format!(
        "{}.sort-run-",
        spool_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("store.spool")
    );

    let mut run_paths: Vec<PathBuf> = Vec::new();
    let mut chunk: Vec<Event> = Vec::new();
    let mut chunk_bytes: usize = 0;
    let mut run_index: usize = 0;

    for result in iter {
        let event = result?;
        let event_bytes = estimate_event_bytes(&event);
        // 予算を超える前に chunk を flush する。
        if !chunk.is_empty() && chunk_bytes + event_bytes > memory_budget_bytes {
            let path = parent.join(format!("{run_prefix}{run_index}"));
            write_sorted_run(&path, std::mem::take(&mut chunk))?;
            run_paths.push(path);
            chunk_bytes = 0;
            run_index += 1;
        }
        chunk.push(event);
        chunk_bytes = chunk_bytes.saturating_add(event_bytes);
    }
    // 残りを最終 run へ。
    if !chunk.is_empty() {
        let path = parent.join(format!("{run_prefix}{run_index}"));
        write_sorted_run(&path, std::mem::take(&mut chunk))?;
        run_paths.push(path);
    }

    if run_paths.is_empty() {
        // Event が1件も無い場合は空の in-memory iterator へフォールバック。
        return Ok(SortedEventIter::from_memory(
            Vec::<Event>::new().into_iter(),
        ));
    }

    SortedEventIter::from_external(run_paths)
}

/// Event の canonical JSON byte 数を概算する（chunk 区切り判定用）。
fn estimate_event_bytes(event: &Event) -> usize {
    to_canonical_string(&event.to_canonical_value())
        .map(|s| s.len() + 4) // length prefix 分を加算
        .unwrap_or(1024)
        .max(64)
}

/// 1つの run file へ sort 済み Event 列を書き込む。
///
/// run file 形式: 繰り返し `[4 byte BE length] [canonical JSON bytes]`。
fn write_sorted_run(path: &Path, mut events: Vec<Event>) -> Result<(), StoreError> {
    events.sort_by(|a, b| TimelineKey::from_event(a).cmp(&TimelineKey::from_event(b)));
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    apply_run_permissions(&file)?;
    let mut writer = BufWriter::new(file);
    for event in &events {
        let bytes = to_canonical_string(&event.to_canonical_value())
            .map_err(|e| StoreError::Serialize(e.to_string()))?;
        writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
        writer.write_all(bytes.as_bytes())?;
    }
    writer.flush()?;
    Ok(())
}

/// run file へ所有者限定 permission を適用する（規範 §10、spool file と同等）。
#[cfg(unix)]
fn apply_run_permissions(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(StoreError::Io)?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_run_permissions(_file: &File) -> Result<(), StoreError> {
    Ok(())
}

/// run file の1レコードを読む。
fn read_run_record(reader: &mut impl Read) -> Result<Option<Vec<u8>>, StoreError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(StoreError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).map_err(StoreError::Io)?;
    Ok(Some(buf))
}

/// run file から Event を復元する。
fn decode_run_event(bytes: &[u8]) -> Result<Event, StoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| StoreError::Serialize(e.to_string()))?;
    crate::store::event_from_canonical_value(&value)
}

/// 指定 reader から次の Event を読む。run 終端時は `None`。
fn read_next_event(reader: &mut RunReader) -> Result<Option<Event>, StoreError> {
    let bytes = match read_run_record(&mut reader.reader)? {
        Some(b) => b,
        None => return Ok(None),
    };
    decode_run_event(&bytes).map(Some)
}

/// k-way merge を行う iterator（規範 §10: external merge sort）。
///
/// 全 run file を同時に開き、各々の先頭 Event の [`TimelineKey`] を min-heap へ入れる。
/// heap から最小を取り出したら、その run の次の Event を読んで heap へ戻す。
/// これを全 run が尽きるまで繰り返す。
pub(crate) struct KWayMerger {
    readers: Vec<RunReader>,
    heap: BinaryHeap<Reverse<HeapEntry>>,
    /// drop 時に run file を削除する（規範 §10: 自動削除しない対象は spool 本体のみ）。
    run_paths: Vec<PathBuf>,
}

struct RunReader {
    reader: BufReader<File>,
    index: usize,
}

#[derive(Clone, Debug)]
struct HeapEntry {
    key: TimelineKey,
    event: Event,
    run_index: usize,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.run_index == other.run_index
    }
}
impl Eq for HeapEntry {}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // TimelineKey 昇順。run_index で tie-break して安定させる。
        self.key
            .cmp(&other.key)
            .then_with(|| self.run_index.cmp(&other.run_index))
    }
}

impl KWayMerger {
    pub(crate) fn new(run_paths: Vec<PathBuf>) -> Result<Self, StoreError> {
        let mut readers: Vec<RunReader> = Vec::with_capacity(run_paths.len());
        for (index, path) in run_paths.iter().enumerate() {
            let file = File::open(path)?;
            readers.push(RunReader {
                reader: BufReader::new(file),
                index,
            });
        }

        let mut merger = KWayMerger {
            readers,
            heap: BinaryHeap::new(),
            run_paths,
        };

        // 各 run の先頭 Event を heap へ投入する。
        for reader in &mut merger.readers {
            if let Some(event) = read_next_event(reader)? {
                let key = TimelineKey::from_event(&event);
                merger.heap.push(Reverse(HeapEntry {
                    key,
                    event,
                    run_index: reader.index,
                }));
            }
        }

        Ok(merger)
    }

    /// heap から最小 Event を取り出し、その run の次を補充する。
    pub(crate) fn next_event(&mut self) -> Option<Result<Event, StoreError>> {
        let Reverse(entry) = self.heap.pop()?;
        let run_index = entry.run_index;
        // 同じ run から次の Event を読んで heap へ戻す。
        if let Some(reader) = self.readers.get_mut(run_index) {
            match read_next_event(reader) {
                Ok(Some(event)) => {
                    let key = TimelineKey::from_event(&event);
                    self.heap.push(Reverse(HeapEntry {
                        key,
                        event,
                        run_index,
                    }));
                }
                Ok(None) => { /* run が終わり */ }
                Err(e) => return Some(Err(e)),
            }
        }
        Some(Ok(entry.event))
    }
}

impl Drop for KWayMerger {
    fn drop(&mut self) {
        // run file は一時的なので削除する。spool 本体は呼出側が管理する（規範 §10）。
        for path in &self.run_paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
    use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

    fn sample_event(id: &str, dt: DateTime<Utc>) -> Event {
        let time = EventTime::utc_instant(
            dt,
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        );
        Event {
            id: id.to_string(),
            time,
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: None,
            user: None,
            path: None,
            program: None,
            process: None,
            message: String::new(),
            attributes: BTreeMap::new(),
            provenance: Provenance {
                evidence_id: "tf-evidence-v1:t".to_string(),
                artifact_id: "tf-artifact-v1:t".to_string(),
                source_locator: "x.evtx".to_string(),
                source_sha256: "ab".repeat(32),
                parser_id: "p".to_string(),
                parser_version: "1".to_string(),
                record_locator: RecordLocator::SourceOrdinal,
                source_ordinal: 0,
            },
        }
    }

    #[test]
    fn small_dataset_uses_in_memory_sort() {
        // spool file size < budget → in-memory sort へ切り替える。
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = crate::store::EventStore::create(&path).unwrap();
        // 3件を逆順で格納（i=0 が最新、i=2 が最古）。
        for (i, dt) in [
            "2026-08-10T03:00:00Z",
            "2026-08-10T02:00:00Z",
            "2026-08-10T01:00:00Z",
        ]
        .iter()
        .enumerate()
        {
            let mut e = sample_event(&format!("tf-event-v1:{i}"), dt.parse().unwrap());
            e.id = format!("tf-event-v1:{i}");
            store.store_event(&e).unwrap();
        }
        let mut sorted = store.iter_sorted(1024 * 1024).unwrap();
        let first = sorted.next().unwrap().unwrap();
        // UTC 昇順では最古（01:00:00 = i=2）が先頭。
        assert_eq!(first.id, "tf-event-v1:2", "最も古い timestamp が先頭");
    }

    #[test]
    fn tiny_budget_forces_external_sort() {
        // 極小 budget を与えて external sort path を強制起動する。
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = crate::store::EventStore::create(&path).unwrap();
        for i in 0..6 {
            let hour = 6 - i; // 逆順
            let dt: DateTime<Utc> = format!("2026-08-10T{hour:02}:00:00Z").parse().unwrap();
            let mut e = sample_event(&format!("tf-event-v1:{i}"), dt);
            e.id = format!("tf-event-v1:{i}");
            store.store_event(&e).unwrap();
        }
        // budget を spool file size より明らかに小さく設定。
        let file_size = std::fs::metadata(&path).unwrap().len() as usize;
        let tiny_budget = file_size / 4; // 確実に下回る
        let mut sorted = store.iter_sorted(tiny_budget).unwrap();
        let ids: Vec<String> = sorted.by_ref().map(|r| r.unwrap().id).collect();
        assert_eq!(ids.len(), 6);
        // 時刻昇順になっているはず。格納は 06→05→04→...→01 だった。
        // 先頭は hour=1（最古）、末尾は hour=6（最新）。
        assert!(ids.contains(&"tf-event-v1:5".to_string())); // hour=1 の Event
        assert!(ids.contains(&"tf-event-v1:0".to_string())); // hour=6 の Event
    }

    #[test]
    fn external_sort_run_files_cleaned_up() {
        // 規範 §10: 自動削除しない対象は spool 本体のみ。run file は破棄する。
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = crate::store::EventStore::create(&path).unwrap();
        for i in 0..4 {
            let dt: DateTime<Utc> = format!("2026-08-10T0{i}:00:00Z").parse().unwrap();
            let mut e = sample_event(&format!("tf-event-v1:{i}"), dt);
            e.id = format!("tf-event-v1:{i}");
            store.store_event(&e).unwrap();
        }
        let file_size = std::fs::metadata(&path).unwrap().len() as usize;
        {
            let mut sorted = store.iter_sorted(file_size / 4).unwrap();
            // 全部消費する。
            for _ in &mut sorted {}
        }
        // run file が残っていないことを確認。
        let run_files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".sort-run-"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(run_files.is_empty(), "run file は破棄されるべき");
        // spool 本体は残る。
        assert!(path.exists(), "spool file は残るべき");
    }

    #[test]
    fn empty_store_iter_sorted_yields_nothing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let store = crate::store::EventStore::create(&path).unwrap();
        let mut sorted = store.iter_sorted(1024).unwrap();
        assert!(sorted.next().is_none());
    }
}
