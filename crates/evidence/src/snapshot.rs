//! Evidence Snapshot 手順（規範 §5.5）。
//!
//! Parser は元 Evidence を直接解析してはならない。本モジュールが作成した
//! 不変 snapshot のみを解析する（規範 §5.5）。
//!
//! 手順（規範 §5.5-1〜9）:
//! 1. 元 Evidence を read-only かつ symlink 非追跡で開く
//! 2. size・mtime・OS file identity を取得し `before` として保持
//! 3. private temporary directory へ新規 snapshot file を作成
//! 4. 固定長 buffer で末尾まで読み、同時に snapshot へ書きながら SHA-256 を計算
//! 5. snapshot を flush し、read-only で再 open
//! 6. 元 handle から再度 metadata を取得し `after` として保持
//! 7. `before` ≠ `after` なら `ChangedDuringSnapshot` として skip
//! 8. snapshot の size と SHA-256 を再検証
//! 9. Parser と YARA-X には同一 snapshot を渡す
//!
//! `VerifiedSnapshot` 以外から Event/YARA Match を生成してはならない（規範 §5.5）。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};
use tf_core::case::{EvidenceItem, IntegrityStatus};
use tf_core::id;

use crate::source_locator::normalize_source_locator;

/// snapshot の読み書きに使う固定長 buffer サイズ（64 KiB）。
const BUFFER_SIZE: usize = 64 * 1024;

/// snapshot 作成前後で比較する file metadata（規範 §5.5-2/6）。
///
/// size・mtime・file identity の3要素で「snapshot 中に元 file が変化したか」を検出する。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    /// file size（byte）。
    pub size: u64,
    /// 最終更新時刻。
    pub modified: Option<SystemTime>,
    /// OS 每 file 識別子（Unix: inode、Windows: file index）。
    /// `None` の場合は size + mtime のみで比較する。
    pub file_index: Option<u64>,
}

impl FileIdentity {
    /// `File` の handle から metadata を取得し `FileIdentity` を構築する。
    fn from_file(file: &File) -> io::Result<Self> {
        let meta = file.metadata()?;
        let size = meta.len();
        let modified = meta.modified().ok();

        // platform 毎の file identity（inode / file index）。
        let file_index = file_identity_from_metadata(&meta);

        Ok(FileIdentity {
            size,
            modified,
            file_index,
        })
    }
}

/// platform 毎に metadata から file 識別子を取り出す。
#[cfg(unix)]
fn file_identity_from_metadata(meta: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(meta.ino())
}

#[cfg(windows)]
fn file_identity_from_metadata(_meta: &fs::Metadata) -> Option<u64> {
    // Windows では std のみでは file index を取得できない。
    // size + mtime の組で変更検出を行う。将来 GetFileInformationByHandle で強化可能。
    None
}

#[cfg(not(any(unix, windows)))]
fn file_identity_from_metadata(_meta: &fs::Metadata) -> Option<u64> {
    None
}

/// snapshot 作成の結果。
///
/// `VerifiedSnapshot` のみが Parser・YARA-X への入力として許可される（規範 §5.5）。
#[derive(Clone, Debug)]
pub struct SnapshotOutcome {
    /// Evidence 情報（ID・size・SHA-256・整合性状態を含む）。
    pub evidence: EvidenceItem,
    /// snapshot file の絶対 path。Parser はこれを read-only で開く。
    pub snapshot_path: PathBuf,
    /// snapshot の SHA-256 lowercase hex（元 Evidence と同一のもの）。
    pub sha256: String,
}

/// snapshot 作成の失敗。
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// 元 Evidence file が symlink（規範 §5.5-1: symlink 非追跡で開く）。
    #[error("元 Evidence が symlink である: {0}")]
    SymlinkDetected(PathBuf),
    /// 元 Evidence file を開けない・読めない。
    #[error("元 Evidence の I/O error: {0}")]
    SourceIo(#[from] io::Error),
    /// snapshot 中に元 Evidence が変化した（規範 §5.5-7: ChangedDuringSnapshot）。
    /// `before` と `after` の metadata を付随する。
    #[error("snapshot 中に元 Evidence が変化した（before={before:?}, after={after:?}）")]
    ChangedDuringSnapshot {
        before: FileIdentity,
        after: FileIdentity,
    },
    /// snapshot の SHA-256 再検証で不一致（規範 §5.5-8）。
    #[error("snapshot の SHA-256 再検証で不一致: 期待={expected}, 実測={actual}")]
    HashVerificationMismatch { expected: String, actual: String },
    /// snapshot の size が元 Evidence と不一致（規範 §5.5-8）。
    #[error("snapshot の size 不一致: 期待={expected}, 実測={actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    /// source_locator の正規化に失敗（規範 §5.2）。
    #[error(transparent)]
    LocatorError(#[from] crate::source_locator::SourceLocatorError),
}

/// 元 Evidence を read-only で開き、不変 snapshot を作成する（規範 §5.5）。
///
/// `source_path` は解析 host 上の file path。`temp_dir` は private な一時 directory。
/// `source_locator_raw` は入力 root からの相対 path（OS separator を含んでよい）。
///
/// 戻り値の `SnapshotOutcome.evidence.integrity_status` は:
/// - `VerifiedSnapshot`: 全手順成功。Parser へ渡してよい。
/// - `ChangedDuringSnapshot`: 元 file が snapshot 中に変化。解析しない。
/// - `SnapshotFailed`: その他の失敗（I/O error・hash 不一致等）。
pub fn snapshot(
    source_locator_raw: &str,
    source_path: &Path,
    temp_dir: &Path,
) -> Result<SnapshotOutcome, SnapshotError> {
    // 規範 §5.5-1: symlink でないことを確認してから read-only で開く。
    let meta = fs::symlink_metadata(source_path)?;
    if meta.is_symlink() {
        return Err(SnapshotError::SymlinkDetected(source_path.to_path_buf()));
    }

    // read-only で開く（規範 §5.5-1）。
    let mut source = File::open(source_path)?;

    // 規範 §5.5-2: before metadata を取得。
    let before = FileIdentity::from_file(&source)?;

    // 規範 §5.5-3: private temp directory へ snapshot を作成。
    let snapshot_path = make_snapshot_path(temp_dir, source_path);
    let mut snapshot_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .truncate(true)
        .open(&snapshot_path)?;

    // 規範 §5.5-4: 固定長 buffer で copy しながら同時 SHA-256 計算。
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total_copied: u64 = 0;
    loop {
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        snapshot_file.write_all(&buffer[..n])?;
        total_copied += n as u64;
    }

    // 規範 §5.5-5: snapshot を flush。
    snapshot_file.flush()?;
    // snapshot file を閉じる（以後 read-only で再 open）。
    drop(snapshot_file);

    // SHA-256 を確定。
    let sha256_hex = hex::encode(hasher.finalize());

    // 規範 §5.5-6: after metadata を取得。
    let after = FileIdentity::from_file(&source)?;

    // 規範 §5.5-7: before ≠ after なら ChangedDuringSnapshot。
    if before != after {
        // 失敗した snapshot を削除する。
        let _ = fs::remove_file(&snapshot_path);
        return Err(SnapshotError::ChangedDuringSnapshot { before, after });
    }

    // 規範 §5.5-8: snapshot の size と SHA-256 を再検証。
    let snapshot_meta = fs::metadata(&snapshot_path)?;
    let actual_size = snapshot_meta.len();
    if actual_size != total_copied {
        let _ = fs::remove_file(&snapshot_path);
        return Err(SnapshotError::SizeMismatch {
            expected: total_copied,
            actual: actual_size,
        });
    }

    // snapshot を読み直して SHA-256 を再計算（規範 §5.5-8）。
    let verify_hash = compute_file_sha256(&snapshot_path)?;
    if verify_hash != sha256_hex {
        let _ = fs::remove_file(&snapshot_path);
        return Err(SnapshotError::HashVerificationMismatch {
            expected: sha256_hex,
            actual: verify_hash,
        });
    }

    // 規範 §5.2: source_locator を正規化。
    let source_locator = normalize_source_locator(source_locator_raw)?;

    // 規範 §5.6: Evidence ID を生成。
    let evidence_id = id::evidence_id(&source_locator, total_copied, &sha256_hex);

    let evidence = EvidenceItem {
        evidence_id,
        source_locator,
        size: total_copied,
        sha256: sha256_hex.clone(),
        integrity_status: IntegrityStatus::VerifiedSnapshot,
        parse_eligible: true,
        snapshot_locator: snapshot_path.to_string_lossy().into_owned(),
    };

    Ok(SnapshotOutcome {
        evidence,
        snapshot_path,
        sha256: sha256_hex,
    })
}

/// 失敗した Evidence の `EvidenceItem` を構築する（`SnapshotFailed` 状態）。
///
/// SHA-256 が計算できなかった場合は空文字列を格納する。
pub fn failed_evidence(
    source_locator_raw: &str,
    size: u64,
    sha256: &str,
) -> Result<EvidenceItem, SnapshotError> {
    let source_locator = normalize_source_locator(source_locator_raw)?;
    let evidence_id = id::evidence_id(&source_locator, size, sha256);
    Ok(EvidenceItem {
        evidence_id,
        source_locator,
        size,
        sha256: sha256.to_string(),
        integrity_status: IntegrityStatus::SnapshotFailed,
        parse_eligible: false,
        snapshot_locator: String::new(),
    })
}

/// file 全体の SHA-256 を計算する。
fn compute_file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// snapshot file の path を生成する。
///
/// 元 file 名と PID を組み合わせて一意性を確保する。
fn make_snapshot_path(temp_dir: &Path, source: &Path) -> PathBuf {
    let name = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("evidence");
    let pid = std::process::id();
    // nanoid や UUID は使わない（規範 §12: 決定的 ID のみ）が、
    // snapshot file 名は runtime 情報（private）なので非決定的でよい（規範 §13.1 除外項目）。
    let snapshot_name = format!("{name}.{pid}.snapshot");
    temp_dir.join(snapshot_name)
}

/// snapshot file を read-only で開く（規範 §5.5-5: read-only 再 open）。
///
/// Parser は元 Evidence ではなく、この snapshot handle から読む（規範 §5.5-9）。
pub fn open_snapshot_readonly(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_env() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("test.evtx");
        fs::write(&source, b"hello world").unwrap();
        let temp_dir = dir.path().join("snapshots");
        fs::create_dir(&temp_dir).unwrap();
        (dir, source, temp_dir)
    }

    #[test]
    fn snapshot_creates_verified_copy() {
        let (_dir, source, temp_dir) = create_test_env();

        let outcome = snapshot("test.evtx", &source, &temp_dir).unwrap();

        // 規範 §5.5: VerifiedSnapshot である。
        assert_eq!(
            outcome.evidence.integrity_status,
            IntegrityStatus::VerifiedSnapshot
        );
        assert!(outcome.evidence.parse_eligible);

        // snapshot file が存在する。
        assert!(outcome.snapshot_path.exists());

        // snapshot の内容が元 file と一致する。
        let snapshot_content = fs::read(&outcome.snapshot_path).unwrap();
        assert_eq!(snapshot_content, b"hello world");

        // SHA-256 が正しい（"hello world" の SHA-256）。
        let expected = sha2_hex(b"hello world");
        assert_eq!(outcome.sha256, expected);
    }

    #[test]
    fn snapshot_sha256_matches_content() {
        // 規範 §21-4: snapshot SHA-256 と読取 bytes が一致する。
        let (_dir, source, temp_dir) = create_test_env();
        let outcome = snapshot("test.evtx", &source, &temp_dir).unwrap();

        // snapshot を読み直して SHA-256 を計算。
        let snapshot_bytes = fs::read(&outcome.snapshot_path).unwrap();
        let recomputed = sha2_hex(&snapshot_bytes);
        assert_eq!(outcome.sha256, recomputed);
        assert_eq!(outcome.evidence.sha256, recomputed);
    }

    #[test]
    fn snapshot_evidence_id_is_deterministic() {
        let (_dir, source, temp_dir) = create_test_env();

        let a = snapshot("test.evtx", &source, &temp_dir).unwrap();
        // snapshot file を削除して再作成。
        fs::remove_file(&a.snapshot_path).unwrap();
        let b = snapshot("test.evtx", &source, &temp_dir).unwrap();

        // 規範 §13.1: 同一入力なら同一 Evidence ID。
        assert_eq!(a.evidence.evidence_id, b.evidence.evidence_id);
        assert_eq!(a.sha256, b.sha256);
    }

    #[test]
    fn snapshot_rejects_symlink_source() {
        // 規範 §5.5-1: symlink 非追跡で開く。
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = tempfile::tempdir().unwrap();
            let real = dir.path().join("real.evtx");
            fs::write(&real, b"data").unwrap();
            let link = dir.path().join("link.evtx");
            symlink(&real, &link).unwrap();

            let temp_dir = dir.path().join("tmp");
            fs::create_dir(&temp_dir).unwrap();

            let result = snapshot("link.evtx", &link, &temp_dir);
            assert!(matches!(result, Err(SnapshotError::SymlinkDetected(_))));
        }
    }

    #[test]
    fn file_identity_detects_size_change() {
        // 規範 §5.5-7: before/after の FileIdentity 比較で size 変化を検出する。
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("target.evtx");
        fs::write(&source, b"initial").unwrap();

        let file = File::open(&source).unwrap();
        let before = FileIdentity::from_file(&file).unwrap();
        drop(file);

        // 元 file の size を変える。
        fs::write(&source, b"modified content is longer than initial").unwrap();

        let file = File::open(&source).unwrap();
        let after = FileIdentity::from_file(&file).unwrap();

        assert_ne!(before.size, after.size);
        assert_ne!(before, after);
    }

    #[test]
    fn file_identity_detects_mtime_change() {
        // 規範 §5.5-7: size が同じでも mtime 変化を検出する。
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("target.evtx");
        fs::write(&source, b"12345678").unwrap();

        let file = File::open(&source).unwrap();
        let before = FileIdentity::from_file(&file).unwrap();
        drop(file);

        // 同じ size で内容だけ変える + mtime を未来時刻へ設定。
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(&source, b"87654321").unwrap();
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        let f = File::options().write(true).open(&source).unwrap();
        let _ = f.set_times(std::fs::FileTimes::new().set_modified(future));
        drop(f);

        let file = File::open(&source).unwrap();
        let after = FileIdentity::from_file(&file).unwrap();

        assert_eq!(before.size, after.size, "size は同じ");
        assert_ne!(before.modified, after.modified, "mtime は変化");
        assert_ne!(before, after);
    }

    #[test]
    fn snapshot_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("empty.evtx");
        fs::write(&source, b"").unwrap();
        let temp_dir = dir.path().join("tmp");
        fs::create_dir(&temp_dir).unwrap();

        let outcome = snapshot("empty.evtx", &source, &temp_dir).unwrap();
        assert_eq!(outcome.evidence.size, 0);
        // 空 file の SHA-256。
        assert_eq!(outcome.sha256, sha2_hex(b""));
    }

    #[test]
    fn snapshot_large_file_integrity() {
        // buffer 境界（64 KiB）をまたぐ file で hash が正しく計算されるか。
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("large.evtx");
        let content: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
        fs::write(&source, &content).unwrap();
        let temp_dir = dir.path().join("tmp");
        fs::create_dir(&temp_dir).unwrap();

        let outcome = snapshot("large.evtx", &source, &temp_dir).unwrap();
        assert_eq!(outcome.evidence.size, 200_000);
        assert_eq!(outcome.sha256, sha2_hex(&content));
    }

    #[test]
    fn snapshot_source_locator_normalized() {
        // 規範 §5.2: separator 正規化。
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("file.evtx");
        fs::write(&source, b"x").unwrap();
        let temp_dir = dir.path().join("tmp");
        fs::create_dir(&temp_dir).unwrap();

        let outcome = snapshot(r"sub\file.evtx", &source, &temp_dir).unwrap();
        assert_eq!(outcome.evidence.source_locator, "sub/file.evtx");
    }

    #[test]
    fn snapshot_file_cannot_be_symlink_output() {
        // snapshot_path が意図しない場所へ上書きしないことを確認。
        // create_new を使っているため既存 file があると error。
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("a.evtx");
        fs::write(&source, b"data").unwrap();
        let temp_dir = dir.path().join("tmp");
        fs::create_dir(&temp_dir).unwrap();

        // 先に同じ名前の snapshot file を作る。
        let pid = std::process::id();
        let pre_existing = temp_dir.join(format!("a.evtx.{pid}.snapshot"));
        fs::write(&pre_existing, b"existing").unwrap();

        // 2回目は create_new なので失敗するはず。
        let result = snapshot("a.evtx", &source, &temp_dir);
        assert!(result.is_err());
    }

    /// test 用: SHA-256 hex を計算。
    fn sha2_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }
}
