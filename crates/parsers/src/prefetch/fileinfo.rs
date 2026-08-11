//! File information block（libyal PF format、T4-021）。
//!
//! File header（84 byte）の直後に続く、実行痕跡の要情報:
//!
//! - 各 section（file metrics / trace chains / filename strings / volumes）への
//!   offset と size
//! - Last run time（FILETIME）。v17/v23 は1個、v26/v30/v31 は最大8個
//! - Run count（実行回数）
//!
//! version 毎に layout と size が異なるため、[`FileInfo`] へ正規化して返す。
//! 未知 version は呼出側で弾くため、本 module は5 version のみ扱う。

/// Last run time の最大保持数（v26/v30/v31）。
pub const MAX_RUN_TIMES: usize = 8;

/// File information block から抽出した正規化済み情報。
#[derive(Clone, Debug)]
pub struct FileInfo {
    /// File metrics array の offset（file 先頭からの絶対 byte offset）。
    pub metrics_offset: u32,
    /// File metrics entry 数。
    pub metrics_count: u32,
    /// Filename strings block の offset（file 先頭からの絶対 byte offset）。
    pub filename_strings_offset: u32,
    /// Filename strings block の size（byte）。
    pub filename_strings_size: u32,
    /// Volumes information の offset（file 先頭からの絶対 byte offset）。
    pub volumes_offset: u32,
    /// Volume 数。
    pub volumes_count: u32,
    /// Last run time（FILETIME）。0 は「未設定」。先頭ほど最近の実行。
    pub last_run_times: [u64; MAX_RUN_TIMES],
    /// Run count（実行回数）。
    pub run_count: u32,
}

impl FileInfo {
    /// version 17 用の file information block（68 byte）を解析する。
    ///
    /// layout（libyal より）:
    /// | offset | size | 内容 |
    /// |--------|------|------|
    /// | 0  | 4 | metrics offset |
    /// | 4  | 4 | metrics count |
    /// | 8  | 4 | trace chains offset |
    /// | 12 | 4 | trace chains count |
    /// | 16 | 4 | filename strings offset |
    /// | 20 | 4 | filename strings size |
    /// | 24 | 4 | volumes offset |
    /// | 28 | 4 | volumes count |
    /// | 32 | 4 | volumes size |
    /// | 36 | 8 | last run time（単一）|
    /// | 44 | 16 | 不明 |
    /// | 60 | 4 | run count |
    /// | 64 | 4 | 不明 |
    pub fn parse_v17(buf: &[u8]) -> Option<FileInfo> {
        const LEN: usize = 68;
        if buf.len() < LEN {
            return None;
        }
        let metrics_offset = rd_u32(buf, 0)?;
        let metrics_count = rd_u32(buf, 4)?;
        let filename_strings_offset = rd_u32(buf, 16)?;
        let filename_strings_size = rd_u32(buf, 20)?;
        let volumes_offset = rd_u32(buf, 24)?;
        let volumes_count = rd_u32(buf, 28)?;
        let last_run_0 = rd_u64(buf, 36)?;
        let run_count = rd_u32(buf, 60)?;

        let mut last_run_times = [0u64; MAX_RUN_TIMES];
        last_run_times[0] = last_run_0;

        Some(FileInfo {
            metrics_offset,
            metrics_count,
            filename_strings_offset,
            filename_strings_size,
            volumes_offset,
            volumes_count,
            last_run_times,
            run_count,
        })
    }

    /// version 23 用の file information block（156 byte）を解析する。
    /// v17 との差分: offset 36 が 8 byte の不明領域、last run time は offset 44（8 byte）。
    /// run count は offset 68。
    pub fn parse_v23(buf: &[u8]) -> Option<FileInfo> {
        const LEN: usize = 156;
        if buf.len() < LEN {
            return None;
        }
        let metrics_offset = rd_u32(buf, 0)?;
        let metrics_count = rd_u32(buf, 4)?;
        let filename_strings_offset = rd_u32(buf, 16)?;
        let filename_strings_size = rd_u32(buf, 20)?;
        let volumes_offset = rd_u32(buf, 24)?;
        let volumes_count = rd_u32(buf, 28)?;
        let last_run_0 = rd_u64(buf, 44)?;
        let run_count = rd_u32(buf, 68)?;

        let mut last_run_times = [0u64; MAX_RUN_TIMES];
        last_run_times[0] = last_run_0;

        Some(FileInfo {
            metrics_offset,
            metrics_count,
            filename_strings_offset,
            filename_strings_size,
            volumes_offset,
            volumes_count,
            last_run_times,
            run_count,
        })
    }

    /// version 26 / 30 / 31 用の file information block（220 byte）を解析する。
    ///
    /// これら3 version は前半（offset 0..136）が共通:
    /// - offset 44 に8個の last run time（各 8 byte = 64 byte）
    /// - offset 124 に run count
    ///
    /// v30/v31 の後半（hash string 等）は本 Parser では観測しないため、
    /// 先頭 136 byte が読めれば解析を成功とする。
    pub fn parse_v26(buf: &[u8]) -> Option<FileInfo> {
        // v26 の block size は 220 byte だが、本 Parser が使うのは先頭 136 byte。
        // 呼出側で過不足なく渡すため、136 byte 以上を要求する。
        const USED_LEN: usize = 136;
        if buf.len() < USED_LEN {
            return None;
        }
        let metrics_offset = rd_u32(buf, 0)?;
        let metrics_count = rd_u32(buf, 4)?;
        let filename_strings_offset = rd_u32(buf, 16)?;
        let filename_strings_size = rd_u32(buf, 20)?;
        let volumes_offset = rd_u32(buf, 24)?;
        let volumes_count = rd_u32(buf, 28)?;

        let mut last_run_times = [0u64; MAX_RUN_TIMES];
        for (i, slot) in last_run_times.iter_mut().enumerate() {
            *slot = rd_u64(buf, 44 + i * 8)?;
        }
        let run_count = rd_u32(buf, 124)?;

        Some(FileInfo {
            metrics_offset,
            metrics_count,
            filename_strings_offset,
            filename_strings_size,
            volumes_offset,
            volumes_count,
            last_run_times,
            run_count,
        })
    }

    /// 指定 version へ対応する file information block の想定 size（byte）を返す。
    /// 境界検証（block が途中で切れていないか）に使う。
    pub fn expected_block_len(version: u32) -> Option<usize> {
        match version {
            17 => Some(68),
            23 => Some(156),
            26 | 31 => Some(220),
            // v30 には variant 1（220）と variant 2（212）があるが、
            // 本 Parser は先頭 136 byte の共通部しか読まないため安全側へ 212 を下限とする。
            30 => Some(212),
            _ => None,
        }
    }
}

fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(off..off + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v17_basic() {
        let mut buf = vec![0u8; 68];
        // metrics offset = 152, count = 2
        buf[0..4].copy_from_slice(&152u32.to_le_bytes());
        buf[4..8].copy_from_slice(&2u32.to_le_bytes());
        // filename strings offset = 200, size = 64
        buf[16..20].copy_from_slice(&200u32.to_le_bytes());
        buf[20..24].copy_from_slice(&64u32.to_le_bytes());
        // volumes offset = 300, count = 1
        buf[24..28].copy_from_slice(&300u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1u32.to_le_bytes());
        // last run time = 12345
        buf[36..44].copy_from_slice(&12345u64.to_le_bytes());
        // run count = 5
        buf[60..64].copy_from_slice(&5u32.to_le_bytes());

        let fi = FileInfo::parse_v17(&buf).unwrap();
        assert_eq!(fi.metrics_offset, 152);
        assert_eq!(fi.metrics_count, 2);
        assert_eq!(fi.filename_strings_offset, 200);
        assert_eq!(fi.volumes_offset, 300);
        assert_eq!(fi.volumes_count, 1);
        assert_eq!(fi.last_run_times[0], 12345);
        assert_eq!(fi.run_count, 5);
        // 残りの run time slot は 0。
        assert_eq!(fi.last_run_times[1], 0);
    }

    #[test]
    fn parse_v23_run_time_at_offset_44() {
        let mut buf = vec![0u8; 156];
        buf[44..52].copy_from_slice(&999u64.to_le_bytes());
        buf[68..72].copy_from_slice(&7u32.to_le_bytes());
        let fi = FileInfo::parse_v23(&buf).unwrap();
        assert_eq!(fi.last_run_times[0], 999);
        assert_eq!(fi.run_count, 7);
    }

    #[test]
    fn parse_v26_eight_run_times() {
        let mut buf = vec![0u8; 220];
        for i in 0..MAX_RUN_TIMES {
            buf[44 + i * 8..44 + i * 8 + 8].copy_from_slice(&((i + 1) as u64).to_le_bytes());
        }
        buf[124..128].copy_from_slice(&42u32.to_le_bytes());
        let fi = FileInfo::parse_v26(&buf).unwrap();
        for i in 0..MAX_RUN_TIMES {
            assert_eq!(fi.last_run_times[i], (i + 1) as u64);
        }
        assert_eq!(fi.run_count, 42);
    }

    #[test]
    fn parse_returns_none_on_truncated() {
        let short = vec![0u8; 30];
        assert!(FileInfo::parse_v17(&short).is_none());
        assert!(FileInfo::parse_v23(&short).is_none());
        assert!(FileInfo::parse_v26(&short).is_none());
    }

    #[test]
    fn expected_block_len_known_versions() {
        assert_eq!(FileInfo::expected_block_len(17), Some(68));
        assert_eq!(FileInfo::expected_block_len(23), Some(156));
        assert_eq!(FileInfo::expected_block_len(26), Some(220));
        assert_eq!(FileInfo::expected_block_len(30), Some(212));
        assert_eq!(FileInfo::expected_block_len(31), Some(220));
        assert_eq!(FileInfo::expected_block_len(99), None);
    }
}
