//! File metrics array と filename strings（libyal PF format、T4-021）。
//!
//! File metrics array は「executable が読み込んだ file/directory」の一覧。
//! 各 entry が filename strings block 中の文字列を指す。version 毎に entry size が異なる:
//!
//! - v17: 20 byte（trace chain index / trace count / filename offset / filename 文字数 / flags）
//! - v23 以降: 32 byte（上記に prefetch blocks・file reference が追加）
//!
//! 本 Parser は filename 文字列（参照 file/directory）を観測目的で取得する。
//! trace chain・file reference は解析しても Event 化に必須ではないため読み飛ばす。

/// v17 の file metrics entry size（byte）。
pub const METRICS_ENTRY_V17: usize = 20;
/// v23 以降の file metrics entry size（byte）。
pub const METRICS_ENTRY_V23: usize = 32;

/// 参照 file/directory の1件分（filename strings から切り出した文字列）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferencedFile {
    /// UTF-16LE から変換した file/directory path。
    pub name: String,
}

/// File metrics entry から取得すべき値。
///
/// trace chain 等の本 Parser が観測しない field はここへ含めない。
#[derive(Clone, Debug)]
pub struct MetricsFields {
    /// Filename strings block 先頭からの offset（byte）。
    pub filename_offset: u32,
    /// Filename の UTF-16 code unit 数（終端 null を含まない）。
    pub filename_chars: u32,
}

impl MetricsFields {
    /// v17 entry（20 byte）から filename 関連 field を取り出す。
    pub fn parse_v17(buf: &[u8]) -> Option<MetricsFields> {
        if buf.len() < METRICS_ENTRY_V17 {
            return None;
        }
        let filename_offset = rd_u32(buf, 8)?;
        let filename_chars = rd_u32(buf, 12)?;
        Some(MetricsFields {
            filename_offset,
            filename_chars,
        })
    }

    /// v23 以降の entry（32 byte）から filename 関連 field を取り出す。
    pub fn parse_v23(buf: &[u8]) -> Option<MetricsFields> {
        if buf.len() < METRICS_ENTRY_V23 {
            return None;
        }
        let filename_offset = rd_u32(buf, 12)?;
        let filename_chars = rd_u32(buf, 16)?;
        Some(MetricsFields {
            filename_offset,
            filename_chars,
        })
    }
}

/// version に応じた file metrics entry size を返す。
pub fn entry_size_for(version: u32) -> Option<usize> {
    match version {
        17 => Some(METRICS_ENTRY_V17),
        23 | 26 | 30 | 31 => Some(METRICS_ENTRY_V23),
        _ => None,
    }
}

/// File metrics array と filename strings block から参照 file 一覧を構築する。
///
/// - `metrics_buf`: file metrics array 全体（`metrics_count * entry_size` 以上を想定）。
///   呼出側で file 先頭からの offset に基づき切り出しておくこと。
/// - `strings_buf`: filename strings block 全体。
/// - `entry_size`: version に応じた1 entry の byte 数。
///
/// 境界外を指す entry や UTF-16 変換に失敗した entry は安全に skip する
/// （互換 §12-2: 破損で panic しない）。最大取得件数は呼出側で制限済みを前提とする。
pub fn collect_referenced_files(
    metrics_buf: &[u8],
    strings_buf: &[u8],
    entry_size: usize,
    parse_fn: fn(&[u8]) -> Option<MetricsFields>,
) -> Vec<ReferencedFile> {
    let mut out = Vec::new();
    let mut iter = metrics_buf.chunks_exact(entry_size);
    for entry in iter.by_ref() {
        let Some(fields) = parse_fn(entry) else {
            continue;
        };
        if let Some(name) = read_filename_string(strings_buf, fields) {
            out.push(ReferencedFile { name });
        }
    }
    out
}

/// filename strings block から1件の文字列を取り出す。
///
/// `filename_offset` は strings block 先頭からの byte offset。
/// `filename_chars` は UTF-16 code unit 数。終端 null は含まない。
fn read_filename_string(strings_buf: &[u8], fields: MetricsFields) -> Option<String> {
    let start = usize::try_from(fields.filename_offset).ok()?;
    let char_count = usize::try_from(fields.filename_chars).ok()?;
    let byte_len = char_count.checked_mul(2)?;
    let end = start.checked_add(byte_len)?;
    let slice = strings_buf.get(start..end)?;
    // char_count が大きすぎて実データが足りない場合は、安全のため None。
    // （過大 offset 攻撃対策・互換 §12-2）
    let units: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // 終端 null が紛れ込んでいれば除去。
    let trimmed: Vec<u16> = units.into_iter().take_while(|&u| u != 0).collect();
    Some(String::from_utf16_lossy(&trimmed))
}

fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_strings(names: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for n in names {
            for u in n.encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes()); // null 終端
        }
        buf
    }

    #[test]
    fn read_filename_string_basic() {
        let strings = build_strings(&["\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\NOTEPAD.EXE"]);
        // char_count を実際の長さに合わせる
        let real_chars = "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\NOTEPAD.EXE"
            .encode_utf16()
            .count() as u32;
        let fields = MetricsFields {
            filename_offset: 0,
            filename_chars: real_chars,
        };
        let s = read_filename_string(&strings, fields).unwrap();
        assert_eq!(s, "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\NOTEPAD.EXE");
    }

    #[test]
    fn collect_v23_entries() {
        let strings = build_strings(&["\\VOLUME1\\A.DLL", "\\VOLUME1\\B.DLL"]);
        // entry_size = 32 (v23+). filename offset は entry[12..16], chars は [16..20].
        let a_off = 0u32;
        let a_chars = "\\VOLUME1\\A.DLL".encode_utf16().count() as u32;
        let b_off = (("\\VOLUME1\\A.DLL".len() + 1) * 2) as u32; // null 含む次の開始
        let b_chars = "\\VOLUME1\\B.DLL".encode_utf16().count() as u32;

        let mut metrics = Vec::new();
        // entry 1
        let mut e1 = vec![0u8; METRICS_ENTRY_V23];
        e1[12..16].copy_from_slice(&a_off.to_le_bytes());
        e1[16..20].copy_from_slice(&a_chars.to_le_bytes());
        // entry 2
        let mut e2 = vec![0u8; METRICS_ENTRY_V23];
        e2[12..16].copy_from_slice(&b_off.to_le_bytes());
        e2[16..20].copy_from_slice(&b_chars.to_le_bytes());
        metrics.extend_from_slice(&e1);
        metrics.extend_from_slice(&e2);

        let files = collect_referenced_files(
            &metrics,
            &strings,
            METRICS_ENTRY_V23,
            MetricsFields::parse_v23,
        );
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "\\VOLUME1\\A.DLL");
        assert_eq!(files[1].name, "\\VOLUME1\\B.DLL");
    }

    #[test]
    fn collect_skips_out_of_bounds() {
        let strings = build_strings(&["SHORT"]);
        let mut metrics = Vec::new();
        let mut e = vec![0u8; METRICS_ENTRY_V23];
        // 過大 offset を仕込む。
        e[12..16].copy_from_slice(&999_999u32.to_le_bytes());
        e[16..20].copy_from_slice(&5u32.to_le_bytes());
        metrics.extend_from_slice(&e);
        let files = collect_referenced_files(
            &metrics,
            &strings,
            METRICS_ENTRY_V23,
            MetricsFields::parse_v23,
        );
        assert!(files.is_empty(), "過大 offset は安全に skip");
    }

    #[test]
    fn entry_size_for_versions() {
        assert_eq!(entry_size_for(17), Some(METRICS_ENTRY_V17));
        assert_eq!(entry_size_for(23), Some(METRICS_ENTRY_V23));
        assert_eq!(entry_size_for(31), Some(METRICS_ENTRY_V23));
        assert_eq!(entry_size_for(99), None);
    }
}
