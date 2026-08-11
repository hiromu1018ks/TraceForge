//! LinkInfo 解析（[MS-SHLLINK] §2.3、互換 §4.4）。
//!
//! LinkInfo は local または network の target 情報を保持する。本 Parser は
//! 最低限 `LocalBasePath` と `CommonPathSuffix` を取り、target path を復元する。
//! network target（`CommonNetworkRelativeLink`）は v1.0 では未対応（将来拡張）。
//!
//! ```text
//! Offset  Size  Field
//! 0       4     LinkInfoSize       (u32 LE) ── LinkInfo 全体の byte 長
//! 4       4     LinkInfoHeaderSize (u32 LE) ── 0x1C (v1) または 0x24 (v2)
//! 8       4     LinkInfoFlags      (u32 LE) ── bit0=VolumeIDAndLocalBasePath, bit1=CommonNetworkRelativeLink
//! 12      4     VolumeIDOffset     (u32 LE)
//! 16      4     LocalBasePathOffset(u32 LE) ── LinkInfo 先頭からの offset
//! 20      4     CommonNetworkRelativeLinkOffset (u32 LE)
//! 24      4     CommonPathSuffixOffset (u32 LE) ── LinkInfo 先頭からの offset
//! -- v2 以降は LocalBasePathOffsetUnicode と CommonPathSuffixOffsetUnicode が続く
//! VolumeID / LocalBasePath / CommonPathSuffix 等は可変長で後続する
//! ```
//!
//! LocalBasePath は null-terminated ASCII 文字列。CommonPathSuffix も同様。
//! target path は `LocalBasePath + CommonPathSuffix` を結合したもの。

use crate::framework::ReadSeek;

/// LinkInfo v1 header size。
const LINKINFO_HEADER_V1: u32 = 0x0000_001C;
/// LinkInfo v2 header size（Unicode path offset 追加）。
const LINKINFO_HEADER_V2: u32 = 0x0000_0024;

/// LinkInfoFlags bit0: VolumeIDAndLocalBasePath（local target が存在する）。
const LIF_VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x01;

/// 解析済みの LinkInfo。
#[derive(Clone, Debug, Default)]
pub struct LinkInfo {
    /// LinkInfo 全体の byte 長。
    pub link_info_size: u32,
    /// LinkInfoHeaderSize（version 判定に使う）。
    pub link_info_header_size: u32,
    /// LocalBasePath（null 終端を除いた ASCII 文字列）。`VolumeIDAndLocalBasePath` flag 時のみ。
    pub local_base_path: Option<String>,
    /// CommonPathSuffix（null 終端を除いた ASCII 文字列）。
    pub common_path_suffix: Option<String>,
    /// LinkInfo section の全消費 byte 数。
    pub consumed_bytes: u64,
}

/// LinkInfo 解析の error。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkInfoError {
    /// LinkInfoSize を読む前に EOF。
    TruncatedSize,
    /// LinkInfoSize が小さすぎる（header すら入らない）。
    InvalidSize(u32),
    /// LinkInfo 本体が短い（宣言された Size 分の byte が無い）。
    TruncatedBody,
    /// 不正な offset（LinkInfoSize を越える）。
    InvalidOffset(u32),
}

/// Header 直後（LinkInfo section がある場合）から LinkInfo を読む。
///
/// `ForceNoLinkInfo` flag の場合は呼出側がこの関数を呼ばないこと。
pub fn read_link_info(reader: &mut dyn ReadSeek) -> Result<LinkInfo, LinkInfoError> {
    // LinkInfoSize (4 byte LE)。
    let mut size_buf = [0u8; 4];
    reader
        .read_exact(&mut size_buf)
        .map_err(|_| LinkInfoError::TruncatedSize)?;
    let link_info_size = u32::from_le_bytes(size_buf);

    if link_info_size < 4 {
        return Err(LinkInfoError::InvalidSize(link_info_size));
    }

    // LinkInfoSize が header v1 より小さい場合は不正。
    if link_info_size < LINKINFO_HEADER_V1 {
        return Err(LinkInfoError::InvalidSize(link_info_size));
    }

    // LinkInfo 全体を buffer へ読む。境界検証を安全に行うため。
    // 既に LinkInfoSize (4 byte) を読んだので、残り (link_info_size - 4) を読む。
    let remaining = (link_info_size as usize).saturating_sub(4);
    let mut body = vec![0u8; remaining];
    reader
        .read_exact(&mut body)
        .map_err(|_| LinkInfoError::TruncatedBody)?;

    // body の先頭 4 byte は LinkInfoHeaderSize。
    if body.len() < 4 {
        return Err(LinkInfoError::InvalidSize(link_info_size));
    }
    let header_size = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    if header_size != LINKINFO_HEADER_V1 && header_size != LINKINFO_HEADER_V2 {
        // 未知の header size は安全のため LocalBasePath 無しで記録する（解析自体は継続）。
        return Ok(LinkInfo {
            link_info_size,
            link_info_header_size: header_size,
            local_base_path: None,
            common_path_suffix: None,
            consumed_bytes: link_info_size as u64,
        });
    }

    // header v1 / v2 に必要な field が body 内にあるか。
    if body.len() < (LINKINFO_HEADER_V1 as usize - 4) {
        return Err(LinkInfoError::InvalidSize(link_info_size));
    }

    let flags = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let local_base_path_offset = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
    let common_path_suffix_offset = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);

    let mut local_base_path: Option<String> = None;
    let mut common_path_suffix: Option<String> = None;

    // VolumeIDAndLocalBasePath が立っていれば LocalBasePath を取る。
    if flags & LIF_VOLUME_ID_AND_LOCAL_BASE_PATH != 0
        && let Some(path) = read_null_terminated(&body, local_base_path_offset, link_info_size)?
    {
        local_base_path = Some(path);
    }
    // CommonPathSuffix は常に存在し得る。
    if let Some(suffix) = read_null_terminated(&body, common_path_suffix_offset, link_info_size)? {
        common_path_suffix = Some(suffix);
    }

    Ok(LinkInfo {
        link_info_size,
        link_info_header_size: header_size,
        local_base_path,
        common_path_suffix,
        consumed_bytes: link_info_size as u64,
    })
}

/// `body`（LinkInfo 全体、LinkInfoSize field を除く）内の `offset` から
/// null 終端 ASCII 文字列を読む。`body` の index は `offset - 4`（LinkInfoSize field 分を引く）。
fn read_null_terminated(
    body: &[u8],
    offset_in_link_info: u32,
    link_info_size: u32,
) -> Result<Option<String>, LinkInfoError> {
    if offset_in_link_info == 0 || offset_in_link_info >= link_info_size {
        // offset 0 は無効。LinkInfoSize を越える offset も無効。
        return if offset_in_link_info >= link_info_size {
            Err(LinkInfoError::InvalidOffset(offset_in_link_info))
        } else {
            Ok(None)
        };
    }
    // body は「LinkInfoSize を除く」ため、body_index = offset - 4。
    let body_index = (offset_in_link_info as usize).saturating_sub(4);
    if body_index >= body.len() {
        return Ok(None);
    }
    // null terminator を探す。
    let slice = &body[body_index..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let bytes = &slice[..end];
    // ASCII 文字列を UTF-8 へ安全変換（CP_ACP は lossy）。
    Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
}

/// LinkInfo の LocalBasePath と CommonPathSuffix を結合して target path を復元する。
///
/// どちらかが無ければ `None` を返す。
pub fn reconstruct_target_path(link_info: &LinkInfo) -> Option<String> {
    let base = link_info.local_base_path.as_ref()?;
    let suffix = link_info.common_path_suffix.as_deref().unwrap_or("");
    if suffix.is_empty() {
        Some(base.clone())
    } else {
        Some(format!("{base}{suffix}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cursor(data: Vec<u8>) -> Cursor<Vec<u8>> {
        Cursor::new(data)
    }

    /// v1 LinkInfo を構築する。LocalBasePath と CommonPathSuffix を含む。
    fn build_v1_link_info(local_base: &str, suffix: &str) -> Vec<u8> {
        // LinkInfo 全体の byte 長を計算する。
        // Layout: LinkInfoSize(4) + HeaderSize(4) + Flags(4) + VolumeIDOffset(4) +
        //         LocalBasePathOffset(4) + CommonNetworkRelativeLinkOffset(4) +
        //         CommonPathSuffixOffset(4) = 28 byte header。
        // 続いて VolumeID（最小 4 byte の dummy）+ LocalBasePath(null 含む) +
        // CommonPathSuffix(null 含む)。
        let header_size: u32 = LINKINFO_HEADER_V1; // 0x1C
        let volume_id_offset: u32 = header_size; // header 直後
        let volume_id_size: u32 = 4; // dummy VolumeID（size のみ）
        let local_base_offset: u32 = volume_id_offset + volume_id_size;
        let local_base_with_null = format!("{local_base}\0");
        let suffix_offset: u32 = local_base_offset + local_base_with_null.len() as u32;
        let suffix_with_null = format!("{suffix}\0");
        let total_size: u32 = suffix_offset + suffix_with_null.len() as u32;

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&total_size.to_le_bytes());
        buf.extend_from_slice(&header_size.to_le_bytes());
        buf.extend_from_slice(&LIF_VOLUME_ID_AND_LOCAL_BASE_PATH.to_le_bytes()); // Flags
        buf.extend_from_slice(&volume_id_offset.to_le_bytes());
        buf.extend_from_slice(&local_base_offset.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset
        buf.extend_from_slice(&suffix_offset.to_le_bytes());
        // VolumeID dummy
        buf.extend_from_slice(&volume_id_size.to_le_bytes());
        // LocalBasePath
        buf.extend_from_slice(local_base_with_null.as_bytes());
        // CommonPathSuffix
        buf.extend_from_slice(suffix_with_null.as_bytes());
        assert_eq!(buf.len() as u32, total_size);
        buf
    }

    #[test]
    fn read_v1_with_local_base_path() {
        let data = build_v1_link_info("C:\\Users\\alice", "\\file.txt");
        let mut c = cursor(data);
        // cursor を先頭から（実際は LinkInfo section 先頭）。
        let li = read_link_info(&mut c).unwrap();
        assert_eq!(li.local_base_path.as_deref(), Some("C:\\Users\\alice"));
        assert_eq!(li.common_path_suffix.as_deref(), Some("\\file.txt"));
        let target = reconstruct_target_path(&li).unwrap();
        assert_eq!(target, "C:\\Users\\alice\\file.txt");
    }

    #[test]
    fn read_v1_empty_suffix() {
        let data = build_v1_link_info("C:\\Windows\\notepad.exe", "");
        let mut c = cursor(data);
        let li = read_link_info(&mut c).unwrap();
        assert_eq!(
            li.local_base_path.as_deref(),
            Some("C:\\Windows\\notepad.exe")
        );
        let target = reconstruct_target_path(&li).unwrap();
        assert_eq!(target, "C:\\Windows\\notepad.exe");
    }

    #[test]
    fn read_truncated_size() {
        // 規範 §9.2: truncated で panic しない。
        let mut c = cursor(vec![0u8; 2]);
        let err = read_link_info(&mut c).unwrap_err();
        assert_eq!(err, LinkInfoError::TruncatedSize);
    }

    #[test]
    fn read_truncated_body() {
        // LinkInfoSize = 100 を宣言するが、body が短い。
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&100u32.to_le_bytes()); // LinkInfoSize
        buf.extend_from_slice(&[0u8; 10]); // 10 byte しか無い
        let mut c = cursor(buf);
        let err = read_link_info(&mut c).unwrap_err();
        assert_eq!(err, LinkInfoError::TruncatedBody);
    }

    #[test]
    fn read_unknown_header_size_returns_safe_linkinfo() {
        // 未知 header size は LocalBasePath 無しで安全に記録する（解析継続）。
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&28u32.to_le_bytes()); // LinkInfoSize
        buf.extend_from_slice(&0x99u32.to_le_bytes()); // 未知 HeaderSize
        buf.extend_from_slice(&[0u8; 20]); // 残り
        let mut c = cursor(buf);
        let li = read_link_info(&mut c).unwrap();
        assert_eq!(li.link_info_size, 28);
        assert_eq!(li.link_info_header_size, 0x99);
        assert!(li.local_base_path.is_none());
    }
}
