//! LinkTargetIDList 解析（[MS-SHLLINK] §2.2）。
//!
//! ```text
//! Offset  Size  Field
//! 0       2     IDListSize  (u16 LE) ── IDList の byte 長（TerminalID を含む）
//! IDList: ItemID の列
//!   各 ItemID:
//!     2     ItemIDSize  (u16 LE) ── ItemID の byte 長（size field 自身を含まない）
//!     ItemIDSize byte  ItemID ── 任意内容。未知 ItemID は raw byte を保持する
//!   TerminalID: 0x0000 (u16 LE) ── IDList 終端
//! ```
//!
//! ItemID の内容は shell namespace item へ依存し、仕様上は可変長で任意。本 Parser は
//! 各 ItemID を raw byte として保持し、未知 item を黙って無視せず記録する（互換 §4.4）。

use std::io::SeekFrom;

use crate::framework::ReadSeek;

/// 1 個の ItemID（raw byte）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawItemId {
    /// ItemIDSize（size field 自身を除いた byte 長）。
    pub size: u16,
    /// ItemID の raw byte（size 分の長さ）。
    pub bytes: Vec<u8>,
}

/// 解析済みの LinkTargetIDList。
#[derive(Clone, Debug, Default)]
pub struct LinkTargetIdList {
    /// IDList 全体の byte 長（IDListSize）。
    pub id_list_size: u16,
    /// 各 ItemID。TerminalID は含まない。
    pub items: Vec<RawItemId>,
    /// IDListSize を含めた全体の消費 byte 数（IDListSize field 2 byte + IDListSize 分）。
    pub consumed_bytes: u64,
}

/// LinkTargetIDList 解析の error。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdListError {
    /// IDListSize を読む前に EOF（truncated）。
    TruncatedSize,
    /// IDListSize が大きすぎる（snapshot 全体より大きい等）。
    InvalidSize(u16),
    /// ItemIDSize が大きすぎる（残り IDList サイズを越える）。
    InvalidItemSize(u16),
    /// TerminalID が 0 でない（IDList の終端が不正）。
    MissingTerminal,
}

/// Header 直後（offset `HEADER_BYTES`）から LinkTargetIDList を読む。
///
/// 戻り値の `consumed_bytes` は IDListSize field (2 byte) + IDList (IDListSize byte) = 全消費量。
/// 読み取り後、cursor は IDList の直後（TerminalID の次）へ進む。
pub fn read_link_target_id_list(
    reader: &mut dyn ReadSeek,
) -> Result<LinkTargetIdList, IdListError> {
    // IDListSize (2 byte LE)。
    let mut size_buf = [0u8; 2];
    reader
        .read_exact(&mut size_buf)
        .map_err(|_| IdListError::TruncatedSize)?;
    let id_list_size = u16::from_le_bytes(size_buf);

    if id_list_size == 0 {
        // IDListSize が 0 は異常（TerminalID すらない）。
        return Err(IdListError::InvalidSize(0));
    }

    // IDList 本体を読む。境界検証のため、まずは最大サイズ分の一時 buffer を使う。
    // ただし id_list_size には TerminalID (2 byte) が含まれる。ItemID として解析していく。
    let id_list_start = id_list_size as u64;
    let mut consumed_within: u64 = 0;
    let mut items: Vec<RawItemId> = Vec::new();

    while consumed_within < id_list_size as u64 {
        // ItemIDSize (2 byte LE)。
        let mut item_size_buf = [0u8; 2];
        reader
            .read_exact(&mut item_size_buf)
            .map_err(|_| IdListError::MissingTerminal)?;
        let item_size = u16::from_le_bytes(item_size_buf);
        consumed_within += 2;

        if item_size == 0 {
            // TerminalID に到達。IDList 終端。これ以上 ItemID は無い。
            // 残りの consumed_within が id_list_size と一致しているはず。
            break;
        }

        // 残りサイズ内に収まるか。
        let remaining = (id_list_size as u64).saturating_sub(consumed_within);
        if item_size as u64 > remaining {
            return Err(IdListError::InvalidItemSize(item_size));
        }

        // ItemID 本体を読む。
        let mut item_bytes = vec![0u8; item_size as usize];
        reader
            .read_exact(&mut item_bytes)
            .map_err(|_| IdListError::InvalidItemSize(item_size))?;
        consumed_within += item_size as u64;

        items.push(RawItemId {
            size: item_size,
            bytes: item_bytes,
        });
    }

    // TerminalID へ到達した、または IDListSize を使い切った。
    // consumed_within が IDListSize に満たない場合（TerminalID 後の余剰）、seek で進める。
    if consumed_within < id_list_start {
        let skip = id_list_start - consumed_within;
        reader
            .seek(SeekFrom::Current(skip as i64))
            .map_err(|_| IdListError::InvalidSize(id_list_size))?;
    }

    Ok(LinkTargetIdList {
        id_list_size,
        items,
        consumed_bytes: 2 + id_list_size as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cursor(data: Vec<u8>) -> Cursor<Vec<u8>> {
        Cursor::new(data)
    }

    #[test]
    fn read_minimal_idlist() {
        // IDListSize = 2（TerminalID のみ）。
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&2u16.to_le_bytes()); // IDListSize
        buf.extend_from_slice(&0u16.to_le_bytes()); // TerminalID
        let mut c = cursor(buf);
        let list = read_link_target_id_list(&mut c).unwrap();
        assert_eq!(list.id_list_size, 2);
        assert!(list.items.is_empty());
        assert_eq!(list.consumed_bytes, 4);
    }

    #[test]
    fn read_idlist_with_items() {
        // IDListSize = 2 + (2 + 3) + (2 + 1) = 10。
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&10u16.to_le_bytes()); // IDListSize
        // ItemID 1: size=3, data=[1,2,3]
        buf.extend_from_slice(&3u16.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3]);
        // ItemID 2: size=1, data=[9]
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&[9]);
        // TerminalID
        buf.extend_from_slice(&0u16.to_le_bytes());

        let mut c = cursor(buf);
        let list = read_link_target_id_list(&mut c).unwrap();
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].size, 3);
        assert_eq!(list.items[0].bytes, vec![1, 2, 3]);
        assert_eq!(list.items[1].size, 1);
        assert_eq!(list.items[1].bytes, vec![9]);
        assert_eq!(list.consumed_bytes, 12);
    }

    #[test]
    fn read_truncated_size() {
        // 規範 §9.2: truncated で panic しない。
        let mut c = cursor(vec![0u8; 1]); // 1 byte しかない
        let err = read_link_target_id_list(&mut c).unwrap_err();
        assert_eq!(err, IdListError::TruncatedSize);
    }

    #[test]
    fn read_zero_size_rejected() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u16.to_le_bytes());
        let mut c = cursor(buf);
        let err = read_link_target_id_list(&mut c).unwrap_err();
        assert_eq!(err, IdListError::InvalidSize(0));
    }

    #[test]
    fn read_oversize_item_rejected() {
        // IDListSize = 4（TerminalID のみ想定）だが、ItemIDSize = 10 を入れる。
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&4u16.to_le_bytes()); // IDListSize
        buf.extend_from_slice(&10u16.to_le_bytes()); // でかい ItemIDSize
        let mut c = cursor(buf);
        let err = read_link_target_id_list(&mut c).unwrap_err();
        assert!(matches!(err, IdListError::InvalidItemSize(10)));
    }
}
