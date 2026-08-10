//! Length-prefixed encoding（規範 §12.2）。
//!
//! 決定的 ID の hash 入力を構築するための符号化方式。各 field を
//! `4 byte unsigned big-endian length` + `field bytes` の形で連結する。
//!
//! 規則（規範 §12.2）:
//! - null: 長さ `0xFFFFFFFF`（bytes なし）。空文字列（長さ 0）と区別される。
//! - 空文字列: 長さ 0（bytes なし）。
//! - 整数: 符号なし decimal ASCII 文字列へ変換してから length-prefix。
//! - enum: Schema が定義する lowercase 文字列。
//! - list: 要素数を先頭 field として encode し、続けて各要素を同じ形式で encode。

/// null を示す長さ（規範 §12.2）。`0xFFFFFFFF`。
pub const NULL_LENGTH: u32 = 0xFFFF_FFFF;

/// length-prefixed byte 列を構築する accumulator。
///
/// 各 `append_*` 呼出で末尾へ field を追加する。構築後は [`as_bytes`] / [`into_bytes`]
/// で取得し、`hash::sha256_hex` へ渡して ID suffix を得る。
///
/// [`as_bytes`]: LengthPrefixed::as_bytes
/// [`into_bytes`]: LengthPrefixed::into_bytes
#[derive(Default, Clone, Debug)]
pub struct LengthPrefixed {
    buf: Vec<u8>,
}

impl LengthPrefixed {
    /// 空の accumulator を作成する。
    pub fn new() -> Self {
        Self::default()
    }

    /// 構築済みの byte 列を参照する。
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// 構築済みの byte 列を消費して取り出す。
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// 末尾へ length-prefixed bytes を追加する（内部共通処理）。
    ///
    /// `bytes.len()` を 4 byte big-endian で書き込み、続けて bytes を書き込む。
    fn append_bytes(&mut self, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).expect("field が 4GiB を超えている");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
    }

    /// null を追加する（規範 §12.2）。長さ `0xFFFFFFFF`、bytes なし。
    pub fn append_null(&mut self) {
        self.buf.extend_from_slice(&NULL_LENGTH.to_be_bytes());
    }

    /// 文字列を追加する。空文字列は長さ 0 になる（null と区別される）。
    pub fn append_str(&mut self, s: &str) {
        self.append_bytes(s.as_bytes());
    }

    /// `Option<&str>` を追加する。`None` は null、`Some("")` は空文字列。
    pub fn append_opt_str(&mut self, s: Option<&str>) {
        match s {
            None => self.append_null(),
            Some(v) => self.append_str(v),
        }
    }

    /// 非負整数を decimal ASCII として追加する（規範 §12.2: 整数は符号なし decimal ASCII）。
    pub fn append_u64(&mut self, n: u64) {
        let s = n.to_string();
        self.append_bytes(s.as_bytes());
    }

    /// `Option<u64>` を追加する。`None` は null。
    pub fn append_opt_u64(&mut self, n: Option<u64>) {
        match n {
            None => self.append_null(),
            Some(v) => self.append_u64(v),
        }
    }

    /// 文字列 list を追加する。先頭へ要素数を encode し、続けて各要素を encode する
    /// （規範 §12.2: list は要素数を先頭 field とする）。
    pub fn append_str_list(&mut self, list: &[&str]) {
        self.append_u64(u64::try_from(list.len()).expect("list が長すぎる"));
        for s in list {
            self.append_str(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_is_distinct_from_empty_string() {
        // 規範 §12.2: null は 0xFFFFFFFF、空文字列は 0x00000000。
        let mut buf = LengthPrefixed::new();
        buf.append_null();
        assert_eq!(buf.as_bytes(), &[0xFF, 0xFF, 0xFF, 0xFF]);

        let mut buf = LengthPrefixed::new();
        buf.append_str("");
        assert_eq!(buf.as_bytes(), &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn string_is_length_prefixed_utf8() {
        let mut buf = LengthPrefixed::new();
        buf.append_str("ab");
        // length 2 (big-endian) + "ab"
        assert_eq!(buf.as_bytes(), &[0x00, 0x00, 0x00, 0x02, b'a', b'b']);
    }

    #[test]
    fn integer_is_decimal_ascii() {
        // 規範 §12.2: 整数は符号なし decimal ASCII。
        let mut buf = LengthPrefixed::new();
        buf.append_u64(123);
        assert_eq!(buf.as_bytes(), &[0x00, 0x00, 0x00, 0x03, b'1', b'2', b'3']);
    }

    #[test]
    fn list_prefixes_count_then_elements() {
        // 規範 §12.2: list は要素数を先頭 field とする。
        // 要素数 2 は整数 → decimal ASCII "2" → length-prefix で [0,0,0,1, 0x32]。
        let mut buf = LengthPrefixed::new();
        buf.append_str_list(&["x", "yy"]);
        let expected = [
            0x00, 0x00, 0x00, 0x01, b'2', // count = 2
            0x00, 0x00, 0x00, 0x01, b'x', // "x"
            0x00, 0x00, 0x00, 0x02, b'y', b'y', // "yy"
        ];
        assert_eq!(buf.as_bytes(), expected);
    }

    #[test]
    fn opt_none_is_null_some_is_value() {
        let mut buf = LengthPrefixed::new();
        buf.append_opt_str(None);
        buf.append_opt_str(Some("z"));
        assert_eq!(
            buf.as_bytes(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, b'z']
        );
    }
}
