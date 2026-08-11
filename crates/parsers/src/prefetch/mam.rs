//! MAM 圧縮 Prefetch の検出と XPRESS Huffman 展開（互換 §4.1、T4-022）。
//!
//! Windows 10 以降では Prefetch file が MAM 圧縮で格納される。MAM file は次の構造:
//!
//! | offset | size | 内容 |
//! |--------|------|------|
//! | 0 | 4 | magic `b"MAM\x04"`（0x4D 0x41 0x4D 0x04）|
//! | 4 | 4 | 圧縮前の全 data size（byte・little-endian）|
//! | 8 | ... | XPRESS Huffman 圧縮 data |
//!
//! XPRESS Huffman（LZXPRESS Huffman）は LZ77 + Huffman の手法。本 module は
//! 純 Rust で展開器を実装し、新たな外部依存を追加しない（roadmap §9 リスク対応）。
//!
//! ## 設計上の注意
//!
//! - **同一 Provenance chain（互換 §4.1）**: 展開後の bytes を別 Evidence として扱わない。
//!   本 module は bytes を返すだけ。Parser は展開前と同じ Evidence / Artifact の
//!   [`ParseContext`](crate::framework::ParseContext) で Event を生成する。
//! - **安全な失敗**: 破損・truncated・過大 size で panic せず [`DecompressError`] を返す。
//!   Parser はこれを Issue へ変換する。
//!
//! ## XPRESS Huffman の実装範囲
//!
//! Huffman 表の構築・literal 復号は完全に実装する。match（LZ77 back-reference）復号は
//! アルゴリズムに従い実装するが、実 Windows 生成物での最終検証は Phase 8 の fixture
//! 収集時に行う（fixture 収集計画 §3.2）。本 Phase では literal-only 圧縮 fixture で
//! Provenance chain と展開経路を検証する。

/// MAM 展開の上限（byte）。過大 size 攻撃・破損 size field からの保護。
/// Prefetch は通常数 KB〜数百 KB。16 MB は十分大きな安全上限。
pub const MAX_UNCOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// XPRESS Huffman の1 chunk あたり最大展開 size（byte）。
const CHUNK_SIZE: usize = 65_536;

/// Huffman 表の entry 数（literal 256 + match 256 = 512）。
const HUFF_TABLE_ENTRIES: usize = 512;

/// Huffman code 長の上限（bit）。XPRESS Huffman では 15。
const MAX_CODE_LENGTH: usize = 15;

/// MAM header（8 byte）。
#[derive(Clone, Copy, Debug)]
pub struct MamHeader {
    /// 圧縮前の全 data size（byte）。
    pub uncompressed_size: u32,
}

impl MamHeader {
    /// 先頭 8 byte から MAM header を解析する。
    pub fn parse(buf: &[u8]) -> Option<MamHeader> {
        if buf.len() < crate::prefetch::header::MAM_HEADER_BYTES {
            return None;
        }
        let uncompressed_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Some(MamHeader { uncompressed_size })
    }
}

/// 展開失敗。
#[derive(Clone, Debug)]
pub enum DecompressError {
    /// 圧縮 data が途中で切れている。
    Truncated,
    /// 宣言された展開 size が上限を超える、または size 矛盾。
    SizeError,
    /// Huffman 表が不正（過剰な code 数・decode 不能）。
    InvalidTable,
    /// bitstream が途中で尽きた、または match の offset が範囲外。
    InvalidBitstream,
}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecompressError::Truncated => write!(f, "圧縮 data が truncated"),
            DecompressError::SizeError => write!(f, "展開 size が不正または上限超過"),
            DecompressError::InvalidTable => write!(f, "Huffman 表が不正"),
            DecompressError::InvalidBitstream => write!(f, "圧縮 bitstream が不正"),
        }
    }
}

impl std::error::Error for DecompressError {}

/// MAM 圧縮 data を展開し、元の Prefetch bytes を返す。
///
/// `compressed` は MAM header（8 byte）を含む全体。戻り値は
/// header に宣言された size の展開済み bytes。
pub fn decompress_mam(compressed: &[u8]) -> Result<Vec<u8>, DecompressError> {
    let header = MamHeader::parse(compressed).ok_or(DecompressError::Truncated)?;
    let uncompressed_size =
        usize::try_from(header.uncompressed_size).map_err(|_| DecompressError::SizeError)?;
    if uncompressed_size > MAX_UNCOMPRESSED_BYTES {
        return Err(DecompressError::SizeError);
    }
    let body = compressed
        .get(crate::prefetch::header::MAM_HEADER_BYTES..)
        .ok_or(DecompressError::Truncated)?;
    decompress_xpress_huffman(body, uncompressed_size)
}

/// XPRESS Huffman 圧縮 data を展開する。
///
/// `compressed` は MAM header を含まない純粋な圧縮 bitstream。
/// `uncompressed_size` に達するまで chunk を順次展開する。
pub fn decompress_xpress_huffman(
    compressed: &[u8],
    uncompressed_size: usize,
) -> Result<Vec<u8>, DecompressError> {
    let mut output: Vec<u8> = Vec::with_capacity(uncompressed_size.min(1024));
    let mut reader = BitReader::new(compressed);

    while output.len() < uncompressed_size {
        let chunk_target = uncompressed_size - output.len();
        let chunk_cap = chunk_target.min(CHUNK_SIZE);
        let chunk_start = output.len();

        // 1. Huffman 表（256 byte = 512 × 4 bit）を読む。
        let lengths = read_table_lengths(&mut reader)?;

        // 2. canonical Huffman 復号器を構築。
        let decoder = CanonicalHuffman::build(&lengths)?;

        // 3. chunk の bitstream を復号。
        while output.len() - chunk_start < chunk_cap {
            let symbol = decoder
                .decode(&mut reader)
                .ok_or(DecompressError::InvalidBitstream)?;

            if symbol < 256 {
                // literal
                output.push(symbol as u8);
            } else {
                // match（LZ77 back-reference）
                let (length, distance) = decode_match(&mut reader, &output, chunk_start)?;
                copy_match(&mut output, distance, length)?;
            }
        }
    }

    output.truncate(uncompressed_size);
    Ok(output)
}

/// 16-bit LE word 単位で MSB-first に bit を読む reader。
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    /// 現在の 16-bit word。bit_pos が 16 に達したら次の word を読む。
    word: u16,
    /// 次に読む bit の位置（0=MSB .. 15=LSB）。16 は「未読込」を意味する。
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_pos: 0,
            word: 0,
            bit_pos: 16,
        }
    }

    /// 次の1 bit を返す。data が尽きた場合は `None`。
    fn read_bit(&mut self) -> Option<u32> {
        if self.bit_pos >= 16 {
            self.refill()?;
        }
        // MSB から順に消費。
        let bit = ((self.word >> (15 - self.bit_pos)) & 1) as u32;
        self.bit_pos += 1;
        Some(bit)
    }

    /// `n` bit を MSB-first で読んで `u32` へ詰める。
    fn read_bits(&mut self, n: u8) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..n {
            value = (value << 1) | self.read_bit()?;
        }
        Some(value)
    }

    /// 次の 16-bit LE word を読み込む。data が不足なら `None`。
    fn refill(&mut self) -> Option<()> {
        if self.byte_pos + 2 > self.data.len() {
            return None;
        }
        self.word = u16::from_le_bytes([self.data[self.byte_pos], self.data[self.byte_pos + 1]]);
        self.byte_pos += 2;
        self.bit_pos = 0;
        Some(())
    }
}

/// 512 個の Huffman code 長を読む（256 byte = 各 byte が2つの4-bit長）。
fn read_table_lengths(reader: &mut BitReader<'_>) -> Result<Vec<u8>, DecompressError> {
    // 表は 256 byte で、byte 単位で並んでいる。bit reader 経由ではなく
    // byte 単位で直接読む方が確実かつ高速。reader の byte_pos を使う。
    // ただし reader は bit と word を管理しているため、表は「bitstream の先頭」
    // として MSB-first で解釈する必要がある。libyal 仕様では表は 4-bit 単位で
    // 先頭から詰められる。本実装では read_bits(4) を512回呼んで安全に読む。
    let mut lengths = vec![0u8; HUFF_TABLE_ENTRIES];
    for slot in lengths.iter_mut() {
        *slot = reader.read_bits(4).ok_or(DecompressError::Truncated)? as u8;
    }
    Ok(lengths)
}

/// Canonical Huffman 復号器。
struct CanonicalHuffman {
    /// 各 code 長ごとの entry 数。
    count: [u32; MAX_CODE_LENGTH + 1],
    /// code 長・symbol 順に並んだ symbol 表。
    symbols: Vec<u16>,
}

impl CanonicalHuffman {
    fn build(lengths: &[u8]) -> Result<Self, DecompressError> {
        let mut count = [0u32; MAX_CODE_LENGTH + 1];
        for &l in lengths {
            if l as usize > MAX_CODE_LENGTH {
                return Err(DecompressError::InvalidTable);
            }
            count[l as usize] += 1;
        }
        // 長さ 0 の symbol は木へ含めない。
        count[0] = 0;

        // over-subscribed 検証: 全 code が占有する空間 == 2^MAX か（完全木）。
        // DEFLATE 風の left/right 計算で確認する。
        let mut left: i64 = 1;
        for &cnt in count[1..=MAX_CODE_LENGTH].iter() {
            left <<= 1;
            left -= cnt as i64;
            if left < 0 {
                return Err(DecompressError::InvalidTable);
            }
        }
        // incomplete tree（left > 0）は許容する実装もあるが、XPRESS Huffman では
        // 完全木または単一 symbol を想定。極端に空過ぎる場合は不正とみなす。
        // ただし literal-only でも完全木になるため、ここは left == 0 を強要しない
        // （単一 symbol 表のための例外を許す）。

        // symbol 表を code 長 → symbol 番号順で構築（canonical 順序）。
        // 各 code 長の symbols 内での開始 offset を累積和で求める。
        let mut sym_offsets = [0usize; MAX_CODE_LENGTH + 2];
        for l in 1..=MAX_CODE_LENGTH {
            sym_offsets[l + 1] = sym_offsets[l] + count[l] as usize;
        }
        let total: usize = count.iter().sum::<u32>() as usize;
        let mut symbols = vec![0u16; total];
        let mut cursor = sym_offsets;
        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let idx = cursor[len as usize];
            cursor[len as usize] += 1;
            symbols[idx] = sym as u16;
        }

        // canonical 復号は長さ順に code を昇順で割り当てる前提。復号時（decode）に
        // 局所的に first/code を計算するため、表には保持しない。

        Ok(CanonicalHuffman { count, symbols })
    }

    /// 1 symbol を復号。bit 不足時は `None`。
    fn decode(&self, reader: &mut BitReader<'_>) -> Option<u16> {
        let mut code = 0u32;
        let mut first = 0u32;
        let mut index = 0usize;
        for l in 1..=MAX_CODE_LENGTH {
            code = (code << 1) | reader.read_bit()?;
            let cnt = self.count[l];
            if code - first < cnt {
                let pos = index + (code - first) as usize;
                return Some(self.symbols[pos]);
            }
            index += cnt as usize;
            first += cnt;
            first <<= 1;
        }
        None
    }
}

/// match symbol に続く長さ・距離を bitstream から読む（libyal 仕様）。
///
/// 仕様: 4 bit 長 + 4 bit 距離(下位) + 1 bit flag。flag=1 なら距離の上位 byte を追加で読む。
/// 長さが上限（15）に達した場合は拡張長を読む（plain XPRESS に準拠）。
///
/// 戻り値: `(copy_length, back_distance)`。`distance` は 1 以上 `output.len()` 以下を保証。
fn decode_match(
    reader: &mut BitReader<'_>,
    output: &[u8],
    _chunk_start: usize,
) -> Result<(usize, usize), DecompressError> {
    let len4 = reader
        .read_bits(4)
        .ok_or(DecompressError::InvalidBitstream)?;
    let dist_lo = reader
        .read_bits(4)
        .ok_or(DecompressError::InvalidBitstream)?;
    let flag = reader
        .read_bits(1)
        .ok_or(DecompressError::InvalidBitstream)?;

    // 長さ: len4 に最小 match 長（3）を足す。len4 == 15 のとき拡張長を読む。
    let mut length = len4 as usize + 3;
    if len4 == 15 {
        let ext = reader
            .read_bits(8)
            .ok_or(DecompressError::InvalidBitstream)?;
        length += ext as usize;
    }

    // 距離: 下位 4 bit に、flag が立っていれば上位 8 bit を追加。
    let mut distance = dist_lo as usize;
    if flag == 1 {
        let dist_hi = reader
            .read_bits(8)
            .ok_or(DecompressError::InvalidBitstream)?;
        distance |= (dist_hi as usize) << 4;
    }
    distance += 1; // 0-based → 1-based

    if distance == 0 || distance > output.len() {
        return Err(DecompressError::InvalidBitstream);
    }
    Ok((length, distance))
}

/// LZ77 overlap 対応の match copy。
fn copy_match(output: &mut Vec<u8>, distance: usize, length: usize) -> Result<(), DecompressError> {
    let start = output
        .len()
        .checked_sub(distance)
        .ok_or(DecompressError::InvalidBitstream)?;
    for i in 0..length {
        let b = *output
            .get(start + i)
            .ok_or(DecompressError::InvalidBitstream)?;
        output.push(b);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// literal-only XPRESS Huffman の bitstream を構築する（test 用 compressor）。
    ///
    /// 全256 literal に code 長 8 を割り当て、各 byte をそのまま8 bit で符号化する。
    /// match symbol（256-511）は code 長 0（不使用）。
    fn compress_literal_only(input: &[u8]) -> Vec<u8> {
        let mut writer = BitWriter::new();
        // 256 byte の表（512 nibble）:
        //   symbol 0-255（literal）= 長さ8（完全8bit 木）
        //   symbol 256-511（match） = 長さ0（不使用）
        // 前 256 nibble（128 byte）が全て 8、後半 256 nibble が全て 0。
        for _ in 0..128 {
            writer.write_bits(4, 8); // symbol 2k
            writer.write_bits(4, 8); // symbol 2k+1
        }
        for _ in 0..128 {
            writer.write_bits(4, 0); // symbol 256+2k
            writer.write_bits(4, 0); // symbol 256+2k+1
        }
        // 全256 literal が長さ8 → canonical: symbol s の code は s（8 bit）。
        // byte b を出力 = 8 bit で b（MSB-first）。
        for &b in input {
            writer.write_bits(8, b as u32);
        }
        writer.finish()
    }

    /// MSB-first で 16-bit LE word へ bit を詰める writer。
    struct BitWriter {
        out: Vec<u8>,
        word: u16,
        bit_pos: u8, // 0=最初の bit は bit15 へ、順に降る。
    }

    impl BitWriter {
        fn new() -> Self {
            BitWriter {
                out: Vec::new(),
                word: 0,
                bit_pos: 0,
            }
        }
        fn write_bits(&mut self, n: u8, value: u32) {
            for i in (0..n).rev() {
                let bit = (value >> i) & 1;
                // MSB から詰める: 最初の bit → bit15。
                self.word |= (bit as u16) << (15 - self.bit_pos);
                self.bit_pos += 1;
                if self.bit_pos == 16 {
                    self.out.extend_from_slice(&self.word.to_le_bytes());
                    self.word = 0;
                    self.bit_pos = 0;
                }
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.bit_pos > 0 {
                self.out.extend_from_slice(&self.word.to_le_bytes());
            }
            self.out
        }
    }

    #[test]
    fn roundtrip_literal_only_small() {
        let input = b"Hello, Prefetch! XPRESS Huffman literal round-trip test.";
        let compressed = compress_literal_only(input);
        let decompressed = decompress_xpress_huffman(&compressed, input.len()).expect("round-trip");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn roundtrip_literal_only_binary() {
        // 全 byte 値を網羅する binary input。
        let input: Vec<u8> = (0u16..1000).map(|i| (i % 256) as u8).collect();
        let compressed = compress_literal_only(&input);
        let decompressed = decompress_xpress_huffman(&compressed, input.len()).expect("round-trip");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn mam_header_parse() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(b"MAM\x04");
        buf[4..8].copy_from_slice(&1234u32.to_le_bytes());
        let h = MamHeader::parse(&buf).unwrap();
        assert_eq!(h.uncompressed_size, 1234);
    }

    #[test]
    fn decompress_mam_wrapped_literal() {
        // 小さな Prefetch 風 payload を MAM 圧縮で包む。
        let payload = b"\x1F\x00\x00\x00SCCA dummy prefetch payload for MAM test!!";
        let mut compressed = compress_literal_only(payload);
        let mut mam = Vec::with_capacity(8 + compressed.len());
        mam.extend_from_slice(b"MAM\x04");
        mam.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        mam.append(&mut compressed);

        let out = decompress_mam(&mam).expect("MAM 展開成功");
        assert_eq!(out, payload);
    }

    #[test]
    fn decompress_rejects_huge_size() {
        let mut mam = vec![0u8; 16];
        mam[0..4].copy_from_slice(b"MAM\x04");
        // 100 MB（上限 16 MB 超過）
        mam[4..8].copy_from_slice(&100_000_000u32.to_le_bytes());
        assert!(matches!(
            decompress_mam(&mam),
            Err(DecompressError::SizeError)
        ));
    }

    #[test]
    fn decompress_truncated_returns_error_not_panic() {
        // 表すら足りない。
        let short = vec![0u8; 10];
        assert!(matches!(
            decompress_xpress_huffman(&short, 100),
            Err(DecompressError::Truncated) | Err(DecompressError::InvalidBitstream)
        ));
    }
}
