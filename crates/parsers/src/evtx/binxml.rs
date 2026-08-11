//! BinXml decoder（libyal libevtx 仕様、T4-041・T4-042）。
//!
//! BinXml は EVTX record 本体へ埋め込まれたバイナリ XML 表現。token 列から element tree
//! を構成し、substitution placeholder へ実行時値を埋め込むことで元の XML event へ復元する。
//!
//! ## 対象範囲
//!
//! EVTX event を構成するための必要十分な token のみを扱う:
//!
//! | token | 意味 |
//! |---|---|
//! | 0x00 | EndOfStream |
//! | 0x01 | EndElement |
//! | 0x02 | CloseStartElement（`>`）|
//! | 0x03 | OpenStartElement（要素開始）|
//! | 0x04 | CloseEmptyElement（`/>`）|
//! | 0x05 | Value（text content）|
//! | 0x06 | Attribute |
//! | 0x0C | TemplateInstance |
//! | 0x0D | NormalSubstitution |
//! | 0x0E | ConditionalSubstitution |
//! | 0x0F | FragmentHeader |
//!
//! これ以外の token（CDATA・CharReference 等）は未対応として [`DecodeError::UnsupportedToken`]
//! へ分類する。raw XML 保存は行わず、必要な要素（EventID・Provider・Channel・Computer・EventData）
//! へ絞った構造化抽出を行う（T4-042）。
//!
//! ## 値型
//!
//! Value token と substitution が扱う値型は libyal libevtx 準拠。本 Phase で必要な型のみ
//! 実装する（String/WString/Int32/UInt16/UInt32/UInt64/FileTime/Bool/Null/Binary/Guid）。

// --- Token 定数（libyal libevtx_binxml 準拠）---

const TOKEN_END_OF_STREAM: u8 = 0x00;
const TOKEN_END_ELEMENT: u8 = 0x01;
const TOKEN_CLOSE_START_ELEMENT: u8 = 0x02;
const TOKEN_OPEN_START_ELEMENT: u8 = 0x03;
const TOKEN_CLOSE_EMPTY_ELEMENT: u8 = 0x04;
const TOKEN_VALUE: u8 = 0x05;
const TOKEN_ATTRIBUTE: u8 = 0x06;
const TOKEN_TEMPLATE_INSTANCE: u8 = 0x0c;
const TOKEN_NORMAL_SUBSTITUTION: u8 = 0x0d;
const TOKEN_CONDITIONAL_SUBSTITUTION: u8 = 0x0e;
const TOKEN_FRAGMENT_HEADER: u8 = 0x0f;

// --- 値型（libyal libevtx 準拠）---

const VALUE_TYPE_NULL: u8 = 0x00;
const VALUE_TYPE_STRING: u8 = 0x01;
const VALUE_TYPE_INT8: u8 = 0x03;
const VALUE_TYPE_UINT8: u8 = 0x04;
const VALUE_TYPE_INT16: u8 = 0x05;
const VALUE_TYPE_UINT16: u8 = 0x06;
const VALUE_TYPE_INT32: u8 = 0x07;
const VALUE_TYPE_UINT32: u8 = 0x08;
const VALUE_TYPE_INT64: u8 = 0x09;
const VALUE_TYPE_UINT64: u8 = 0x0a;
const VALUE_TYPE_BOOL: u8 = 0x0d;
const VALUE_TYPE_BINARY: u8 = 0x0e;
const VALUE_TYPE_GUID: u8 = 0x0f;
const VALUE_TYPE_FILETIME: u8 = 0x11;
const VALUE_TYPE_SYSTEMTIME: u8 = 0x12;
const VALUE_TYPE_SID: u8 = 0x13;
const VALUE_TYPE_WSTRING: u8 = 0x14;

/// substitution 値の最大数。異常入力からの過大 alloc 防止。
const MAX_SUBSTITUTIONS: usize = 1024;
/// 1 element の子要素の最大数。異常入力からの再起無限 loop 防止。
const MAX_CHILDREN: usize = 4096;
/// 1 record 内の template 入れ子の最大深さ。
const MAX_TEMPLATE_DEPTH: usize = 16;
/// value byte 長の安全上限。
const MAX_VALUE_BYTES: usize = 65_536;

/// binxml decode 失敗。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// data が途中で切れた。
    #[error("binxml data が truncated（offset {0}）")]
    Truncated(usize),
    /// 未知の token type。
    #[error("未知の token 0x{0:02x}（offset {1}）")]
    UnsupportedToken(u8, usize),
    /// 未知の値型。
    #[error("未知の値型 0x{0:02x}（offset {1}）")]
    UnsupportedValueType(u8, usize),
    /// UTF-16LE decode 失敗。
    #[error("UTF-16LE decode 失敗（offset {0}）")]
    BadEncoding(usize),
    /// template 入れ子深さ上限超過。
    #[error("template 入れ子深さ上限 ({MAX_TEMPLATE_DEPTH}) 超過")]
    TemplateDepthExceeded,
    /// substitution 数上限超過。
    #[error("substitution 数上限 ({MAX_SUBSTITUTIONS}) 超過")]
    TooManySubstitutions,
    /// 子要素数上限超過。
    #[error("子要素数上限 ({MAX_CHILDREN}) 超過")]
    TooManyChildren,
    /// 値 byte 長が上限超過。
    #[error("値 byte 長が上限 ({MAX_VALUE_BYTES}) 超過")]
    ValueTooLong,
    /// 矛盾した size 宣言（template definition size 等）。
    #[error("size 宣言が矛盾: declared={declared}, actual={actual}")]
    InconsistentSize { declared: u32, actual: usize },
    /// template instance が fragment header 直後の1個目ではない。
    #[error("record binxml の root が template instance ではない: token=0x{0:02x}")]
    NotTemplateInstance(u8),
}

/// binxml から抽出した event 内容。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EventContent {
    /// `<System><EventID>` の数値。
    pub event_id: Option<i32>,
    /// `<System><Version>` の数値（省略可）。
    pub version: Option<u8>,
    /// `<System><Level>` の数値（省略可）。
    pub level: Option<u8>,
    /// `<System><Opcode>` の数値（省略可）。
    pub opcode: Option<u8>,
    /// `<System><Provider Name="...">`。
    pub provider_name: Option<String>,
    /// `<System><Provider Guid="...">`。
    pub provider_guid: Option<String>,
    /// `<System><Channel>`。
    pub channel: Option<String>,
    /// `<System><Computer>`。
    pub computer: Option<String>,
    /// `<EventData><Data Name="...">value</Data>` の一覧。順序を保持。
    pub event_data: Vec<(String, EventDataValue)>,
    /// `<System>` 配下の task コード（省略可）。
    pub task: Option<u32>,
    /// `<System>` 配下の keywords（u64 bitmask、省略可）。
    pub keywords: Option<u64>,
}

/// EventData の値。文字列表現も保持し、型情報も残す。
#[derive(Clone, Debug, PartialEq)]
pub enum EventDataValue {
    Null,
    Str(String),
    Int(i64),
    UInt(u64),
    Bool(bool),
    FileTime(u64),
    /// 元型が binary / guid / sid 等、文字列化のみ行うもの。
    Other(String),
}

impl EventDataValue {
    /// 文字列表現へ。
    pub fn as_str_value(&self) -> String {
        match self {
            EventDataValue::Null => String::new(),
            EventDataValue::Str(s) => s.clone(),
            EventDataValue::Int(n) => n.to_string(),
            EventDataValue::UInt(n) => n.to_string(),
            EventDataValue::Bool(b) => b.to_string(),
            EventDataValue::FileTime(ft) => ft.to_string(),
            EventDataValue::Other(s) => s.clone(),
        }
    }

    /// `i64` として取り出せる場合。
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            EventDataValue::Int(n) => Some(*n),
            EventDataValue::UInt(n) => {
                if *n <= i64::MAX as u64 {
                    Some(*n as i64)
                } else {
                    None
                }
            }
            EventDataValue::Str(s) => s.parse().ok(),
            _ => None,
        }
    }
}

// --- binxml value（内部表現）---

#[derive(Clone, Debug)]
enum BinXmlValue {
    Null,
    Str(String),
    Int(i64),
    UInt(u64),
    Bool(bool),
    FileTime(u64),
    /// raw bytes を hex 文字列化して保持。
    Other(String),
}

impl BinXmlValue {
    fn to_event_data_value(&self) -> EventDataValue {
        match self {
            BinXmlValue::Null => EventDataValue::Null,
            BinXmlValue::Str(s) => EventDataValue::Str(s.clone()),
            BinXmlValue::Int(n) => EventDataValue::Int(*n),
            BinXmlValue::UInt(n) => EventDataValue::UInt(*n),
            BinXmlValue::Bool(b) => EventDataValue::Bool(*b),
            BinXmlValue::FileTime(ft) => EventDataValue::FileTime(*ft),
            BinXmlValue::Other(s) => EventDataValue::Other(s.clone()),
        }
    }
}

// --- XML tree の中間表現 ---

#[derive(Clone, Debug)]
enum XmlNode {
    Element {
        name: String,
        attributes: Vec<(String, BinXmlValue)>,
        children: Vec<XmlNode>,
    },
    Text(BinXmlValue),
    /// substitution placeholder。適用後に Text へ置換。
    Substitution {
        index: usize,
        conditional: bool,
    },
}

/// binxml decoder 本体。
struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Decoder { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or(DecodeError::Truncated(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn peek_u8(&self) -> Result<u8, DecodeError> {
        self.data
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::Truncated(self.pos))
    }

    fn read_u16(&mut self) -> Result<u16, DecodeError> {
        if self.pos + 2 > self.data.len() {
            return Err(DecodeError::Truncated(self.pos));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        if self.pos + 4 > self.data.len() {
            return Err(DecodeError::Truncated(self.pos));
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_i32(&mut self) -> Result<i32, DecodeError> {
        Ok(self.read_u32()? as i32)
    }

    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        if self.pos + 8 > self.data.len() {
            return Err(DecodeError::Truncated(self.pos));
        }
        let v = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.data.len() {
            return Err(DecodeError::Truncated(self.pos));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// fragment header (0x0F major flags) を読み飛ばす。
    fn read_fragment_header(&mut self) -> Result<(), DecodeError> {
        let token = self.read_u8()?;
        if token != TOKEN_FRAGMENT_HEADER {
            return Err(DecodeError::UnsupportedToken(token, self.pos));
        }
        let _major = self.read_u8()?;
        let _flags = self.read_u8()?;
        Ok(())
    }

    /// UTF-16LE name（hash 4 + count 2 + chars）を読む。
    fn read_name(&mut self) -> Result<String, DecodeError> {
        let _hash = self.read_u32()?;
        let char_count = self.read_u16()? as usize;
        let byte_len = char_count.checked_mul(2).ok_or(DecodeError::ValueTooLong)?;
        if byte_len > MAX_VALUE_BYTES {
            return Err(DecodeError::ValueTooLong);
        }
        let raw = self.read_bytes(byte_len)?;
        decode_utf16le(raw)
    }

    /// value token (0x05 type bytes...) を読む。
    fn read_value(&mut self) -> Result<BinXmlValue, DecodeError> {
        let value_type = self.read_u8()?;
        self.decode_value_of_type(value_type)
    }

    /// 指定値型の bytes を読む。
    fn decode_value_of_type(&mut self, value_type: u8) -> Result<BinXmlValue, DecodeError> {
        match value_type {
            VALUE_TYPE_NULL => Ok(BinXmlValue::Null),
            VALUE_TYPE_STRING | VALUE_TYPE_WSTRING => {
                let n = self.read_u16()? as usize;
                let byte_len = n.checked_mul(2).ok_or(DecodeError::ValueTooLong)?;
                if byte_len > MAX_VALUE_BYTES {
                    return Err(DecodeError::ValueTooLong);
                }
                let raw = self.read_bytes(byte_len)?;
                let s = decode_utf16le(raw)?;
                Ok(BinXmlValue::Str(s))
            }
            VALUE_TYPE_INT8 => {
                let b = self.read_u8()?;
                Ok(BinXmlValue::Int(b as i8 as i64))
            }
            VALUE_TYPE_UINT8 => {
                let b = self.read_u8()?;
                Ok(BinXmlValue::UInt(b as u64))
            }
            VALUE_TYPE_INT16 => {
                let v = self.read_u16()?;
                Ok(BinXmlValue::Int(v as i16 as i64))
            }
            VALUE_TYPE_UINT16 => {
                let v = self.read_u16()?;
                Ok(BinXmlValue::UInt(v as u64))
            }
            VALUE_TYPE_INT32 => {
                let v = self.read_i32()?;
                Ok(BinXmlValue::Int(v as i64))
            }
            VALUE_TYPE_UINT32 => {
                let v = self.read_u32()?;
                Ok(BinXmlValue::UInt(v as u64))
            }
            VALUE_TYPE_INT64 => {
                let v = self.read_u64()?;
                Ok(BinXmlValue::Int(v as i64))
            }
            VALUE_TYPE_UINT64 => {
                let v = self.read_u64()?;
                Ok(BinXmlValue::UInt(v))
            }
            VALUE_TYPE_BOOL => {
                let b = self.read_u8()?;
                Ok(BinXmlValue::Bool(b != 0))
            }
            VALUE_TYPE_FILETIME => {
                let v = self.read_u64()?;
                Ok(BinXmlValue::FileTime(v))
            }
            VALUE_TYPE_BINARY => {
                let n = self.read_u16()? as usize;
                if n > MAX_VALUE_BYTES {
                    return Err(DecodeError::ValueTooLong);
                }
                let raw = self.read_bytes(n)?;
                Ok(BinXmlValue::Other(bytes_to_hex(raw)))
            }
            VALUE_TYPE_GUID => {
                let raw = self.read_bytes(16)?;
                Ok(BinXmlValue::Other(format_guid(raw)))
            }
            VALUE_TYPE_SYSTEMTIME => {
                let raw = self.read_bytes(16)?;
                Ok(BinXmlValue::Other(bytes_to_hex(raw)))
            }
            VALUE_TYPE_SID => {
                let rev = self.read_u8()?;
                let count = self.read_u8()?;
                let _id_auth = self.read_bytes(6)?;
                let mut sa = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    sa.push(self.read_u32()?);
                }
                let mut s = format!("S-{rev}-1");
                for v in sa {
                    s.push_str(&format!("-{v}"));
                }
                Ok(BinXmlValue::Other(s))
            }
            _ => Err(DecodeError::UnsupportedValueType(value_type, self.pos)),
        }
    }
}

fn decode_utf16le(bytes: &[u8]) -> Result<String, DecodeError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(DecodeError::BadEncoding(0));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // 終端 NUL を取り除く。
    let trimmed: Vec<u16> = units.into_iter().take_while(|&u| u != 0).collect();
    String::from_utf16(&trimmed).map_err(|_| DecodeError::BadEncoding(0))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn format_guid(raw: &[u8]) -> String {
    if raw.len() != 16 {
        return bytes_to_hex(raw);
    }
    // Windows GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    // 最初の 3 group は little-endian、残りは big-endian。
    let d1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let d2 = u16::from_le_bytes([raw[4], raw[5]]);
    let d3 = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        d1, d2, d3, raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    )
}

/// EVTX record の binxml 本体を decode する。
pub fn decode_record(data: &[u8]) -> Result<EventContent, DecodeError> {
    if data.is_empty() {
        return Ok(EventContent::default());
    }
    let mut dec = Decoder::new(data);
    dec.read_fragment_header()?;
    // root は1個の template instance を想定。
    let token = dec.read_u8()?;
    if token == TOKEN_END_OF_STREAM {
        return Ok(EventContent::default());
    }
    if token != TOKEN_TEMPLATE_INSTANCE {
        return Err(DecodeError::NotTemplateInstance(token));
    }
    let root = decode_template_instance(&mut dec, 0)?;
    let event_content = extract_event_content(&root);
    Ok(event_content)
}

fn decode_template_instance(dec: &mut Decoder, depth: usize) -> Result<XmlNode, DecodeError> {
    if depth >= MAX_TEMPLATE_DEPTH {
        return Err(DecodeError::TemplateDepthExceeded);
    }
    // template instance header: version(1) + template_id(4) + definition_offset(4)
    let _version = dec.read_u8()?;
    let _template_id = dec.read_u32()?;
    let definition_offset = dec.read_u32()?;
    if definition_offset != 0 {
        // キャッシュ参照（offset-based lookup）は本 Phase では未対応。
        // 空要素を返す（Event 化は諦めるが panic しない）。
        return Ok(XmlNode::Element {
            name: String::new(),
            attributes: Vec::new(),
            children: Vec::new(),
        });
    }
    // inline definition: next_offset(4) + template_id(4) + size(4) + token stream
    let _next_offset = dec.read_u32()?;
    let _template_id = dec.read_u32()?;
    let def_size = dec.read_u32()?;
    if def_size as usize > dec.remaining() {
        return Err(DecodeError::Truncated(dec.pos));
    }
    let def_end = dec.pos + def_size as usize;
    let nodes = decode_nodes_until(dec, def_end, depth)?;

    // substitutions
    let num_subs = dec.read_u32()? as usize;
    if num_subs > MAX_SUBSTITUTIONS {
        return Err(DecodeError::TooManySubstitutions);
    }
    let mut subs: Vec<BinXmlValue> = Vec::with_capacity(num_subs);
    for _ in 0..num_subs {
        let vt = dec.read_u8()?;
        let v = dec.decode_value_of_type(vt)?;
        subs.push(v);
    }

    // template instance の要素数は1（root 要素）を想定。複数ある場合は最初の要素を使う。
    let mut root_node = nodes
        .into_iter()
        .find(|n| matches!(n, XmlNode::Element { .. }))
        .unwrap_or(XmlNode::Element {
            name: String::new(),
            attributes: Vec::new(),
            children: Vec::new(),
        });
    apply_substitutions(&mut root_node, &subs);
    Ok(root_node)
}

/// nodes を end_pos（または EndOfStream）まで読む。
fn decode_nodes_until(
    dec: &mut Decoder,
    end_pos: usize,
    depth: usize,
) -> Result<Vec<XmlNode>, DecodeError> {
    let mut nodes = Vec::new();
    while dec.pos < end_pos {
        let token = dec.read_u8()?;
        match token {
            TOKEN_END_OF_STREAM => break,
            TOKEN_FRAGMENT_HEADER => {
                let _major = dec.read_u8()?;
                let _flags = dec.read_u8()?;
            }
            TOKEN_OPEN_START_ELEMENT => {
                let element = decode_open_start_element(dec, depth)?;
                nodes.push(element);
                if nodes.len() > MAX_CHILDREN {
                    return Err(DecodeError::TooManyChildren);
                }
            }
            TOKEN_VALUE => {
                let v = dec.read_value()?;
                nodes.push(XmlNode::Text(v));
            }
            TOKEN_NORMAL_SUBSTITUTION => {
                let idx = dec.read_u8()? as usize;
                let _type_hint = dec.read_u8()?;
                nodes.push(XmlNode::Substitution {
                    index: idx,
                    conditional: false,
                });
            }
            TOKEN_CONDITIONAL_SUBSTITUTION => {
                let idx = dec.read_u8()? as usize;
                let _type_hint = dec.read_u8()?;
                nodes.push(XmlNode::Substitution {
                    index: idx,
                    conditional: true,
                });
            }
            TOKEN_TEMPLATE_INSTANCE => {
                let inner = decode_template_instance(dec, depth + 1)?;
                nodes.push(inner);
            }
            TOKEN_END_ELEMENT | TOKEN_CLOSE_START_ELEMENT | TOKEN_CLOSE_EMPTY_ELEMENT => {
                // template definition 内で使われる。上位の要素 loop へ返すためここでは消費。
                break;
            }
            _ => return Err(DecodeError::UnsupportedToken(token, dec.pos)),
        }
    }
    Ok(nodes)
}

/// OpenStartElement (0x03) を decode する。
/// 書式: token(1) + dependency(1) + element_data_size(4) + name(hash+count+chars)
///       + (attribute | CloseStartElement | CloseEmptyElement)*
///       + (children)* + EndElement
fn decode_open_start_element(dec: &mut Decoder, depth: usize) -> Result<XmlNode, DecodeError> {
    let _dependency = dec.read_u8()?;
    let _element_data_size = dec.read_u32()?;
    let name = dec.read_name()?;

    let mut attributes = Vec::new();
    let mut children = Vec::new();

    // attributes と CloseStartElement を探す。
    loop {
        let token = dec.peek_u8()?;
        match token {
            TOKEN_ATTRIBUTE => {
                dec.read_u8()?; // consume token
                let (n, v) = decode_attribute(dec)?;
                attributes.push((n, v));
            }
            TOKEN_CLOSE_START_ELEMENT => {
                dec.read_u8()?; // consume
                break;
            }
            TOKEN_CLOSE_EMPTY_ELEMENT => {
                dec.read_u8()?; // consume
                return Ok(XmlNode::Element {
                    name,
                    attributes,
                    children: Vec::new(),
                });
            }
            _ => break, // 属性以外のトークン → CloseStartElement 省略形の子要素 loop へ。
        }
    }

    // 子要素を EndElement まで読む。
    loop {
        let token = dec.peek_u8()?;
        match token {
            TOKEN_END_ELEMENT => {
                dec.read_u8()?; // consume
                return Ok(XmlNode::Element {
                    name,
                    attributes,
                    children,
                });
            }
            TOKEN_OPEN_START_ELEMENT => {
                dec.read_u8()?; // consume
                let child = decode_open_start_element(dec, depth + 1)?;
                children.push(child);
                if children.len() > MAX_CHILDREN {
                    return Err(DecodeError::TooManyChildren);
                }
            }
            TOKEN_VALUE => {
                dec.read_u8()?; // consume
                let v = dec.read_value()?;
                children.push(XmlNode::Text(v));
            }
            TOKEN_NORMAL_SUBSTITUTION => {
                dec.read_u8()?; // consume
                let idx = dec.read_u8()? as usize;
                let _type_hint = dec.read_u8()?;
                children.push(XmlNode::Substitution {
                    index: idx,
                    conditional: false,
                });
            }
            TOKEN_CONDITIONAL_SUBSTITUTION => {
                dec.read_u8()?; // consume
                let idx = dec.read_u8()? as usize;
                let _type_hint = dec.read_u8()?;
                children.push(XmlNode::Substitution {
                    index: idx,
                    conditional: true,
                });
            }
            TOKEN_TEMPLATE_INSTANCE => {
                dec.read_u8()?; // consume
                let inner = decode_template_instance(dec, depth + 1)?;
                children.push(inner);
            }
            TOKEN_FRAGMENT_HEADER => {
                dec.read_u8()?; // consume
                let _major = dec.read_u8()?;
                let _flags = dec.read_u8()?;
            }
            TOKEN_END_OF_STREAM => {
                dec.read_u8()?; // consume
                return Ok(XmlNode::Element {
                    name,
                    attributes,
                    children,
                });
            }
            TOKEN_ATTRIBUTE | TOKEN_CLOSE_START_ELEMENT | TOKEN_CLOSE_EMPTY_ELEMENT => {
                // 構文的に異常だが継続のため消費して無視。
                dec.read_u8()?;
            }
            _ => return Err(DecodeError::UnsupportedToken(token, dec.pos)),
        }
    }
}

/// Attribute (0x06) を decode する。
/// 書式: token(1) + dependency(1) + attribute_data_size(4) + name(hash+count+chars) + value
fn decode_attribute(dec: &mut Decoder) -> Result<(String, BinXmlValue), DecodeError> {
    let _dependency = dec.read_u8()?;
    let _attribute_data_size = dec.read_u32()?;
    let name = dec.read_name()?;
    // attribute value は value token (0x05 + type) または substitution (0x0D/0x0E + idx + type)
    let token = dec.read_u8()?;
    let value = match token {
        TOKEN_VALUE => dec.read_value()?,
        TOKEN_NORMAL_SUBSTITUTION | TOKEN_CONDITIONAL_SUBSTITUTION => {
            let _idx = dec.read_u8()?;
            let _type_hint = dec.read_u8()?;
            // substitution placeholder は後で埋めるが、attribute 内の場合は一旦 Null で代用。
            // 本 Phase では Provider Name/Guid 属性を literal で生成するため、この経路は稀。
            BinXmlValue::Null
        }
        _ => return Err(DecodeError::UnsupportedToken(token, dec.pos)),
    };
    Ok((name, value))
}

/// substitution placeholder へ実際の値を埋め込む。
fn apply_substitutions(node: &mut XmlNode, subs: &[BinXmlValue]) {
    match node {
        XmlNode::Element { children, .. } => {
            let mut new_children = Vec::with_capacity(children.len());
            for child in children.drain(..) {
                match child {
                    XmlNode::Substitution { index, conditional } => {
                        let value = subs.get(index).cloned().unwrap_or(BinXmlValue::Null);
                        if conditional && matches!(value, BinXmlValue::Null) {
                            // conditional で Null の場合は要素を除去。
                            continue;
                        }
                        new_children.push(XmlNode::Text(value));
                    }
                    mut other => {
                        apply_substitutions(&mut other, subs);
                        new_children.push(other);
                    }
                }
            }
            *children = new_children;
        }
        XmlNode::Text(_) | XmlNode::Substitution { .. } => {}
    }
}

/// XmlNode 木から EventContent を抽出する。
fn extract_event_content(root: &XmlNode) -> EventContent {
    let mut content = EventContent::default();
    let element_name = if let XmlNode::Element { name, .. } = root {
        name.clone()
    } else {
        return content;
    };
    // <Event><System>... と <Event><EventData>... を拾う。
    if element_name.eq_ignore_ascii_case("Event")
        && let XmlNode::Element { children, .. } = root
    {
        for child in children {
            if let XmlNode::Element {
                name,
                children: grand,
                ..
            } = child
            {
                let lname = name.to_ascii_lowercase();
                match lname.as_str() {
                    "system" => extract_system(grand, &mut content),
                    "eventdata" => extract_event_data(grand, &mut content),
                    _ => {}
                }
            }
        }
    }
    content
}

fn extract_system(children: &[XmlNode], content: &mut EventContent) {
    for child in children {
        if let XmlNode::Element {
            name,
            attributes,
            children: grand,
        } = child
        {
            let lname = name.to_ascii_lowercase();
            match lname.as_str() {
                "provider" => {
                    for (k, v) in attributes {
                        let k = k.to_ascii_lowercase();
                        if k == "name"
                            && let BinXmlValue::Str(s) = v
                        {
                            content.provider_name = Some(s.clone());
                        } else if k == "guid"
                            && let BinXmlValue::Str(s) = v
                        {
                            content.provider_guid = Some(s.clone());
                        }
                    }
                }
                "eventid" => {
                    if let Some(v) = first_text(grand) {
                        match v {
                            BinXmlValue::Int(n) => content.event_id = Some(*n as i32),
                            BinXmlValue::UInt(n) => content.event_id = Some(*n as i32),
                            _ => {}
                        }
                    }
                }
                "version" => {
                    if let Some(BinXmlValue::UInt(n)) = first_text(grand) {
                        content.version = Some(*n as u8);
                    } else if let Some(BinXmlValue::Int(n)) = first_text(grand) {
                        content.version = Some(*n as u8);
                    }
                }
                "level" => {
                    if let Some(BinXmlValue::UInt(n)) = first_text(grand) {
                        content.level = Some(*n as u8);
                    } else if let Some(BinXmlValue::Int(n)) = first_text(grand) {
                        content.level = Some(*n as u8);
                    }
                }
                "opcode" => {
                    if let Some(BinXmlValue::UInt(n)) = first_text(grand) {
                        content.opcode = Some(*n as u8);
                    } else if let Some(BinXmlValue::Int(n)) = first_text(grand) {
                        content.opcode = Some(*n as u8);
                    }
                }
                "channel" => {
                    if let Some(BinXmlValue::Str(s)) = first_text(grand) {
                        content.channel = Some(s.clone());
                    }
                }
                "computer" => {
                    if let Some(BinXmlValue::Str(s)) = first_text(grand) {
                        content.computer = Some(s.clone());
                    }
                }
                "task" => {
                    if let Some(BinXmlValue::UInt(n)) = first_text(grand) {
                        content.task = Some(*n as u32);
                    } else if let Some(BinXmlValue::Int(n)) = first_text(grand) {
                        content.task = Some(*n as u32);
                    }
                }
                "keywords" => {
                    if let Some(BinXmlValue::UInt(n)) = first_text(grand) {
                        content.keywords = Some(*n);
                    } else if let Some(BinXmlValue::Int(n)) = first_text(grand) {
                        content.keywords = Some(*n as u64);
                    }
                }
                _ => {}
            }
        }
    }
}

fn extract_event_data(children: &[XmlNode], content: &mut EventContent) {
    for child in children {
        if let XmlNode::Element {
            name,
            attributes,
            children: grand,
        } = child
        {
            if !name.eq_ignore_ascii_case("Data") && !name.eq_ignore_ascii_case("data") {
                continue;
            }
            // <Data Name="...">value</Data>
            let data_name = attributes
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("name"))
                .and_then(|(_, v)| {
                    if let BinXmlValue::Str(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            let value = first_text(grand)
                .map(|v| v.to_event_data_value())
                .unwrap_or(EventDataValue::Null);
            content.event_data.push((data_name, value));
        }
    }
}

fn first_text(children: &[XmlNode]) -> Option<&BinXmlValue> {
    for child in children {
        if let XmlNode::Text(v) = child {
            return Some(v);
        }
    }
    None
}

// ====================================================================
// BinXmlBuilder: テスト用エンコーダ（literal-only、substitution なし）
// ====================================================================

/// builder が生成する値の種別（テスト用）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    Null,
    String,
    Int32,
    UInt16,
    UInt32,
    UInt64,
    FileTime,
    Bool,
}

/// event 内容の builder 入力。
#[derive(Debug)]
pub struct EventContentSpec {
    pub provider_name: String,
    pub provider_guid: Option<String>,
    pub event_id: i32,
    pub version: Option<u8>,
    pub level: Option<u8>,
    pub channel: String,
    pub computer: String,
    pub event_data: Vec<EventDataEntry>,
}

/// EventData の1 entry。
#[derive(Clone, Debug)]
pub struct EventDataEntry {
    pub name: String,
    pub value: String,
    pub kind: ValueKind,
}

/// テスト用 helper: 文字列型 EventData entry を作る。
pub fn ev_data(name: impl Into<String>, value: impl Into<String>) -> EventDataEntry {
    EventDataEntry {
        name: name.into(),
        value: value.into(),
        kind: ValueKind::String,
    }
}

/// テスト用 binxml builder。`<Event><System>...</System><EventData>...</EventData></Event>`
/// を inline template instance で構築する。全ての値は literal（substitution なし）。
pub struct BinXmlBuilder {
    out: Vec<u8>,
}

impl BinXmlBuilder {
    pub fn new() -> Self {
        BinXmlBuilder { out: Vec::new() }
    }

    pub fn finish(self) -> Vec<u8> {
        // fragment header（record 直下）
        let mut result = vec![
            TOKEN_FRAGMENT_HEADER,
            0x01,
            0x00,
            // template instance header
            TOKEN_TEMPLATE_INSTANCE,
            0x01, // version
        ];
        result.extend_from_slice(&1u32.to_le_bytes()); // template_id
        result.extend_from_slice(&0u32.to_le_bytes()); // definition_offset = 0 (inline)
        // template definition header
        result.extend_from_slice(&0u32.to_le_bytes()); // next_offset
        result.extend_from_slice(&1u32.to_le_bytes()); // template_id
        let size_pos = result.len();
        result.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
        // token stream 開始
        let stream_start = result.len();
        result.push(TOKEN_FRAGMENT_HEADER);
        result.push(0x01);
        result.push(0x00);
        // 構築した event element を append。
        result.extend_from_slice(&self.out);
        let stream_end = result.len();
        let stream_size = (stream_end - stream_start) as u32;
        result[size_pos..size_pos + 4].copy_from_slice(&stream_size.to_le_bytes());
        // substitutions 0 個（literal-only）
        result.extend_from_slice(&0u32.to_le_bytes());
        result
    }

    /// event 全体を1要素として構築する。
    pub fn start_event(&mut self, spec: &EventContentSpec) {
        // <Event>
        self.open_element("Event");
        // <System>
        self.open_element("System");
        // <Provider Name="..." Guid="..."/>
        self.open_element_with_attributes("Provider", {
            let mut attrs = vec![("Name".to_string(), spec.provider_name.clone())];
            if let Some(g) = &spec.provider_guid {
                attrs.push(("Guid".to_string(), g.clone()));
            }
            attrs
        });
        self.close_empty();
        self.end_element(); // Provider
        // <EventID>val</EventID>
        self.open_element("EventID");
        self.value_int32(spec.event_id);
        self.end_element();
        if let Some(v) = spec.version {
            self.open_element("Version");
            self.value_uint8(v);
            self.end_element();
        }
        if let Some(v) = spec.level {
            self.open_element("Level");
            self.value_uint8(v);
            self.end_element();
        }
        self.open_element("Channel");
        self.value_string(&spec.channel);
        self.end_element();
        self.open_element("Computer");
        self.value_string(&spec.computer);
        self.end_element();
        self.end_element(); // </System>

        if !spec.event_data.is_empty() {
            self.open_element("EventData");
            for entry in &spec.event_data {
                self.open_element_with_attributes(
                    "Data",
                    vec![("Name".to_string(), entry.name.clone())],
                );
                match entry.kind {
                    ValueKind::String => self.value_string(&entry.value),
                    ValueKind::Int32 => {
                        let v: i32 = entry.value.parse().unwrap_or(0);
                        self.value_int32(v);
                    }
                    ValueKind::UInt16 => {
                        let v: u16 = entry.value.parse().unwrap_or(0);
                        self.value_uint16(v);
                    }
                    ValueKind::UInt32 => {
                        let v: u32 = entry.value.parse().unwrap_or(0);
                        self.value_uint32(v);
                    }
                    ValueKind::UInt64 => {
                        let v: u64 = entry.value.parse().unwrap_or(0);
                        self.value_uint64(v);
                    }
                    ValueKind::FileTime => {
                        let v: u64 = entry.value.parse().unwrap_or(0);
                        self.value_filetime(v);
                    }
                    ValueKind::Bool => {
                        let v: bool = entry.value == "true" || entry.value == "1";
                        self.value_bool(v);
                    }
                    ValueKind::Null => self.value_null(),
                }
                self.end_element();
            }
            self.end_element();
        }

        self.end_element(); // </Event>
    }

    fn open_element(&mut self, name: &str) {
        self.out.push(TOKEN_OPEN_START_ELEMENT);
        self.out.push(0x00); // dependency
        let nb = name_bytes(name);
        self.out.extend_from_slice(&(nb.len() as u32).to_le_bytes());
        self.out.extend_from_slice(&nb);
        self.out.push(TOKEN_CLOSE_START_ELEMENT);
    }

    fn open_element_with_attributes(&mut self, name: &str, attrs: Vec<(String, String)>) {
        self.out.push(TOKEN_OPEN_START_ELEMENT);
        self.out.push(0x00);
        let nb = name_bytes(name);
        self.out.extend_from_slice(&(nb.len() as u32).to_le_bytes());
        self.out.extend_from_slice(&nb);
        for (an, av) in attrs {
            self.out.push(TOKEN_ATTRIBUTE);
            self.out.push(0x00);
            let anb = name_bytes(&an);
            self.out
                .extend_from_slice(&(anb.len() as u32).to_le_bytes());
            self.out.extend_from_slice(&anb);
            self.out.push(TOKEN_VALUE);
            self.out.push(VALUE_TYPE_STRING);
            let chars: Vec<u16> = av.encode_utf16().collect();
            self.out
                .extend_from_slice(&(chars.len() as u16).to_le_bytes());
            for u in chars {
                self.out.extend_from_slice(&u.to_le_bytes());
            }
        }
        self.out.push(TOKEN_CLOSE_START_ELEMENT);
    }

    fn close_empty(&mut self) {
        self.out.push(TOKEN_CLOSE_EMPTY_ELEMENT);
    }

    fn end_element(&mut self) {
        self.out.push(TOKEN_END_ELEMENT);
    }

    fn value_string(&mut self, s: &str) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_STRING);
        let chars: Vec<u16> = s.encode_utf16().collect();
        self.out
            .extend_from_slice(&(chars.len() as u16).to_le_bytes());
        for u in chars {
            self.out.extend_from_slice(&u.to_le_bytes());
        }
    }

    fn value_int32(&mut self, v: i32) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_INT32);
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn value_uint8(&mut self, v: u8) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_UINT8);
        self.out.push(v);
    }

    fn value_uint16(&mut self, v: u16) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_UINT16);
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn value_uint32(&mut self, v: u32) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_UINT32);
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn value_uint64(&mut self, v: u64) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_UINT64);
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn value_filetime(&mut self, v: u64) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_FILETIME);
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn value_bool(&mut self, v: bool) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_BOOL);
        self.out.push(if v { 1 } else { 0 });
    }

    fn value_null(&mut self) {
        self.out.push(TOKEN_VALUE);
        self.out.push(VALUE_TYPE_NULL);
    }
}

impl Default for BinXmlBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// name 構造体: hash(4) + count(2) + UTF-16LE bytes。
/// hash は decoder 側で使用しないため 0 で構わない。
fn name_bytes(name: &str) -> Vec<u8> {
    let chars: Vec<u16> = name.encode_utf16().collect();
    let mut buf = Vec::with_capacity(6 + chars.len() * 2);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&(chars.len() as u16).to_le_bytes());
    for u in chars {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> Vec<u8> {
        let mut builder = BinXmlBuilder::new();
        builder.start_event(&EventContentSpec {
            provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
            provider_guid: Some("{54849625-5478-4994-A5BA-3E3B0328C30D}".to_string()),
            event_id: 4624,
            version: Some(0),
            level: Some(0),
            channel: "Security".to_string(),
            computer: "WORKSTATION1".to_string(),
            event_data: vec![
                ev_data("TargetUserName", "alice"),
                ev_data("LogonType", "3"),
            ],
        });
        builder.finish()
    }

    #[test]
    fn decodes_minimal_event() {
        let data = sample_event();
        let content = decode_record(&data).unwrap();
        assert_eq!(content.event_id, Some(4624));
        assert_eq!(
            content.provider_name.as_deref(),
            Some("Microsoft-Windows-Security-Auditing")
        );
        assert_eq!(content.channel.as_deref(), Some("Security"));
        assert_eq!(content.computer.as_deref(), Some("WORKSTATION1"));
        assert_eq!(content.event_data.len(), 2);
        assert_eq!(content.event_data[0].0, "TargetUserName");
        assert_eq!(content.event_data[0].1.as_str_value(), "alice");
    }

    #[test]
    fn empty_data_returns_default() {
        let content = decode_record(&[]).unwrap();
        assert_eq!(content, EventContent::default());
    }

    #[test]
    fn truncated_data_returns_err() {
        let data = [TOKEN_FRAGMENT_HEADER, 0x01];
        let err = decode_record(&data).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated(_)));
    }

    #[test]
    fn guid_format_correct() {
        // GUID {54849625-5478-4994-a5ba-3e3b0328c30d} を Windows LE byte order へ。
        let raw: [u8; 16] = [
            0x25, 0x96, 0x84, 0x54, // d1 LE
            0x78, 0x54, // d2 LE
            0x94, 0x49, // d3 LE
            0xa5, 0xba, // d4 BE
            0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d, // d5 BE
        ];
        let g = format_guid(&raw);
        assert_eq!(g, "{54849625-5478-4994-a5ba-3e3b0328c30d}");
    }

    #[test]
    fn decodes_event_without_eventdata() {
        let mut builder = BinXmlBuilder::new();
        builder.start_event(&EventContentSpec {
            provider_name: "Service Control Manager".to_string(),
            provider_guid: None,
            event_id: 7045,
            version: None,
            level: None,
            channel: "System".to_string(),
            computer: "HOST".to_string(),
            event_data: vec![],
        });
        let data = builder.finish();
        let content = decode_record(&data).unwrap();
        assert_eq!(content.event_id, Some(7045));
        assert_eq!(
            content.provider_name.as_deref(),
            Some("Service Control Manager")
        );
        assert_eq!(content.channel.as_deref(), Some("System"));
        assert!(content.event_data.is_empty());
    }

    #[test]
    fn event_data_value_kinds_preserved() {
        let mut builder = BinXmlBuilder::new();
        builder.start_event(&EventContentSpec {
            provider_name: "P".to_string(),
            provider_guid: None,
            event_id: 1,
            version: None,
            level: None,
            channel: "C".to_string(),
            computer: "H".to_string(),
            event_data: vec![
                EventDataEntry {
                    name: "u32".into(),
                    value: "12345".into(),
                    kind: ValueKind::UInt32,
                },
                EventDataEntry {
                    name: "u64".into(),
                    value: "99999999999".into(),
                    kind: ValueKind::UInt64,
                },
                EventDataEntry {
                    name: "bool".into(),
                    value: "true".into(),
                    kind: ValueKind::Bool,
                },
                EventDataEntry {
                    name: "ft".into(),
                    value: "132548480000000000".into(),
                    kind: ValueKind::FileTime,
                },
            ],
        });
        let data = builder.finish();
        let content = decode_record(&data).unwrap();
        assert_eq!(content.event_data.len(), 4);
        assert_eq!(content.event_data[0].0, "u32");
        assert_eq!(content.event_data[0].1.as_str_value(), "12345");
        assert_eq!(content.event_data[3].1.as_str_value(), "132548480000000000");
    }

    #[test]
    fn decoder_handles_empty_template_stream() {
        // template definition size = 0（token stream 空）+ 0 substitutions。
        let mut data = vec![
            TOKEN_FRAGMENT_HEADER,
            0x01,
            0x00,
            TOKEN_TEMPLATE_INSTANCE,
            0x01,
        ];
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // definition_offset
        data.extend_from_slice(&0u32.to_le_bytes()); // next_offset
        data.extend_from_slice(&1u32.to_le_bytes()); // template_id
        data.extend_from_slice(&0u32.to_le_bytes()); // size = 0
        data.extend_from_slice(&0u32.to_le_bytes()); // 0 substitutions
        let content = decode_record(&data).unwrap();
        assert_eq!(content, EventContent::default());
    }
}
