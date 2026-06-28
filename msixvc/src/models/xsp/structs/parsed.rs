use crate::models::xsp::raw;

#[derive(Debug, Clone)]
pub struct XspHeader {
    pub content_id: uuid::Uuid,
    pub page_size: u32,
    pub record_count: u32,
}

#[derive(thiserror::Error, Debug)]
pub enum XspHeaderParseError {
    #[error(r#"invalid magic: expected "MS-XPFM": {0:?}"#)]
    InvalidMagic([u8; 8]),
}

impl XspHeader {
    const MAGIC: [u8; 8] = *b"MS-XPFM ";
}

impl TryFrom<raw::XspHeader> for XspHeader {
    type Error = XspHeaderParseError;

    fn try_from(value: raw::XspHeader) -> Result<Self, Self::Error> {
        if value.magic != Self::MAGIC {
            return Err(XspHeaderParseError::InvalidMagic(value.magic));
        }

        println!("{value:#?}");

        Ok(Self {
            content_id: uuid::Uuid::from_bytes_le(value.vduid),
            page_size: value.block_size_or_payload.get(),
            record_count: value.record_count.get(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct XspPatchRecord {
    pub source: u32,
    pub flag: u32,
    pub target: u32,
    pub size: u32,
}

impl From<raw::XspPatchRecord> for XspPatchRecord {
    fn from(value: raw::XspPatchRecord) -> Self {
        Self {
            source: value.source_offset.get(),
            flag: value.flag.get(),
            target: value.target_offset.get(),
            size: value.length.get(),
        }
    }
}
