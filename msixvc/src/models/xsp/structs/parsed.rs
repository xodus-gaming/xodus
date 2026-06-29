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

        Ok(Self {
            content_id: uuid::Uuid::from_bytes_le(value.vduid),
            page_size: value.block_size_or_payload.get(),
            record_count: value.record_count.get(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum XspPatchRecord {
    NewData {
        block_number: u32,
        block_count: u32,
    },
    CopyData {
        old_block_number: u32,
        new_block_number: u32,
        block_count: u32,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum XspPatchRecordParseError {
    #[error("Unknown patch record flag {0:X}")]
    UnknownFlag(u32),
}

impl TryFrom<raw::XspPatchRecord> for XspPatchRecord {
    type Error = XspPatchRecordParseError;

    fn try_from(value: raw::XspPatchRecord) -> Result<Self, Self::Error> {
        let flag = value.flag.get();

        match flag {
            0 => Ok(Self::NewData {
                block_number: value.target_offset.get(),
                block_count: value.length.get(),
            }),
            0x88000000 => Ok(Self::CopyData {
                old_block_number: value.source_offset.get(),
                new_block_number: value.target_offset.get(),
                block_count: value.length.get(),
            }),
            _ => Err(XspPatchRecordParseError::UnknownFlag(flag)),
        }
    }
}
