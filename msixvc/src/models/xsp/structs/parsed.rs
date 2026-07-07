use super::raw;
use crate::models::common::Version;

#[derive(Debug, Clone)]
pub struct XspHeader {
    pub content_id: uuid::Uuid,
    pub plan_id: uuid::Uuid,
    pub xsp_id: uuid::Uuid,
    pub page_size: u32,
    pub record_count: u32,
    pub total_download: u64,
    pub disk_space_required: u64,
    pub upgrade_from_version: Version,
    pub upgrade_to_version: Version,
}

impl XspHeader {
    const MAGIC: [u8; 8] = *b"MS-XPFM ";
}

#[derive(thiserror::Error, Debug)]
pub enum XspHeaderParseError {
    #[error(r#"invalid magic: expected {magic:?}, got {0:?}"#, magic = XspHeader::MAGIC)]
    InvalidMagic([u8; 8]),
}

impl TryFrom<raw::XspHeader> for XspHeader {
    type Error = XspHeaderParseError;

    fn try_from(value: raw::XspHeader) -> Result<Self, Self::Error> {
        if value.magic != Self::MAGIC {
            return Err(XspHeaderParseError::InvalidMagic(value.magic));
        }

        Ok(Self {
            content_id: uuid::Uuid::from_bytes_le(value.vduid),
            plan_id: uuid::Uuid::from_bytes_le(value.plan_id),
            xsp_id: uuid::Uuid::from_bytes_le(value.xsp_id),
            page_size: value.block_size_or_payload.get(),
            record_count: value.record_count.get(),
            total_download: value.total_bytes.get(),
            disk_space_required: value.disk_space_required.get(),
            upgrade_from_version: Version::from_fields(
                value.previous_build_version.map(|n| n.get()),
            ),
            upgrade_to_version: Version::from_fields(value.current_build_version.map(|n| n.get())),
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
