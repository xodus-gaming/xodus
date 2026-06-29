use zerocopy::{FromBytes, little_endian::*};

#[derive(FromBytes, Debug)]
#[repr(C, packed)]
pub struct XspHeader {
    pub signature: [u8; 0x200],
    pub magic: [u8; 8],
    pub block_size_or_payload: U32, // Or payload offset
    pub _unknown_val: [u8; 4],
    pub vduid: [u8; 0x10],
    pub uduid: [u8; 0x10],
    pub build_id: [u8; 0x10],
    pub _reserved: [u8; 0x30],
    pub _unknown1: U32,
    pub _unknown2: U32,
    pub _unknown3: U32,
    pub record_count: U32,
    pub _unknown_block_size_or_payload: U64,
    pub _reserved2: [u8; 8],
    pub _reserved3: [u8; 8],
    pub _reserved4: [u8; 8],
    pub _reserved5: [u8; 8],
    pub _unknown_int1: U64,
    pub next_block_size: U64,
    pub _unknown4: U64,
    pub number_of_elements: U32,
    pub _value_1: U32,
    pub total_bytes: U64,
    pub disk_space_required: U64,
    pub _value_0: U64,
    pub _unknown5: U64,
    pub _value2_0: U64,
    pub _unknown_big_value: U64,
    pub _unknown6: U64,
    pub always_64: U64, // Potential alignment / cluster size
    pub _reserved6: [u8; 0x10],
    pub plan_id: [u8; 0x10],
    pub _value3_0: [u8; 0x14],
    pub xsp_id: [u8; 0x10],
    pub previous_build_version: [U16; 4],
    pub current_build_version: [U16; 4],
}

#[derive(FromBytes, Debug)]
#[repr(C, packed)]
pub struct XspPatchRecord {
    pub source_offset: U32,
    pub flag: U32,
    pub target_offset: U32,
    pub length: U32,
}
