use zerocopy::{FromBytes, little_endian::*};

// All multi-byte integers must use zerocopy's endian-aware types.

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdHeader {
    pub signature: [u8; 0x200],
    pub magic: [u8; 8],
    pub volume_flags: U32,
    pub format_version: U32,
    pub file_time_created: I64,
    pub drive_size: U64,
    pub vduid: [u8; 0x10],
    pub uduid: [u8; 0x10],
    pub top_hash_block_hash: [u8; 0x20],
    pub original_xvc_data_hash: [u8; 0x20],
    pub xvd_type: U32,
    pub xvd_content_type: U32,
    pub embedded_xvd_length: U32,
    pub user_data_length: U32,
    pub xvc_data_length: U32,
    pub dynamic_header_length: U32,
    pub block_size: U32,
    pub ext_entries: [XvdExtEntry; 0x4],
    pub capabilities: [U16; 0x8],
    pub pe_catalog_hash: [u8; 0x20],
    pub embedded_xvd_pduid: [u8; 0x10],
    pub reserved13c: [u8; 0x10],
    pub key_material: [u8; 0x20],
    pub user_data_hash: [u8; 0x20],
    pub sandbox_id: [u8; 0x10],
    pub product_id: [u8; 0x10],
    pub pduid: [u8; 0x10],
    pub package_version1: U16,
    pub package_version2: U16,
    pub package_version3: U16,
    pub package_version4: U16,
    pub pe_catalog_caps: [U16; 0x10],
    pub pe_catalogs: [u8; 0x80],
    pub writeable_expiration_date: U32,
    pub writeable_policy_flags: U32,
    pub persistent_local_storage_size: U32,
    pub mutable_page_count: u8,
    pub _unknown271: u8,
    pub _unknown272: [u8; 0x10],
    pub _reserved282: [u8; 0xA],
    pub sequence_number: I64,
    pub required_system_version1: U16,
    pub required_system_version2: U16,
    pub required_system_version3: U16,
    pub required_system_version4: U16,
    pub odk_keyslot_id: U32,
    pub _reservedd2a0: [u8; 0xB54],
    pub resilient_data_offset: U64,
    pub resilient_data_length: U32, /* 0xE00 = END */
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdExtEntry {
    pub code: U32,
    pub length: U32,
    pub offset: U64,
    pub data_length: U32,
    pub reserved: U32,
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdHashEntry {
    pub block_hash: [u8; 0x14],
    pub unit: U32,
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvcInfo {
    pub content_id: [u8; 0x10],
    pub xvc_encryption_key_id: [[u8; 0x10]; 0xC0],
    pub description: [u8; 0x100],
    pub version: U32,
    pub region_count: U32,
    pub flags: U32,
    pub _paddingd1c: U16,
    pub key_count: U16,
    pub _unknownd20: U32,
    pub initial_play_region_id: U32,
    pub initial_play_offset: U64,
    pub file_time_created: I64,
    pub preview_region_id: U32,
    pub update_segment_count: U32,
    pub preview_offset: U64,
    pub _unused_space: U64,
    pub region_specifier_count: U32,
    pub _reserved: [u8; 0x54], /* 0xDA8 = END (actually 0x2000 but rest is read in XVDFile) */
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdUpdateSegment {
    pub page_num: U32,
    pub hash: U64,
}

#[derive(FromBytes, Debug)]
#[repr(C, packed)]
pub struct XvcRegionSpecifier {
    pub region_id: U32,
    pub padding4: U32,
    pub key: [U16; 0x40],   // UTF-16
    pub value: [U16; 0x80], // UTF-16
}

#[derive(FromBytes, Debug)]
#[repr(C, packed)]
pub struct XvcRegionHeader {
    pub region_id: U32,
    pub key_id: U16,
    pub padding6: U16,
    pub flags: U32,
    pub first_segment_index: U32,
    pub description: [U16; 0x20], // UTF-16
    pub offset: U64,
    pub length: U64,
    pub hash: U64,
    pub unknown_68: U64,
    pub unknown_70: U64,
    pub unknown_78: U64,
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvcRegionPresenceInfo(pub u8);

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdUserDataHeader {
    pub length: U32,
    pub version: U32,
    pub t: U32,
    pub unknown: U32,
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdUserDataPackageFilesHeader {
    pub version: U32,
    pub package_full_name: [U16; 260], // UTF-16
    pub file_count: U32,
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdUserDataPackageFileEntry {
    pub file_path: [U16; 260], // UTF-16
    pub size: U32,
    pub offset: U32,
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdSegmentMetadataHeader {
    pub magic: [u8; 4],
    pub version0: U32,
    pub version1: U32,
    pub header_length: U32,
    pub segment_count: U32,
    pub file_paths_length: U32,
    pub pduid: [u8; 0x10],
    pub unknown: [u8; 0x3c],
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdSegmentMetadataSegment {
    pub flags: U16,
    pub path_length: U16,
    pub path_offset: U32,
    pub filesize: U64,
}
