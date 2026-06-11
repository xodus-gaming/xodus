use zerocopy::FromBytes;

use crate::{
    models::xvd::{
        constants::{LEGACY_SECTOR_SIZE, SECTOR_SIZE, XVD_HEADER_INCL_SIGNATURE_SIZE},
        XvdVolumeFlags,
    },
    xvd::math::{bytes_to_pages, calculate_number_of_hash_pages, page_number_to_offset},
};

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdHeader {
    pub signature: [u8; 0x200],
    pub magic: [u8; 8],
    pub volume_flags: u32,
    pub format_version: u32,
    pub file_time_created: i64,
    pub drive_size: u64,
    pub vduid: [u8; 0x10],
    pub uduid: [u8; 0x10],
    pub top_hash_block_hash: [u8; 0x20],
    pub original_xvc_data_hash: [u8; 0x20],
    pub xvd_type: u32,
    pub xvd_content_type: u32,
    pub embedded_xvd_length: u32,
    pub user_data_length: u32,
    pub xvc_data_length: u32,
    pub dynamic_header_length: u32,
    pub block_size: u32,
    pub ext_entries: [XvdExtEntry; 0x4],
    pub capabilities: [u16; 0x8],
    pub pe_catalog_hash: [u8; 0x20],
    pub embedded_xvd_pduid: [u8; 0x10],
    pub reserved13c: [u8; 0x10],
    pub key_material: [u8; 0x20],
    pub user_data_hash: [u8; 0x20],
    pub sandbox_id: [u8; 0x10],
    pub product_id: [u8; 0x10],
    pub pduid: [u8; 0x10],
    pub package_version1: u16,
    pub package_version2: u16,
    pub package_version3: u16,
    pub package_version4: u16,
    pub pe_catalog_caps: [u16; 0x10],
    pub pe_catalogs: [u8; 0x80],
    pub writeable_expiration_date: u32,
    pub writeable_policy_flags: u32,
    pub persitent_local_storage_size: u32,
    pub mutable_page_count: u8,
    pub _unknown271: u8,
    pub _unknown272: [u8; 0x10],
    pub _reserved282: [u8; 0xA],
    pub sequence_number: i64,
    pub required_system_version1: u16,
    pub required_system_version2: u16,
    pub required_system_version3: u16,
    pub required_system_version4: u16,
    pub odk_keyslot_id: u32,
    pub _reservedd2a0: [u8; 0xB54],
    pub resilient_data_offset: u64,
    pub resilient_data_length: u32, /* 0xE00 = END */
}

impl XvdHeader {
    pub fn is_encrypted(&self) -> bool {
        (self.volume_flags & XvdVolumeFlags::EncryptionDisabled as u32) == 0
    }

    pub fn is_legacy_sector_size(&self) -> bool {
        (self.volume_flags & XvdVolumeFlags::LegacySectorSize as u32) != 0
    }

    pub fn is_data_integrity_enabled(&self) -> bool {
        (self.volume_flags & XvdVolumeFlags::DataIntegrityDisabled as u32) == 0
    }

    pub fn is_resiliency_enabled(&self) -> bool {
        (self.volume_flags & XvdVolumeFlags::ResiliencyEnabled as u32) != 0
    }

    pub fn mutable_data_length(&self) -> u64 {
        page_number_to_offset(self.mutable_page_count as u64)
    }

    pub fn user_data_page_count(&self) -> u64 {
        bytes_to_pages(self.user_data_length as u64)
    }

    pub fn xvc_data_page_count(&self) -> u64 {
        bytes_to_pages(self.xvc_data_length as u64)
    }

    pub fn embedded_xvd_page_count(&self) -> u64 {
        bytes_to_pages(self.embedded_xvd_length as u64)
    }

    pub fn dynamic_header_page_count(&self) -> u64 {
        bytes_to_pages(self.dynamic_header_length as u64)
    }

    pub fn drive_page_count(&self) -> u64 {
        bytes_to_pages(self.drive_size)
    }

    pub fn number_of_hashed_pages(&self) -> u64 {
        self.drive_page_count()
            + self.user_data_page_count()
            + self.xvc_data_page_count()
            + self.dynamic_header_page_count()
    }

    pub fn number_of_metadata_pages(&self) -> u64 {
        self.user_data_page_count() + self.xvc_data_page_count() + self.dynamic_header_page_count()
    }

    pub fn sector_size(&self) -> u32 {
        if self.is_legacy_sector_size() {
            LEGACY_SECTOR_SIZE
        } else {
            SECTOR_SIZE
        }
    }

    pub fn mdu_offset(&self) -> u64 {
        page_number_to_offset(self.embedded_xvd_page_count()) + XVD_HEADER_INCL_SIGNATURE_SIZE
    }

    pub fn hash_tree_offset(&self) -> u64 {
        self.mutable_data_length() + self.mdu_offset()
    }

    pub fn hash_tree_info(&self) -> (u64, u64) {
        calculate_number_of_hash_pages(self.number_of_hashed_pages(), self.is_resiliency_enabled())
    }

    pub fn user_data_offset(&self, hash_tree_page_count: u64) -> u64 {
        let hash_pages_offset = if self.is_data_integrity_enabled() {
            page_number_to_offset(hash_tree_page_count)
        } else {
            0
        };

        hash_pages_offset + self.hash_tree_offset()
    }

    pub fn xvc_info_offset(&self, hash_tree_page_count: u64) -> u64 {
        page_number_to_offset(self.user_data_page_count()) + self.user_data_offset(hash_tree_page_count)
    }
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdExtEntry {
    pub code: u32,
    pub length: u32,
    pub offset: u64,
    pub data_length: u32,
    pub reserved: u32,
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvcInfo {
    pub content_id: [u8; 0x10],
    pub xvc_encryption_key_id: [[u8; 0x10]; 0xC0],
    pub description: [u8; 0x100],
    pub version: u32,
    pub region_count: u32,
    pub flags: u32,
    pub _paddingd1c: u16,
    pub key_count: u16,
    pub _unknownd20: u32,
    pub initial_play_region_id: u32,
    pub initial_play_offse: u64,
    pub file_time_created: i64,
    pub preview_region_id: u32,
    pub update_segment_count: u32,
    pub preview_offset: u64,
    pub _unused_space: u64,
    pub region_specifier_count: u32,
    pub _reserved: [u8; 0x54], /* 0xDA8 = END (actually 0x2000 but rest is read in XVDFile) */
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvdUpdateSegment {
    pub page_num: u32,
    pub hash: u64
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvcRegionSpecifier {
    pub region_id: u32,
    pub padding4: u32,
    pub key: [u8; 0x80], // UTF-16
    pub value: [u8; 0x100] // UTF-16
}

#[derive(FromBytes)]
#[repr(C, packed)]
pub struct XvcRegionHeader {
    pub region_id: u32,
    pub key_id: u16,
    pub padding6: u16,
    pub flags: u32,
    pub first_segment_index: u32,
    pub description: [u8; 0x40], // UTF-16
    pub offset: u64,
    pub length: u64,
    pub hash: u64,
    pub unknown_68: u64,
    pub unknown_70: u64,
    pub unknown_78: u64,
}
