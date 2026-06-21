use super::raw;
use crate::models::xvd::constants::{
    LEGACY_SECTOR_SIZE, SECTOR_SIZE, XVD_HEADER_INCL_SIGNATURE_SIZE,
};
use crate::models::xvd::enums::{XvcRegionId, XvdContentType, XvdType};
use crate::models::xvd::flags::{
    WriteablePolicyFlags, XvcInfoFlags, XvcRegionFlags, XvcRegionPresenceInfoFlags,
    XvdSegmentMetadataSegmentFlags, XvdVolumeFlags,
};
use crate::xvd::math::{bytes_to_pages, calculate_number_of_hash_pages, page_number_to_offset};

use std::collections::HashMap;
use std::fmt::{Debug, Display};

use chrono::DateTime;
use num_enum::TryFromPrimitiveError;
use uuid::Uuid;

/// Converts a Microsoft FILETIME (number of 100ns intervals since 1601-01-01 UTC)
/// into a [`chrono::DateTime`]
const fn microsoft_filetime(filetime: i64) -> DateTime<chrono::Utc> {
    // FILETIME counts 100ns intervals since 1601-01-01 UTC.
    // Unix time counts nanoseconds since 1970-01-01 UTC.

    /// Number of 100 nanoseconds between FILETIME epoch and Unix time
    const FILETIME_TO_UNIX: i64 = 116_444_736_000_000_000;

    let unix_nanos = (filetime - FILETIME_TO_UNIX) * 100;
    DateTime::from_timestamp_nanos(unix_nanos)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.patch, self.build
        )
    }
}

impl Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use the Display implementation as the Debug one
        write!(f, "{}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdHeader {
    pub signature: [u8; 0x200],
    pub volume_flags: XvdVolumeFlags,
    pub format_version: u32,
    pub file_time_created: DateTime<chrono::Utc>,
    pub drive_size: u64,
    pub vduid: Uuid,
    pub uduid: Uuid,
    pub top_hash_block_hash: [u8; 0x20],
    pub original_xvc_data_hash: [u8; 0x20],
    pub xvd_type: XvdType,
    pub xvd_content_type: XvdContentType,
    pub embedded_xvd_length: u32,
    pub user_data_length: u32,
    pub xvc_data_length: u32,
    pub dynamic_header_length: u32,
    pub block_size: u32,
    pub ext_entries: [XvdExtEntry; 0x4],
    pub capabilities: [u16; 0x8],
    pub pe_catalog_hash: [u8; 0x20],
    pub embedded_xvd_pduid: Uuid,
    pub key_material: [u8; 0x20],
    pub user_data_hash: [u8; 0x20],
    pub sandbox_id: [u8; 0x10],
    pub product_id: Uuid,
    pub pduid: Uuid,
    pub package_version: Version,
    pub pe_catalog_caps: [u16; 0x10],
    pub pe_catalogs: [u8; 0x80],
    pub writeable_expiration_date: u32,
    pub writeable_policy_flags: WriteablePolicyFlags,
    pub persistent_local_storage_size: u32,
    pub mutable_page_count: u8,
    pub sequence_number: i64,
    pub required_system_version: Version,
    pub odk_keyslot_id: u32,
    pub resilient_data_offset: u64,
    pub resilient_data_length: u32,
}

impl XvdHeader {
    const MAGIC: [u8; 8] = *b"msft-xvd";
}

#[derive(thiserror::Error, Debug)]
pub enum XvdHeaderParseError {
    #[error(r#"invalid magic: expected "msft-xvd", got {0:?}"#)]
    InvalidMagic([u8; 8]),

    #[error("invalid xvd type: {0}")]
    InvalidXvdType(#[from] TryFromPrimitiveError<XvdType>),

    #[error("invalid xvd content type: {0}")]
    InvalidXvdContentType(#[from] TryFromPrimitiveError<XvdContentType>),
}

impl TryFrom<raw::XvdHeader> for XvdHeader {
    type Error = XvdHeaderParseError;

    fn try_from(value: raw::XvdHeader) -> Result<Self, Self::Error> {
        if value.magic != Self::MAGIC {
            return Err(XvdHeaderParseError::InvalidMagic(value.magic));
        }

        Ok(Self {
            signature: value.signature,
            volume_flags: XvdVolumeFlags::from_bits_retain(value.volume_flags.get()),
            format_version: value.format_version.get(),
            file_time_created: microsoft_filetime(value.file_time_created.get()),
            drive_size: value.drive_size.get(),
            vduid: Uuid::from_bytes_le(value.vduid),
            uduid: Uuid::from_bytes_le(value.uduid),
            top_hash_block_hash: value.top_hash_block_hash,
            original_xvc_data_hash: value.original_xvc_data_hash,
            xvd_type: (value.xvd_type.get() as u8).try_into()?,
            xvd_content_type: (value.xvd_content_type.get() as u8).try_into()?,
            embedded_xvd_length: value.embedded_xvd_length.get(),
            user_data_length: value.user_data_length.get(),
            xvc_data_length: value.xvc_data_length.get(),
            dynamic_header_length: value.dynamic_header_length.get(),
            block_size: value.block_size.get(),
            ext_entries: value.ext_entries.map(|e| e.into()),
            capabilities: value.capabilities.map(|n| n.get()),
            pe_catalog_hash: value.pe_catalog_hash,
            embedded_xvd_pduid: Uuid::from_bytes_le(value.embedded_xvd_pduid),
            key_material: value.key_material,
            user_data_hash: value.user_data_hash,
            sandbox_id: value.sandbox_id,
            product_id: Uuid::from_bytes_le(value.product_id),
            pduid: Uuid::from_bytes_le(value.pduid),
            package_version: Version {
                major: value.package_version4.get(),
                minor: value.package_version3.get(),
                patch: value.package_version2.get(),
                build: value.package_version1.get(),
            },
            pe_catalog_caps: value.pe_catalog_caps.map(|n| n.get()),
            pe_catalogs: value.pe_catalogs,
            writeable_expiration_date: value.writeable_expiration_date.get(),
            writeable_policy_flags: WriteablePolicyFlags::from_bits_retain(
                value.writeable_policy_flags.get(),
            ),
            persistent_local_storage_size: value.persistent_local_storage_size.get(),
            mutable_page_count: value.mutable_page_count,
            sequence_number: value.sequence_number.get(),
            required_system_version: Version {
                major: value.required_system_version4.get(),
                minor: value.required_system_version3.get(),
                patch: value.required_system_version2.get(),
                build: value.required_system_version1.get(),
            },
            odk_keyslot_id: value.odk_keyslot_id.get(),
            resilient_data_offset: value.resilient_data_offset.get(),
            resilient_data_length: value.resilient_data_length.get(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XvdExtEntry {
    pub code: u32,
    pub length: u32,
    pub offset: u64,
    pub data_length: u32,
}

impl From<raw::XvdExtEntry> for XvdExtEntry {
    fn from(value: raw::XvdExtEntry) -> Self {
        Self {
            code: value.code.get(),
            length: value.length.get(),
            offset: value.offset.get(),
            data_length: value.data_length.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdHashEntry {
    /// Truncated SHA-256 hash
    pub block_hash: [u8; 0x14],
    /// Appears to be a counter with an offset applied
    pub unit: u32,
}

impl From<raw::XvdHashEntry> for XvdHashEntry {
    fn from(value: raw::XvdHashEntry) -> Self {
        Self {
            block_hash: value.block_hash,
            unit: value.unit.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvcInfo {
    pub content_id: Uuid,
    pub xvc_encryption_key_id: HashMap<u16, Uuid>,
    pub description: [u8; 0x100],
    pub version: u32,
    pub region_count: u32,
    pub flags: XvcInfoFlags,
    pub key_count: u16,
    pub initial_play_region_id: XvcRegionId,
    pub initial_play_offset: u64,
    pub file_time_created: DateTime<chrono::Utc>,
    pub preview_region_id: XvcRegionId,
    pub update_segment_count: u32,
    pub preview_offset: u64,
    pub region_specifier_count: u32,
}

impl From<raw::XvcInfo> for XvcInfo {
    fn from(value: raw::XvcInfo) -> Self {
        Self {
            content_id: Uuid::from_bytes_le(value.content_id),
            xvc_encryption_key_id: value
                .xvc_encryption_key_id
                .into_iter()
                .enumerate()
                .map(|(i, uuid)| (i as u16, Uuid::from_bytes_le(uuid)))
                .filter(|(_i, id)| !id.is_nil())
                .collect(),
            description: value.description,
            version: value.version.get(),
            region_count: value.region_count.get(),
            flags: XvcInfoFlags::from_bits_retain(value.flags.get()),
            key_count: value.key_count.get(),
            initial_play_region_id: value.initial_play_region_id.get().into(),
            initial_play_offset: value.initial_play_offset.get(),
            file_time_created: microsoft_filetime(value.file_time_created.get()),
            preview_region_id: value.preview_region_id.get().into(),
            update_segment_count: value.update_segment_count.get(),
            preview_offset: value.preview_offset.get(),
            region_specifier_count: value.region_specifier_count.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdUpdateSegment {
    pub page_num: u32,
    pub hash: u64,
}

impl From<raw::XvdUpdateSegment> for XvdUpdateSegment {
    fn from(value: raw::XvdUpdateSegment) -> Self {
        Self {
            page_num: value.page_num.get(),
            hash: value.hash.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvcRegionSpecifier {
    pub region_id: XvcRegionId,
    pub key: [u16; 0x40],   // UTF-16
    pub value: [u16; 0x80], // UTF-16
}

impl From<raw::XvcRegionSpecifier> for XvcRegionSpecifier {
    fn from(value: raw::XvcRegionSpecifier) -> Self {
        Self {
            region_id: value.region_id.get().into(),
            key: value.key.map(|n| n.get()),
            value: value.value.map(|n| n.get()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XvcKeyId(Option<u8>);

impl XvcKeyId {
    fn new(key_id: u16) -> XvcKeyId {
        // `raw::XvcInfo` can hold up to 0xC0 encryption keys
        // Any key higher than that means the region is unencrypted
        if key_id < 0xC0 {
            Self(Some(key_id as u8))
        } else {
            Self(None)
        }
    }

    pub fn is_encrypted(self) -> bool {
        self.0.is_some()
    }

    /// Returns the index of the key, or `None` if it is unencrypted.
    ///
    /// If the returned `Option` is `Some`, then its value is guaranteed
    /// to be a number in the bounds: `0..0xC0`
    pub fn get(self) -> Option<u8> {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvcRegionHeader {
    pub region_id: XvcRegionId,
    pub key_id: XvcKeyId,
    pub flags: XvcRegionFlags,
    pub first_segment_index: u32,
    pub description: [u16; 0x20], // UTF-16
    pub offset: u64,
    pub length: u64,
    pub hash: u64,
}

impl From<raw::XvcRegionHeader> for XvcRegionHeader {
    fn from(value: raw::XvcRegionHeader) -> Self {
        Self {
            region_id: value.region_id.get().into(),
            key_id: XvcKeyId::new(value.key_id.get()),
            flags: XvcRegionFlags::from_bits_retain(value.flags.get()),
            first_segment_index: value.first_segment_index.get(),
            description: value.description.map(|n| n.get()),
            offset: value.offset.get(),
            length: value.length.get(),
            hash: value.hash.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvcRegionPresenceInfo {
    pub flags: XvcRegionPresenceInfoFlags,
    pub discnum: u8,
}

impl From<raw::XvcRegionPresenceInfo> for XvcRegionPresenceInfo {
    fn from(value: raw::XvcRegionPresenceInfo) -> Self {
        Self {
            flags: XvcRegionPresenceInfoFlags::from_bits_retain(value.0),
            discnum: value.0 >> 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdUserDataHeader {
    pub length: u32,
    pub version: u32,
    pub t: u32,
}

impl From<raw::XvdUserDataHeader> for XvdUserDataHeader {
    fn from(value: raw::XvdUserDataHeader) -> Self {
        Self {
            length: value.length.get(),
            version: value.version.get(),
            t: value.t.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdUserDataPackageFilesHeader {
    pub version: u32,
    pub package_full_name: [u16; 260], // UTF-16
    pub file_count: u32,
}

impl From<raw::XvdUserDataPackageFilesHeader> for XvdUserDataPackageFilesHeader {
    fn from(value: raw::XvdUserDataPackageFilesHeader) -> Self {
        Self {
            version: value.version.get(),
            package_full_name: value.package_full_name.map(|n| n.get()),
            file_count: value.file_count.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdUserDataPackageFileEntry {
    pub file_path: [u16; 260], // UTF-16
    pub size: u32,
    pub offset: u32,
}

impl From<raw::XvdUserDataPackageFileEntry> for XvdUserDataPackageFileEntry {
    fn from(value: raw::XvdUserDataPackageFileEntry) -> Self {
        Self {
            file_path: value.file_path.map(|n| n.get()),
            size: value.size.get(),
            offset: value.offset.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdSegmentMetadataHeader {
    pub version0: u32,
    pub version1: u32,
    pub header_length: u32,
    pub segment_count: u32,
    pub file_paths_length: u32,
    pub pduid: Uuid,
}

impl XvdSegmentMetadataHeader {
    const MAGIC: [u8; 4] = *b" PFX";
}

#[derive(thiserror::Error, Debug)]
pub enum XvdSegmentMetadataHeaderParseError {
    #[error(r#"invalid magic: expected "XFP ", got {0:?}"#)]
    InvalidMagic([u8; 4]),
}

impl TryFrom<raw::XvdSegmentMetadataHeader> for XvdSegmentMetadataHeader {
    type Error = XvdSegmentMetadataHeaderParseError;

    fn try_from(value: raw::XvdSegmentMetadataHeader) -> Result<Self, Self::Error> {
        if value.magic != Self::MAGIC {
            return Err(XvdSegmentMetadataHeaderParseError::InvalidMagic(
                value.magic,
            ));
        }

        Ok(Self {
            version0: value.version0.get(),
            version1: value.version1.get(),
            header_length: value.header_length.get(),
            segment_count: value.segment_count.get(),
            file_paths_length: value.file_paths_length.get(),
            pduid: Uuid::from_bytes_le(value.pduid),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdSegmentMetadataSegment {
    pub flags: XvdSegmentMetadataSegmentFlags,
    pub path_length: u16,
    pub path_offset: u32,
    pub filesize: u64,
}

impl From<raw::XvdSegmentMetadataSegment> for XvdSegmentMetadataSegment {
    fn from(value: raw::XvdSegmentMetadataSegment) -> Self {
        Self {
            flags: XvdSegmentMetadataSegmentFlags::from_bits_retain(value.flags.get()),
            path_length: value.path_length.get(),
            path_offset: value.path_offset.get(),
            filesize: value.filesize.get(),
        }
    }
}

impl XvdHeader {
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

    pub fn sector_size(&self) -> usize {
        if self.volume_flags.is_legacy_sector_size() {
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
        calculate_number_of_hash_pages(
            self.number_of_hashed_pages(),
            self.volume_flags.is_resiliency_enabled(),
        )
    }

    pub fn user_data_offset(&self, hash_tree_page_count: u64) -> u64 {
        let hash_pages_offset = if self.volume_flags.is_data_integrity_enabled() {
            page_number_to_offset(hash_tree_page_count)
        } else {
            0
        };

        hash_pages_offset + self.hash_tree_offset()
    }

    pub fn xvc_info_offset(&self, hash_tree_page_count: u64) -> u64 {
        page_number_to_offset(self.user_data_page_count())
            + self.user_data_offset(hash_tree_page_count)
    }
}
