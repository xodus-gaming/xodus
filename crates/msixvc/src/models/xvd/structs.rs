use super::layout::MAX_HASHED_PAGES;
use super::{
    WriteablePolicyFlags, XVD_HEADER_INCL_SIGNATURE_SIZE, XvcInfoFlags, XvcRegionFlags,
    XvcRegionId, XvcRegionPresenceInfoFlags, XvdContentType, XvdSegmentMetadataSegmentFlags,
    XvdType, XvdVolumeFlags,
};
use crate::layout::{Bytes, LEGACY_SECTOR_SIZE, PAGE_SIZE, Pages, SECTOR_SIZE};
use crate::math::calculate_number_of_hash_pages;

use msixvc_common::parse::byteorder::little_endian::*;
use msixvc_common::parse::structs::{Filetime, Version};
use msixvc_common::parse::{BinaryParse, BinaryTryParse, BytesReader, EmptyReader};

use chrono::DateTime;
use num_enum::TryFromPrimitiveError;
use typenum::{
    Diff, Sum, U1 as T1, U2 as T2, U12 as T12, U16 as T16, U24 as T24, U100 as T100, U128 as T128,
    U392 as T392, U528 as T528, U600 as T600, U852 as T852, U2048 as T2048, U4096 as T4096,
};
use uuid::Uuid;

use std::collections::HashMap;
use std::range::Range;

type T2900 = Sum<T2048, T852>;
type T3496 = Diff<T4096, T600>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdHeader {
    pub signature: [u8; 0x200],
    pub volume_flags: XvdVolumeFlags,
    pub format_version: u32,
    pub file_time_created: DateTime<chrono::Utc>,
    pub drive_size: Bytes,
    pub vduid: Uuid,
    pub uduid: Uuid,
    pub top_hash_block_hash: [u8; 0x20],
    pub original_xvc_data_hash: [u8; 0x20],
    pub xvd_type: XvdType,
    pub xvd_content_type: XvdContentType,
    pub embedded_xvd_length: Bytes,
    pub user_data_length: Bytes,
    pub xvc_data_length: Bytes,
    pub dynamic_header_length: Bytes,
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
    pub mutable_page_count: Pages,
    pub sequence_number: i64,
    pub required_system_version: Version,
    pub odk_keyslot_id: u32,
    pub resilient_data_offset: u64,
    pub resilient_data_length: u32,
}

impl XvdHeader {
    const MAGIC: &[u8; 8] = b"msft-xvd";
    const DRIVE_SIZE_RANGE: Range<Bytes> = Range {
        // The drive must be at least one page long.
        start: Bytes(1),
        end: MAX_HASHED_PAGES.to_bytes(),
    };
}

#[derive(thiserror::Error, Debug)]
pub enum XvdHeaderParseError {
    #[error(r#"invalid magic: expected {magic:?}, got {0:?}"#, magic = XvdHeader::MAGIC)]
    InvalidMagic([u8; 8]),

    #[error("invalid xvd type: {0}")]
    InvalidXvdType(#[from] TryFromPrimitiveError<XvdType>),

    #[error("invalid xvd content type: {0}")]
    InvalidXvdContentType(#[from] TryFromPrimitiveError<XvdContentType>),

    #[error("invalid drive size: {drive_size:?}, must be in the range {range:?}", range = XvdHeader::DRIVE_SIZE_RANGE)]
    InvalidDriveSize { drive_size: Bytes },
}

impl BinaryTryParse for XvdHeader {
    type Output = Self;
    type Size = T4096;
    type Error = XvdHeaderParseError;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self, EmptyReader<'a>), Self::Error> {
        let (signature, r) = r.array::<0x200>();

        let r = r.magic(Self::MAGIC).map_err(Self::Error::InvalidMagic)?;

        let (volume_flags, r) = r.read::<XvdVolumeFlags>();
        let (format_version, r) = r.read::<U32>();
        let (file_time_created, r) = r.read::<Filetime>();
        let (drive_size, r) = r.read::<U64>();

        let drive_size = Bytes(drive_size);
        if !Self::DRIVE_SIZE_RANGE.contains(&drive_size) {
            return Err(Self::Error::InvalidDriveSize { drive_size });
        }

        let (vduid, r) = r.read::<Uuid>();
        let (uduid, r) = r.read::<Uuid>();

        let (top_hash_block_hash, r) = r.array::<0x20>();
        let (original_xvc_data_hash, r) = r.array::<0x20>();

        let (xvd_type, r) = r.try_read::<XvdType>()?;
        let (xvd_content_type, r) = r.try_read::<XvdContentType>()?;

        let (embedded_xvd_length, r) = r.read::<U32>();
        let (user_data_length, r) = r.read::<U32>();
        let (xvc_data_length, r) = r.read::<U32>();
        let (dynamic_header_length, r) = r.read::<U32>();
        let (block_size, r) = r.read::<U32>();

        let (ext_entries, r) = r.read::<[XvdExtEntry; 4]>();
        let (capabilities, r) = r.read::<[U16; 8]>();

        let (pe_catalog_hash, r) = r.array::<0x20>();
        let (embedded_xvd_pduid, r) = r.read::<Uuid>();
        let (_reserved13c, r) = r.array::<0x10>();
        let (key_material, r) = r.array::<0x20>();
        let (user_data_hash, r) = r.array::<0x20>();
        let (sandbox_id, r) = r.array::<0x10>();
        let (product_id, r) = r.read::<Uuid>();
        let (pduid, r) = r.read::<Uuid>();
        let (package_version, r) = r.read::<Version>();

        let (pe_catalog_caps, r) = r.read::<[U16; 0x10]>();
        let (pe_catalogs, r) = r.array::<0x80>();

        let (writeable_expiration_date, r) = r.read::<U32>();
        let (writeable_policy_flags, r) = r.read::<WriteablePolicyFlags>();

        let (persistent_local_storage_size, r) = r.read::<U32>();
        let (mutable_page_count, r) = r.read::<u8>();

        let (_unknown271, r) = r.read::<u8>();
        let (_unknown272, r) = r.array::<0x10>();
        let (_reserved282, r) = r.array::<0xA>();

        let (sequence_number, r) = r.read::<I64>();
        let (required_system_version, r) = r.read::<Version>();
        let (odk_keyslot_id, r) = r.read::<U32>();
        let (_reservedd2a0, r) = r.advance::<T2900>();
        let (resilient_data_offset, r) = r.read::<U64>();
        let (resilient_data_length, r) = r.read::<U32>();

        Ok((
            Self {
                signature,
                volume_flags,
                format_version,
                file_time_created,
                drive_size,
                vduid,
                uduid,
                top_hash_block_hash,
                original_xvc_data_hash,
                xvd_type,
                xvd_content_type,
                embedded_xvd_length: Bytes(embedded_xvd_length as u64),
                user_data_length: Bytes(user_data_length as u64),
                xvc_data_length: Bytes(xvc_data_length as u64),
                dynamic_header_length: Bytes(dynamic_header_length as u64),
                block_size,
                ext_entries,
                capabilities,
                pe_catalog_hash,
                embedded_xvd_pduid,
                key_material,
                user_data_hash,
                sandbox_id,
                product_id,
                pduid,
                package_version,
                pe_catalog_caps,
                pe_catalogs,
                writeable_expiration_date,
                writeable_policy_flags,
                persistent_local_storage_size,
                mutable_page_count: Pages(mutable_page_count as u32),
                sequence_number,
                required_system_version,
                odk_keyslot_id,
                resilient_data_offset,
                resilient_data_length,
            },
            r,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XvdExtEntry {
    pub code: u32,
    pub length: u32,
    pub offset: u64,
    pub data_length: u32,
}

impl BinaryParse for XvdExtEntry {
    type Output = Self;
    type Size = T24;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self, EmptyReader<'a>) {
        let (code, r) = r.read::<U32>();
        let (length, r) = r.read::<U32>();
        let (offset, r) = r.read::<U64>();
        let (data_length, r) = r.read::<U32>();
        let (_reserved, r) = r.read::<U32>();

        (
            Self {
                code,
                length,
                offset,
                data_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdHashEntry {
    /// Truncated SHA-256 hash
    pub block_hash: [u8; 0x14],
    /// Appears to be a counter with an offset applied
    pub unit: u32,
}

impl BinaryParse for XvdHashEntry {
    type Output = Self;
    type Size = T24;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (block_hash, r) = r.array();
        let (unit, r) = r.read::<U32>();

        (Self { block_hash, unit }, r)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvcInfo {
    pub content_id: Uuid,
    pub xvc_encryption_key_id: HashMap<u8, Uuid>,
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

impl BinaryParse for XvcInfo {
    type Output = Self;
    type Size = T3496;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (content_id, r) = r.read::<Uuid>();
        let (xvc_encryption_key_id, r) = r.read::<[Uuid; 0xC0]>();
        let xvc_encryption_key_id: HashMap<u8, Uuid> = xvc_encryption_key_id
            .into_iter()
            .enumerate()
            .map(|(i, id)| (i as u8, id))
            .filter(|(_i, id)| !id.is_nil())
            .collect();

        let (description, r) = r.array::<0x100>();

        let (version, r) = r.read::<U32>();
        let (region_count, r) = r.read::<U32>();

        let (flags, r) = r.read::<XvcInfoFlags>();

        let (_paddingd1c, r) = r.read::<U16>();
        let (key_count, r) = r.read::<U16>();

        let (_unknownd20, r) = r.read::<U32>();
        let (initial_play_region_id, r) = r.read::<XvcRegionId>();

        let (initial_play_offset, r) = r.read::<U64>();
        let (file_time_created, r) = r.read::<Filetime>();

        let (preview_region_id, r) = r.read::<XvcRegionId>();

        let (update_segment_count, r) = r.read::<U32>();
        let (preview_offset, r) = r.read::<U64>();

        let (_unused_space, r) = r.read::<U64>();
        let (region_specifier_count, r) = r.read::<U32>();

        let (_reserved, r) = r.array::<0x54>();

        (
            Self {
                content_id,
                xvc_encryption_key_id,
                description,
                version,
                region_count,
                flags,
                key_count,
                initial_play_region_id,
                initial_play_offset,
                file_time_created,
                preview_region_id,
                update_segment_count,
                preview_offset,
                region_specifier_count,
            },
            r,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdUpdateSegment {
    pub page_num: u32,
    pub hash: u64,
}

impl BinaryParse for XvdUpdateSegment {
    type Output = Self;
    type Size = T12;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (page_num, r) = r.read::<U32>();
        let (hash, r) = r.read::<U64>();

        (Self { page_num, hash }, r)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvcRegionSpecifier {
    pub region_id: XvcRegionId,
    pub key: [u16; 0x40],   // UTF-16
    pub value: [u16; 0x80], // UTF-16
}

impl BinaryParse for XvcRegionSpecifier {
    type Output = Self;
    type Size = T392;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (region_id, r) = r.read::<XvcRegionId>();
        let (_padding4, r) = r.read::<U32>();

        let (key, r) = r.read::<[U16; 0x40]>();
        let (value, r) = r.read::<[U16; 0x80]>();

        (
            Self {
                region_id,
                key,
                value,
            },
            r,
        )
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

impl BinaryParse for XvcKeyId {
    type Output = Self;
    type Size = T2;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (key_id, r) = r.read::<U16>();
        (Self::new(key_id), r)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvcRegionHeader {
    pub region_id: XvcRegionId,
    pub key_id: XvcKeyId,
    pub flags: XvcRegionFlags,
    pub first_segment_index: u32,
    pub description: [u16; 0x20], // UTF-16
    pub offset: Pages,
    pub length: Pages,
    pub hash: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum XvcRegionHeaderParseError {
    #[error("invalid offset {0}: must be a multiple of page size ({PAGE_SIZE})")]
    InvalidOffset(u64),

    #[error("invalid length {0}: must be a multiple of page size ({PAGE_SIZE})")]
    InvalidLength(u64),
}

impl BinaryTryParse for XvcRegionHeader {
    type Output = Self;
    type Size = T128;
    type Error = XvcRegionHeaderParseError;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        let (region_id, r) = r.read::<XvcRegionId>();

        let (key_id, r) = r.read::<XvcKeyId>();
        let (_padding6, r) = r.read::<U16>();

        let (flags, r) = r.read::<XvcRegionFlags>();

        let (first_segment_index, r) = r.read::<U32>();
        let (description, r) = r.read::<[U16; 0x20]>();

        let (offset, r) = r.read::<U64>();
        let (length, r) = r.read::<U64>();

        let offset = Bytes(offset)
            .to_page_index_aligned()
            .ok_or(Self::Error::InvalidOffset(offset))?;

        let length = Bytes(length)
            .to_page_index_aligned()
            .ok_or(Self::Error::InvalidLength(length))?;

        let (hash, r) = r.read::<U64>();

        let (_unknown_68, r) = r.read::<U64>();
        let (_unknown_68, r) = r.read::<U64>();
        let (_unknown_78, r) = r.read::<U64>();

        Ok((
            Self {
                region_id,
                key_id,
                flags,
                first_segment_index,
                description,
                offset,
                length,
                hash,
            },
            r,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvcRegionPresenceInfo {
    pub flags: XvcRegionPresenceInfoFlags,
    pub discnum: u8,
}

impl BinaryParse for XvcRegionPresenceInfo {
    type Output = Self;
    type Size = T1;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (byte, r) = r.read::<u8>();

        (
            Self {
                flags: XvcRegionPresenceInfoFlags::from_array(&[byte].into()),
                discnum: byte >> 4,
            },
            r,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdUserDataHeader {
    pub length: u32,
    pub version: u32,
    pub t: u32,
}

impl BinaryParse for XvdUserDataHeader {
    type Output = Self;
    type Size = T16;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (length, r) = r.read::<U32>();
        let (version, r) = r.read::<U32>();
        let (t, r) = r.read::<U32>();
        let (_unknown, r) = r.read::<U32>();

        (Self { length, version, t }, r)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdUserDataPackageFilesHeader {
    pub version: u32,
    pub package_full_name: [u16; 260], // UTF-16
    pub file_count: u32,
}

impl BinaryParse for XvdUserDataPackageFilesHeader {
    type Output = Self;
    type Size = T528;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (version, r) = r.read::<U32>();
        let (package_full_name, r) = r.read::<[U16; 260]>();
        let (file_count, r) = r.read::<U32>();

        (
            Self {
                version,
                package_full_name,
                file_count,
            },
            r,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdUserDataPackageFileEntry {
    pub file_path: [u16; 260], // UTF-16
    pub size: u32,
    pub offset: u32,
}

impl BinaryParse for XvdUserDataPackageFileEntry {
    type Output = Self;
    type Size = T528;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (file_path, r) = r.read::<[U16; 260]>();
        let (size, r) = r.read::<U32>();
        let (offset, r) = r.read::<U32>();

        (
            Self {
                file_path,
                size,
                offset,
            },
            r,
        )
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
    const MAGIC: &[u8; 4] = b" PFX";
}

#[derive(thiserror::Error, Debug)]
pub enum XvdSegmentMetadataHeaderParseError {
    #[error(r#"invalid magic: expected {magic:?}, got {0:?}"#, magic = XvdSegmentMetadataHeader::MAGIC)]
    InvalidMagic([u8; 4]),
}

impl BinaryTryParse for XvdSegmentMetadataHeader {
    type Output = Self;
    type Size = T100;
    type Error = XvdSegmentMetadataHeaderParseError;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        let r = r.magic(Self::MAGIC).map_err(Self::Error::InvalidMagic)?;

        let (version0, r) = r.read::<U32>();
        let (version1, r) = r.read::<U32>();
        let (header_length, r) = r.read::<U32>();
        let (segment_count, r) = r.read::<U32>();
        let (file_paths_length, r) = r.read::<U32>();

        let (pduid, r) = r.read::<Uuid>();

        let (_unknown, r) = r.array::<0x3c>();

        Ok((
            Self {
                version0,
                version1,
                header_length,
                segment_count,
                file_paths_length,
                pduid,
            },
            r,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdSegmentMetadataSegment {
    pub flags: XvdSegmentMetadataSegmentFlags,
    pub path_length: u16,
    pub path_offset: u32,
    pub filesize: u64,
}

impl BinaryParse for XvdSegmentMetadataSegment {
    type Output = Self;
    type Size = T16;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (flags, r) = r.read::<XvdSegmentMetadataSegmentFlags>();
        let (path_length, r) = r.read::<U16>();
        let (path_offset, r) = r.read::<U32>();
        let (filesize, r) = r.read::<U64>();

        (
            Self {
                flags,
                path_length,
                path_offset,
                filesize,
            },
            r,
        )
    }
}

impl XvdHeader {
    pub fn mutable_data_length(&self) -> Bytes {
        self.mutable_page_count.to_bytes()
    }

    pub fn user_data_page_count(&self) -> Pages {
        self.user_data_length.to_page_count()
    }

    pub fn xvc_data_page_count(&self) -> Pages {
        self.xvc_data_length.to_page_count()
    }

    pub fn embedded_xvd_page_count(&self) -> Pages {
        self.embedded_xvd_length.to_page_count()
    }

    pub fn dynamic_header_page_count(&self) -> Pages {
        self.dynamic_header_length.to_page_count()
    }

    pub fn drive_page_count(&self) -> Pages {
        self.drive_size.to_page_count()
    }

    pub fn number_of_hashed_pages(&self) -> Pages {
        self.drive_page_count()
            + self.user_data_page_count()
            + self.xvc_data_page_count()
            + self.dynamic_header_page_count()
    }

    pub fn number_of_metadata_pages(&self) -> Pages {
        self.user_data_page_count() + self.xvc_data_page_count() + self.dynamic_header_page_count()
    }

    pub fn sector_size(&self) -> usize {
        if self.volume_flags.is_legacy_sector_size() {
            LEGACY_SECTOR_SIZE
        } else {
            SECTOR_SIZE
        }
    }

    pub fn mdu_offset(&self) -> Bytes {
        self.embedded_xvd_page_count().to_bytes() + Bytes(XVD_HEADER_INCL_SIGNATURE_SIZE)
    }

    pub fn hash_tree_offset(&self) -> Bytes {
        self.mutable_data_length() + self.mdu_offset()
    }

    pub fn hash_tree_info(&self) -> (u64, Pages) {
        let (levels, pages) = calculate_number_of_hash_pages(
            self.number_of_hashed_pages().0,
            self.volume_flags.is_resiliency_enabled(),
        );

        (levels, Pages(pages))
    }

    pub fn user_data_offset(&self, hash_tree_page_count: Pages) -> Bytes {
        let hash_pages_offset = if self.volume_flags.is_data_integrity_enabled() {
            hash_tree_page_count.to_bytes()
        } else {
            Bytes(0)
        };

        hash_pages_offset + self.hash_tree_offset()
    }

    pub fn xvc_info_offset(&self, hash_tree_page_count: Pages) -> Bytes {
        self.user_data_page_count().to_bytes() + self.user_data_offset(hash_tree_page_count)
    }
}
