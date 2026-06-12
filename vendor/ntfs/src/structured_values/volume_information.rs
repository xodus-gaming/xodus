// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use binrw::io::{Cursor, Read, Seek};
use binrw::{BinRead, BinReaderExt};
use bitflags::bitflags;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Size of all [`VolumeInformationData`] fields.
const VOLUME_INFORMATION_SIZE: usize = 12;

#[derive(BinRead, Clone, Debug)]
struct VolumeInformationData {
    _reserved: u64,
    major_version: u8,
    minor_version: u8,
    flags: u16,
}

bitflags! {
    /// Flags returned by [`NtfsVolumeInformation::flags`].
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsVolumeFlags: u16 {
        /// The volume needs to be checked by `chkdsk`.
        const IS_DIRTY = 0x0001;
        const RESIZE_LOG_FILE = 0x0002;
        const UPGRADE_ON_MOUNT = 0x0004;
        const MOUNTED_ON_NT4 = 0x0008;
        const DELETE_USN_UNDERWAY = 0x0010;
        const REPAIR_OBJECT_ID = 0x0020;
        const CHKDSK_UNDERWAY = 0x4000;
        const MODIFIED_BY_CHKDSK = 0x8000;
    }
}

impl fmt::Display for NtfsVolumeFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Structure of a $VOLUME_INFORMATION attribute.
///
/// This attribute is only used by the top-level $Volume file and contains general information about the filesystem.
/// You can easily access it via [`Ntfs::volume_info`].
///
/// A $VOLUME_INFORMATION attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/volume_information.html>
///
/// [`Ntfs::volume_info`]: crate::Ntfs::volume_info
#[derive(Clone, Debug)]
pub struct NtfsVolumeInformation {
    info: VolumeInformationData,
}

impl NtfsVolumeInformation {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read + Seek,
    {
        if value_length < VOLUME_INFORMATION_SIZE as u64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::StandardInformation,
                expected: VOLUME_INFORMATION_SIZE as u64,
                actual: value_length,
            });
        }

        let info = r.read_le::<VolumeInformationData>()?;

        Ok(Self { info })
    }

    /// Returns flags set for this NTFS filesystem/volume as specified by [`NtfsVolumeFlags`].
    pub fn flags(&self) -> NtfsVolumeFlags {
        NtfsVolumeFlags::from_bits_truncate(self.info.flags)
    }

    /// Returns the major NTFS version of this filesystem (e.g. `3` for NTFS 3.1).
    pub fn major_version(&self) -> u8 {
        self.info.major_version
    }

    /// Returns the minor NTFS version of this filesystem (e.g. `1` for NTFS 3.1).
    pub fn minor_version(&self) -> u8 {
        self.info.minor_version
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsVolumeInformation {
    const TY: NtfsAttributeType = NtfsAttributeType::VolumeInformation;

    fn from_attribute_value<T>(fs: &mut T, value: NtfsAttributeValue<'n, 'f>) -> Result<Self>
    where
        T: Read + Seek,
    {
        let position = value.data_position();
        let value_length = value.len();

        let mut value_attached = value.attach(fs);
        Self::new(&mut value_attached, position, value_length)
    }
}

impl<'n, 'f> NtfsStructuredValueFromResidentAttributeValue<'n, 'f> for NtfsVolumeInformation {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = Cursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}
