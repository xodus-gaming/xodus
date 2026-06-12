// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem;

use arrayvec::ArrayVec;
use binrw::io::{Cursor, Read, Seek};
use nt_string::u16strle::U16StrLe;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// The largest VolumeName attribute has a name containing 128 UTF-16 code points (256 bytes).
const VOLUME_NAME_MAX_SIZE: usize = 128 * mem::size_of::<u16>();

/// Structure of a $VOLUME_NAME attribute.
///
/// This attribute is only used by the top-level $Volume file and contains the user-defined name of this filesystem.
/// You can easily access it via [`Ntfs::volume_name`].
///
/// A $VOLUME_NAME attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/volume_name.html>
///
/// [`Ntfs::volume_name`]: crate::Ntfs::volume_name
#[derive(Clone, Debug)]
pub struct NtfsVolumeName {
    name: ArrayVec<u8, VOLUME_NAME_MAX_SIZE>,
}

impl NtfsVolumeName {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read + Seek,
    {
        if value_length > VOLUME_NAME_MAX_SIZE as u64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::VolumeName,
                expected: VOLUME_NAME_MAX_SIZE as u64,
                actual: value_length,
            });
        }

        let value_length = value_length as usize;

        let mut name = ArrayVec::from([0u8; VOLUME_NAME_MAX_SIZE]);
        r.read_exact(&mut name[..value_length])?;
        name.truncate(value_length);

        Ok(Self { name })
    }

    /// Gets the volume name and returns it wrapped in a [`U16StrLe`].
    pub fn name(&self) -> U16StrLe {
        U16StrLe(&self.name)
    }

    /// Returns the volume name length, in bytes.
    ///
    /// A volume name has a maximum length of 128 UTF-16 code points (256 bytes).
    pub fn name_length(&self) -> usize {
        self.name.len()
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsVolumeName {
    const TY: NtfsAttributeType = NtfsAttributeType::VolumeName;

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

impl<'n, 'f> NtfsStructuredValueFromResidentAttributeValue<'n, 'f> for NtfsVolumeName {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = Cursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}
