// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use binrw::io::{Cursor, Read, Seek};
use binrw::BinReaderExt;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::guid::{NtfsGuid, GUID_SIZE};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Structure of an $OBJECT_ID attribute.
///
/// This optional attribute contains a globally unique identifier of the file.
///
/// An $OBJECT_ID attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/object_id.html>
#[derive(Clone, Debug)]
pub struct NtfsObjectId {
    object_id: NtfsGuid,
    birth_volume_id: Option<NtfsGuid>,
    birth_object_id: Option<NtfsGuid>,
    domain_id: Option<NtfsGuid>,
}

impl NtfsObjectId {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read + Seek,
    {
        if value_length < GUID_SIZE as u64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::ObjectId,
                expected: GUID_SIZE as u64,
                actual: value_length,
            });
        }

        let object_id = r.read_le::<NtfsGuid>()?;

        let mut birth_volume_id = None;
        if value_length >= 2 * GUID_SIZE as u64 {
            birth_volume_id = Some(r.read_le::<NtfsGuid>()?);
        }

        let mut birth_object_id = None;
        if value_length >= 3 * GUID_SIZE as u64 {
            birth_object_id = Some(r.read_le::<NtfsGuid>()?);
        }

        let mut domain_id = None;
        if value_length >= 4 * GUID_SIZE as u64 {
            domain_id = Some(r.read_le::<NtfsGuid>()?);
        }

        Ok(Self {
            object_id,
            birth_volume_id,
            birth_object_id,
            domain_id,
        })
    }

    /// Returns the (optional) first Object ID that has ever been assigned to this file.
    pub fn birth_object_id(&self) -> Option<&NtfsGuid> {
        self.birth_object_id.as_ref()
    }

    /// Returns the (optional) Object ID of the $Volume file of the partition where this file was created.
    pub fn birth_volume_id(&self) -> Option<&NtfsGuid> {
        self.birth_volume_id.as_ref()
    }

    /// Returns the (optional) Domain ID of this file.
    pub fn domain_id(&self) -> Option<&NtfsGuid> {
        self.domain_id.as_ref()
    }

    /// Returns the Object ID, a globally unique identifier of the file.
    pub fn object_id(&self) -> &NtfsGuid {
        &self.object_id
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsObjectId {
    const TY: NtfsAttributeType = NtfsAttributeType::ObjectId;

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

impl<'n, 'f> NtfsStructuredValueFromResidentAttributeValue<'n, 'f> for NtfsObjectId {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = Cursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}
