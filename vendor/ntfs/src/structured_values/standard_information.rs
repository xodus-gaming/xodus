// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use binrw::io::{Cursor, Read, Seek};
use binrw::{BinRead, BinReaderExt};

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::structured_values::{
    NtfsFileAttributeFlags, NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::time::NtfsTime;
use crate::types::NtfsPosition;

/// Size of all [`StandardInformationData`] fields plus some reserved bytes.
const STANDARD_INFORMATION_SIZE_NTFS1: usize = 48;

/// Size of all [`StandardInformationData`] plus [`StandardInformationDataNtfs3`] fields.
const STANDARD_INFORMATION_SIZE_NTFS3: usize = 72;

#[derive(BinRead, Clone, Debug)]
struct StandardInformationDataNtfs1 {
    creation_time: NtfsTime,
    modification_time: NtfsTime,
    mft_record_modification_time: NtfsTime,
    access_time: NtfsTime,
    file_attributes: u32,
}

#[derive(BinRead, Clone, Debug)]
struct StandardInformationDataNtfs3 {
    maximum_versions: u32,
    version: u32,
    class_id: u32,
    owner_id: u32,
    security_id: u32,
    quota_charged: u64,
    usn: u64,
}

/// Structure of a $STANDARD_INFORMATION attribute.
///
/// Among other things, this is the place where the file times and "File Attributes"
/// (Read-Only, Hidden, System, Archive, etc.) are stored.
///
/// A $STANDARD_INFORMATION attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/standard_information.html>
#[derive(Clone, Debug)]
pub struct NtfsStandardInformation {
    ntfs1_data: StandardInformationDataNtfs1,
    ntfs3_data: Option<StandardInformationDataNtfs3>,
}

impl NtfsStandardInformation {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read + Seek,
    {
        if value_length < STANDARD_INFORMATION_SIZE_NTFS1 as u64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::StandardInformation,
                expected: STANDARD_INFORMATION_SIZE_NTFS1 as u64,
                actual: value_length,
            });
        }

        let ntfs1_data = r.read_le::<StandardInformationDataNtfs1>()?;

        let mut ntfs3_data = None;
        if value_length >= STANDARD_INFORMATION_SIZE_NTFS3 as u64 {
            ntfs3_data = Some(r.read_le::<StandardInformationDataNtfs3>()?);
        }

        Ok(Self {
            ntfs1_data,
            ntfs3_data,
        })
    }

    /// Returns the time this file was last accessed.
    pub fn access_time(&self) -> NtfsTime {
        self.ntfs1_data.access_time
    }

    /// Returns the Class ID of the file, if stored via NTFS 3.x file information.
    pub fn class_id(&self) -> Option<u32> {
        self.ntfs3_data.as_ref().map(|x| x.class_id)
    }

    /// Returns the time this file was created.
    pub fn creation_time(&self) -> NtfsTime {
        self.ntfs1_data.creation_time
    }

    /// Returns flags that a user can set for a file (Read-Only, Hidden, System, Archive, etc.).
    /// Commonly called "File Attributes" in Windows Explorer.
    pub fn file_attributes(&self) -> NtfsFileAttributeFlags {
        NtfsFileAttributeFlags::from_bits_truncate(self.ntfs1_data.file_attributes)
    }

    /// Returns the maximum allowed versions for this file, if stored via NTFS 3.x file information.
    ///
    /// A value of zero means that versioning is disabled for this file.
    pub fn maximum_versions(&self) -> Option<u32> {
        self.ntfs3_data.as_ref().map(|x| x.maximum_versions)
    }

    /// Returns the time the MFT record of this file was last modified.
    pub fn mft_record_modification_time(&self) -> NtfsTime {
        self.ntfs1_data.mft_record_modification_time
    }

    /// Returns the time this file was last modified.
    pub fn modification_time(&self) -> NtfsTime {
        self.ntfs1_data.modification_time
    }

    /// Returns the Owner ID of the file, if stored via NTFS 3.x file information.
    pub fn owner_id(&self) -> Option<u32> {
        self.ntfs3_data.as_ref().map(|x| x.owner_id)
    }

    /// Returns the quota charged by this file, if stored via NTFS 3.x file information.
    pub fn quota_charged(&self) -> Option<u64> {
        self.ntfs3_data.as_ref().map(|x| x.quota_charged)
    }

    /// Returns the Security ID of the file, if stored via NTFS 3.x file information.
    pub fn security_id(&self) -> Option<u32> {
        self.ntfs3_data.as_ref().map(|x| x.security_id)
    }

    /// Returns the Update Sequence Number (USN) of the file, if stored via NTFS 3.x file information.
    pub fn usn(&self) -> Option<u64> {
        self.ntfs3_data.as_ref().map(|x| x.usn)
    }

    /// Returns the version of the file, if stored via NTFS 3.x file information.
    ///
    /// This will be zero if versioning is disabled for this file.
    pub fn version(&self) -> Option<u32> {
        self.ntfs3_data.as_ref().map(|x| x.version)
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsStandardInformation {
    const TY: NtfsAttributeType = NtfsAttributeType::StandardInformation;

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

impl<'n, 'f> NtfsStructuredValueFromResidentAttributeValue<'n, 'f> for NtfsStandardInformation {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = Cursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::KnownNtfsFileRecordNumber;
    use crate::ntfs::Ntfs;

    #[test]
    fn test_standard_information() {
        let mut testfs1 = crate::helpers::tests::testfs1();
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();
        let mut mft_attributes = mft.attributes_raw();

        // Check the StandardInformation attribute of the MFT.
        let attribute = mft_attributes.next().unwrap().unwrap();
        assert_eq!(
            attribute.ty().unwrap(),
            NtfsAttributeType::StandardInformation,
        );
        assert_eq!(attribute.attribute_length(), 96);
        assert!(attribute.is_resident());
        assert_eq!(attribute.name_length(), 0);
        assert_eq!(attribute.value_length(), 72);

        // Try to read the actual information.
        let _standard_info = attribute
            .resident_structured_value::<NtfsStandardInformation>()
            .unwrap();

        // There are no reliable values to check here, so that's it.
    }
}
