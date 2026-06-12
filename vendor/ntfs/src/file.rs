// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cmp::Ordering;
use core::fmt;
use core::num::NonZeroU64;

use alloc::vec;
use binrw::io::{Read, Seek, SeekFrom};
use bitflags::bitflags;
use byteorder::{ByteOrder, LittleEndian};
use memoffset::offset_of;
use nt_string::u16strle::U16StrLe;

use crate::attribute::{
    NtfsAttribute, NtfsAttributeItem, NtfsAttributeType, NtfsAttributes, NtfsAttributesRaw,
};
use crate::error::{NtfsError, Result};
use crate::file_reference::NtfsFileReference;
use crate::index::NtfsIndex;
use crate::indexes::NtfsFileNameIndex;
use crate::ntfs::Ntfs;
use crate::record::{Record, RecordHeader};
use crate::structured_values::{
    NtfsFileName, NtfsFileNamespace, NtfsIndexRoot, NtfsStandardInformation,
    NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;
use crate::upcase_table::UpcaseOrd;

/// A list of standardized NTFS File Record Numbers.
///
/// Most of these files store internal NTFS housekeeping information.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/index.html>
#[repr(u64)]
pub enum KnownNtfsFileRecordNumber {
    /// A back-reference to the Master File Table (MFT).
    ///
    /// Leads to the same File Record as [`Ntfs::mft_position`].
    MFT = 0,
    /// A mirror copy of the Master File Table (MFT).
    MFTMirr = 1,
    /// The journaling logfile.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html>
    LogFile = 2,
    /// File containing basic filesystem information and the user-defined volume name.
    ///
    /// You can easily access that information via [`Ntfs::volume_info`] and [`Ntfs::volume_name`].
    Volume = 3,
    /// File defining all attributes supported by this NTFS filesystem.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/attrdef.html>
    AttrDef = 4,
    /// The root directory of the filesystem.
    ///
    /// You can easily access it via [`Ntfs::root_directory`].
    RootDirectory = 5,
    /// Map of used clusters.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/bitmap.html>
    Bitmap = 6,
    /// A back-reference to the boot sector of the filesystem.
    Boot = 7,
    /// A file consisting of Data Runs to bad cluster ranges.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/badclus.html>
    BadClus = 8,
    /// A list of all Security Descriptors used by this filesystem.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/secure.html>
    Secure = 9,
    /// The $UpCase file that contains a table of all uppercase characters for the
    /// 65536 characters of the Unicode Basic Multilingual Plane.
    ///
    /// NTFS uses this table to perform case-insensitive comparisons.
    UpCase = 10,
    /// A directory of further files containing housekeeping information.
    ///
    /// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/files/extend.html>
    Extend = 11,
}

#[repr(C, packed)]
struct FileRecordHeader {
    record_header: RecordHeader,
    sequence_number: u16,
    hard_link_count: u16,
    first_attribute_offset: u16,
    flags: u16,
    data_size: u32,
    allocated_size: u32,
    base_file_record: NtfsFileReference,
    next_attribute_instance: u16,
}

bitflags! {
    /// Flags returned by [`NtfsFile::flags`].
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsFileFlags: u16 {
        /// Record is in use.
        const IN_USE = 0x0001;
        /// Record is a directory.
        const IS_DIRECTORY = 0x0002;
    }
}

impl fmt::Display for NtfsFileFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A single NTFS File Record.
///
/// These records are denoted via a `FILE` signature on the filesystem.
///
/// NTFS uses File Records to manage all user-facing files and directories, as well as some internal files for housekeeping.
/// Every File Record consists of [`NtfsAttribute`]s, which may reference additional File Records.
/// Even the Master File Table (MFT) itself is organized as a File Record.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/file_record.html>
///
/// [`NtfsAttribute`]: crate::attribute::NtfsAttribute
#[derive(Clone, Debug)]
pub struct NtfsFile<'n> {
    ntfs: &'n Ntfs,
    record: Record,
    file_record_number: u64,
}

impl<'n> NtfsFile<'n> {
    pub(crate) fn new<T>(
        ntfs: &'n Ntfs,
        fs: &mut T,
        position: NonZeroU64,
        file_record_number: u64,
    ) -> Result<Self>
    where
        T: Read + Seek,
    {
        let mut data = vec![0; ntfs.file_record_size() as usize];
        fs.seek(SeekFrom::Start(position.get()))?;
        fs.read_exact(&mut data)?;

        let mut record = Record::new(data, position.into());
        Self::validate_signature(&record)?;
        record.fixup()?;

        let file = Self {
            ntfs,
            record,
            file_record_number,
        };
        file.validate_sizes()?;

        Ok(file)
    }

    /// Returns the allocated size of this NTFS File Record, in bytes.
    pub fn allocated_size(&self) -> u32 {
        let start = offset_of!(FileRecordHeader, allocated_size);
        LittleEndian::read_u32(&self.record.data()[start..])
    }

    /// Returns an iterator over all attributes of this file.
    ///
    /// This provides a flattened "data-centric" view of the attributes and abstracts away the filesystem details
    /// to deal with many or large attributes (Attribute Lists and connected attributes).
    /// Use [`NtfsFile::attributes_raw`] to iterate over the plain attributes on the filesystem.
    ///
    /// Due to the abstraction, the iterator returns an [`NtfsAttributeItem`] for each entry.
    ///
    /// [`NtfsAttributeItem`]: crate::NtfsAttributeItem
    pub fn attributes<'f>(&'f self) -> NtfsAttributes<'n, 'f> {
        NtfsAttributes::<'n, 'f>::new(self)
    }

    /// Returns an iterator over all top-level attributes of this file.
    ///
    /// Contrary to [`NtfsFile::attributes`], it does not traverse $ATTRIBUTE_LIST attributes, but returns
    /// them as raw attributes.
    /// Check that function if you want an iterator providing a flattened "data-centric" view over
    /// the attributes by traversing Attribute Lists automatically.
    ///
    /// The iterator returns an [`NtfsAttribute`] for each entry.
    ///
    /// [`NtfsAttribute`]: crate::NtfsAttribute
    pub fn attributes_raw<'f>(&'f self) -> NtfsAttributesRaw<'n, 'f> {
        NtfsAttributesRaw::new(self)
    }

    /// Convenience function to get a $DATA attribute of this file.
    ///
    /// As NTFS supports multiple data streams per file, you can specify the name of the $DATA attribute
    /// to look up.
    /// Passing an empty string here looks up the default unnamed $DATA attribute (commonly known as the "file data").
    /// The name is looked up case-insensitively.
    ///
    /// If you need more control over which $DATA attribute is available and picked up,
    /// you can use [`NtfsFile::attributes`] to iterate over all attributes of this file.
    ///
    /// # Panics
    ///
    /// Panics if `data_stream_name` is non-empty and [`read_upcase_table`][Ntfs::read_upcase_table] had not been
    /// called on the passed [`Ntfs`] object.
    pub fn data<'f, T>(
        &'f self,
        fs: &mut T,
        data_stream_name: &str,
    ) -> Option<Result<NtfsAttributeItem<'n, 'f>>>
    where
        T: Read + Seek,
    {
        let mut iter = self.attributes();

        let equal = if data_stream_name.is_empty() {
            // Use a simpler "comparison" that doesn't require the $UpCase table.
            |_ntfs: &Ntfs, name: &U16StrLe, _data_stream_name: &str| name.is_empty()
        } else {
            |ntfs: &Ntfs, name: &U16StrLe, data_stream_name: &str| {
                name.upcase_cmp(ntfs, &data_stream_name) == Ordering::Equal
            }
        };

        while let Some(item) = iter.next(fs) {
            let item = iter_try!(item);
            let attribute = iter_try!(item.to_attribute());

            let ty = iter_try!(attribute.ty());
            if ty != NtfsAttributeType::Data {
                continue;
            }

            let name = iter_try!(attribute.name());
            if !equal(self.ntfs, &name, data_stream_name) {
                continue;
            }

            return Some(Ok(item));
        }

        None
    }

    /// Returns the size actually used by data of this NTFS File Record, in bytes.
    ///
    /// This is less or equal than [`NtfsFile::allocated_size`].
    pub fn data_size(&self) -> u32 {
        let start = offset_of!(FileRecordHeader, data_size);
        LittleEndian::read_u32(&self.record.data()[start..])
    }

    /// Convenience function to return an [`NtfsIndex`] if this file is a directory.
    /// This structure can be used to iterate over all files of this directory or a find a specific one.
    ///
    /// Apart from any propagated error, this function may return [`NtfsError::NotADirectory`]
    /// if this [`NtfsFile`] is not a directory.
    ///
    /// If you need more control over the picked up $INDEX_ROOT and $INDEX_ALLOCATION attributes
    /// you can use [`NtfsFile::attributes`] to iterate over all attributes of this file.
    pub fn directory_index<'f, T>(
        &'f self,
        fs: &mut T,
    ) -> Result<NtfsIndex<'n, 'f, NtfsFileNameIndex>>
    where
        T: Read + Seek,
    {
        if !self.is_directory() {
            return Err(NtfsError::NotADirectory {
                position: self.position(),
            });
        }

        // A File Record may contain multiple indexes, so we have to match the name of the directory index.
        let directory_index_name = "$I30";

        // The IndexRoot attribute is always resident and has to exist for every directory.
        let index_root_item =
            self.find_attribute(fs, NtfsAttributeType::IndexRoot, Some(directory_index_name))?;
        let index_root_attribute = index_root_item.to_attribute()?;
        let index_root = index_root_attribute.resident_structured_value::<NtfsIndexRoot>()?;

        // The IndexAllocation attribute is only required for "large" indexes.
        // It is always non-resident and may even be in an Attribute List.
        let mut index_allocation_item = None;
        if index_root.is_large_index() {
            index_allocation_item = Some(self.find_attribute(
                fs,
                NtfsAttributeType::IndexAllocation,
                Some(directory_index_name),
            )?);
        }

        NtfsIndex::<NtfsFileNameIndex>::new(index_root_item, index_allocation_item)
    }

    /// Returns the NTFS File Record Number of this file.
    ///
    /// This number uniquely identifies this file and can be used to recreate this [`NtfsFile`]
    /// object via [`Ntfs::file`].
    pub fn file_record_number(&self) -> u64 {
        self.file_record_number
    }

    /// Finds an attribute of a specific type, optionally with a specific name, and returns its [`NtfsAttributeItem`].
    /// Returns [`NtfsError::AttributeNotFound`] if no such attribute could be found.
    ///
    /// This function also traverses Attribute Lists to find the attribute.
    fn find_attribute<'f, T>(
        &'f self,
        fs: &mut T,
        ty: NtfsAttributeType,
        match_name: Option<&str>,
    ) -> Result<NtfsAttributeItem<'n, 'f>>
    where
        T: Read + Seek,
    {
        let mut iter = self.attributes();

        while let Some(item) = iter.next(fs) {
            let item = item?;
            let attribute = item.to_attribute()?;

            if attribute.ty()? != ty {
                continue;
            }

            if let Some(name) = match_name {
                if attribute.name()? != name {
                    continue;
                }
            }

            return Ok(item);
        }

        Err(NtfsError::AttributeNotFound {
            position: self.position(),
            ty,
        })
    }

    /// Finds a resident attribute of a specific type, optionally with a specific name and/or a specific
    /// instance identifier, and returns it.
    /// Returns [`NtfsError::AttributeNotFound`] if no such resident attribute could be found.
    ///
    /// The attribute type is given through the passed structured value type parameter.
    ///
    /// Note that this function DOES NOT traverse Attribute Lists!
    pub(crate) fn find_resident_attribute<'f>(
        &'f self,
        ty: NtfsAttributeType,
        match_name: Option<&str>,
        match_instance: Option<u16>,
    ) -> Result<NtfsAttribute<'n, 'f>> {
        // Resident attributes are always stored on the top-level (we don't have to dig into Attribute Lists).
        for attribute in self.attributes_raw() {
            let attribute = attribute?;

            if attribute.ty()? != ty {
                continue;
            }

            if let Some(instance) = match_instance {
                if attribute.instance() != instance {
                    continue;
                }
            }

            if let Some(name) = match_name {
                if attribute.name()? != name {
                    continue;
                }
            }

            return Ok(attribute);
        }

        Err(NtfsError::AttributeNotFound {
            position: self.position(),
            ty,
        })
    }

    /// Finds a resident attribute of a specific type, optionally with a specific name, and returns its structured value.
    /// Returns [`NtfsError::AttributeNotFound`] if no such resident attribute could be found.
    ///
    /// The attribute type is given through the passed structured value type parameter.
    ///
    /// Note that this function DOES NOT traverse Attribute Lists!
    pub(crate) fn find_resident_attribute_structured_value<'f, S>(
        &'f self,
        match_name: Option<&str>,
    ) -> Result<S>
    where
        S: NtfsStructuredValueFromResidentAttributeValue<'n, 'f>,
    {
        let attribute = self.find_resident_attribute(S::TY, match_name, None)?;
        attribute.resident_structured_value::<S>()
    }

    pub(crate) fn first_attribute_offset(&self) -> u16 {
        let start = offset_of!(FileRecordHeader, first_attribute_offset);
        LittleEndian::read_u16(&self.record.data()[start..])
    }

    /// Returns flags set for this file as specified by [`NtfsFileFlags`].
    pub fn flags(&self) -> NtfsFileFlags {
        let start = offset_of!(FileRecordHeader, flags);
        NtfsFileFlags::from_bits_truncate(LittleEndian::read_u16(&self.record.data()[start..]))
    }

    /// Returns the number of hard links to this NTFS File Record.
    pub fn hard_link_count(&self) -> u16 {
        let start = offset_of!(FileRecordHeader, hard_link_count);
        LittleEndian::read_u16(&self.record.data()[start..])
    }

    /// Convenience function to get the $STANDARD_INFORMATION attribute of this file
    /// (see [`NtfsStandardInformation`]).
    ///
    /// This internally calls [`NtfsFile::attributes_raw`] to iterate through the file's
    /// attributes and pick up the first $STANDARD_INFORMATION attribute.
    pub fn info(&self) -> Result<NtfsStandardInformation> {
        self.find_resident_attribute_structured_value::<NtfsStandardInformation>(None)
    }

    /// Returns whether this NTFS File Record represents a directory.
    pub fn is_directory(&self) -> bool {
        self.flags().contains(NtfsFileFlags::IS_DIRECTORY)
    }

    /// Convenience function to get a $FILE_NAME attribute of this file (see [`NtfsFileName`]).
    ///
    /// A file may have multiple $FILE_NAME attributes for each [`NtfsFileNamespace`].
    /// Files with hard links have further $FILE_NAME attributes for each directory they are in.
    /// You may optionally filter for a namespace and parent directory via the parameters.
    ///
    /// This internally calls [`NtfsFile::attributes`] to iterate through the file's
    /// attributes and pick up the first matching $FILE_NAME attribute.
    pub fn name<T>(
        &self,
        fs: &mut T,
        match_namespace: Option<NtfsFileNamespace>,
        match_parent_record_number: Option<u64>,
    ) -> Option<Result<NtfsFileName>>
    where
        T: Read + Seek,
    {
        let mut iter = self.attributes();

        while let Some(item) = iter.next(fs) {
            let item = iter_try!(item);
            let attribute = iter_try!(item.to_attribute());

            let ty = iter_try!(attribute.ty());
            if ty != NtfsAttributeType::FileName {
                continue;
            }

            let file_name = iter_try!(attribute.structured_value::<_, NtfsFileName>(fs));

            if let Some(namespace) = match_namespace {
                if file_name.namespace() != namespace {
                    continue;
                }
            }

            if let Some(parent_record_number) = match_parent_record_number {
                if file_name.parent_directory_reference().file_record_number()
                    != parent_record_number
                {
                    continue;
                }
            }

            return Some(Ok(file_name));
        }

        None
    }

    /// Returns the [`Ntfs`] object reference associated to this file.
    pub fn ntfs(&self) -> &'n Ntfs {
        self.ntfs
    }

    /// Returns the absolute byte position of this File Record in the NTFS filesystem.
    pub fn position(&self) -> NtfsPosition {
        self.record.position()
    }

    pub(crate) fn record_data(&self) -> &[u8] {
        self.record.data()
    }

    /// Returns the sequence number of this file.
    ///
    /// NTFS reuses records of deleted files when new files are created.
    /// This number is incremented every time a file is deleted.
    /// Hence, it gives a count how many time this File Record has been reused.
    pub fn sequence_number(&self) -> u16 {
        let start = offset_of!(FileRecordHeader, sequence_number);
        LittleEndian::read_u16(&self.record.data()[start..])
    }

    fn validate_signature(record: &Record) -> Result<()> {
        let signature = &record.signature();
        let expected = b"FILE";

        if signature == expected {
            Ok(())
        } else {
            Err(NtfsError::InvalidFileSignature {
                position: record.position(),
                expected,
                actual: *signature,
            })
        }
    }

    fn validate_sizes(&self) -> Result<()> {
        if self.allocated_size() > self.record.len() {
            return Err(NtfsError::InvalidFileAllocatedSize {
                position: self.record.position(),
                expected: self.allocated_size(),
                actual: self.record.len(),
            });
        }

        if self.data_size() > self.allocated_size() {
            return Err(NtfsError::InvalidFileUsedSize {
                position: self.record.position(),
                expected: self.data_size(),
                actual: self.allocated_size(),
            });
        }

        Ok(())
    }
}
