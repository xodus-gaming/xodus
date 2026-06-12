// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem;

use arrayvec::ArrayVec;
use binrw::io::{Cursor, Read, Seek, SeekFrom};
use binrw::{BinRead, BinReaderExt};
use nt_string::u16strle::U16StrLe;

use crate::attribute::{NtfsAttribute, NtfsAttributeType};
use crate::attribute_value::{NtfsAttributeValue, NtfsNonResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::file_reference::NtfsFileReference;
use crate::ntfs::Ntfs;
use crate::structured_values::NtfsStructuredValue;
use crate::traits::NtfsReadSeek;
use crate::types::{NtfsPosition, Vcn};

/// Size of all [`AttributeListEntryHeader`] fields.
const ATTRIBUTE_LIST_ENTRY_HEADER_SIZE: usize = 26;

/// [`AttributeListEntryHeader::name_length`] is an `u8` length field specifying the number of UTF-16 code points.
/// Hence, the name occupies up to 510 bytes.
const NAME_MAX_SIZE: usize = (u8::MAX as usize) * mem::size_of::<u16>();

#[allow(unused)]
#[derive(BinRead, Clone, Debug)]
struct AttributeListEntryHeader {
    /// Type of the attribute, known types are in [`NtfsAttributeType`].
    ty: u32,
    /// Length of this attribute list entry, in bytes.
    list_entry_length: u16,
    /// Length of the name, in UTF-16 code points (every code point is 2 bytes).
    name_length: u8,
    /// Offset to the beginning of the name, in bytes from the beginning of this header.
    name_offset: u8,
    /// Lower boundary of Virtual Cluster Numbers (VCNs) referenced by this attribute.
    /// This becomes relevant when file data is split over multiple attributes.
    /// Otherwise, it's zero.
    lowest_vcn: Vcn,
    /// Reference to the File Record where this attribute is stored.
    base_file_reference: NtfsFileReference,
    /// Identifier of this attribute that is unique within the [`NtfsFile`].
    instance: u16,
}

/// Structure of an $ATTRIBUTE_LIST attribute.
///
/// When a File Record lacks space to incorporate further attributes, NTFS creates an additional File Record,
/// moves all or some of the existing attributes there, and references them via a resident $ATTRIBUTE_LIST attribute
/// in the original File Record.
/// When you add even more attributes, NTFS may turn the resident $ATTRIBUTE_LIST into a non-resident one to
/// make up the required space.
///
/// An $ATTRIBUTE_LIST attribute can hence be resident or non-resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/attribute_list.html>
#[derive(Clone, Debug)]
pub enum NtfsAttributeList<'n, 'f> {
    /// A resident $ATTRIBUTE_LIST attribute.
    Resident(&'f [u8], NtfsPosition),
    /// A non-resident $ATTRIBUTE_LIST attribute.
    NonResident(NtfsNonResidentAttributeValue<'n, 'f>),
}

impl<'n, 'f> NtfsAttributeList<'n, 'f> {
    /// Returns an iterator over all entries of this $ATTRIBUTE_LIST attribute (cf. [`NtfsAttributeListEntry`]).
    pub fn entries(&self) -> NtfsAttributeListEntries<'n, 'f> {
        NtfsAttributeListEntries::new(self.clone())
    }

    /// Returns the absolute position of this $ATTRIBUTE_LIST attribute value within the filesystem, in bytes.
    pub fn position(&self) -> NtfsPosition {
        match self {
            Self::Resident(_slice, position) => *position,
            Self::NonResident(value) => value.data_position(),
        }
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsAttributeList<'n, 'f> {
    const TY: NtfsAttributeType = NtfsAttributeType::AttributeList;

    fn from_attribute_value<T>(_fs: &mut T, value: NtfsAttributeValue<'n, 'f>) -> Result<Self>
    where
        T: Read + Seek,
    {
        match value {
            NtfsAttributeValue::Resident(value) => {
                let slice = value.data();
                let position = value.data_position();
                Ok(Self::Resident(slice, position))
            }
            NtfsAttributeValue::NonResident(value) => Ok(Self::NonResident(value)),
            NtfsAttributeValue::AttributeListNonResident(value) => {
                // Attribute Lists are never nested.
                // Hence, we must not create this attribute from an attribute that is already part of Attribute List.
                let position = value.data_position();
                Err(NtfsError::UnexpectedAttributeListAttribute { position })
            }
        }
    }
}

/// Iterator over
///   all entries of an [`NtfsAttributeList`] attribute,
///   returning an [`NtfsAttributeListEntry`] for each entry.
///
/// This iterator is returned from the [`NtfsAttributeList::entries`] function.
#[derive(Clone, Debug)]
pub struct NtfsAttributeListEntries<'n, 'f> {
    attribute_list: NtfsAttributeList<'n, 'f>,
}

impl<'n, 'f> NtfsAttributeListEntries<'n, 'f> {
    fn new(attribute_list: NtfsAttributeList<'n, 'f>) -> Self {
        Self { attribute_list }
    }

    /// See [`Iterator::next`].
    pub fn next<T>(&mut self, fs: &mut T) -> Option<Result<NtfsAttributeListEntry>>
    where
        T: Read + Seek,
    {
        match &mut self.attribute_list {
            NtfsAttributeList::Resident(slice, position) => Self::next_resident(slice, position),
            NtfsAttributeList::NonResident(value) => Self::next_non_resident(fs, value),
        }
    }

    fn next_non_resident<T>(
        fs: &mut T,
        value: &mut NtfsNonResidentAttributeValue<'n, 'f>,
    ) -> Option<Result<NtfsAttributeListEntry>>
    where
        T: Read + Seek,
    {
        if value.stream_position() >= value.len() {
            return None;
        }

        // Get the current entry.
        let mut value_attached = value.clone().attach(fs);
        let position = value.data_position();
        let entry = iter_try!(NtfsAttributeListEntry::new(&mut value_attached, position));

        // Advance our iterator to the next entry.
        iter_try!(value.seek(fs, SeekFrom::Current(entry.list_entry_length() as i64)));

        Some(Ok(entry))
    }

    fn next_resident(
        slice: &mut &'f [u8],
        position: &mut NtfsPosition,
    ) -> Option<Result<NtfsAttributeListEntry>> {
        if slice.is_empty() {
            return None;
        }

        // Get the current entry.
        let mut cursor = Cursor::new(*slice);
        let entry = iter_try!(NtfsAttributeListEntry::new(&mut cursor, *position));

        // Advance our iterator to the next entry.
        let bytes_to_advance = entry.list_entry_length() as usize;
        *slice = slice.get(bytes_to_advance..)?;
        *position += bytes_to_advance;
        Some(Ok(entry))
    }
}

/// A single entry of an [`NtfsAttributeList`] attribute.
#[derive(Clone, Debug)]
pub struct NtfsAttributeListEntry {
    header: AttributeListEntryHeader,
    name: ArrayVec<u8, NAME_MAX_SIZE>,
    position: NtfsPosition,
}

impl NtfsAttributeListEntry {
    fn new<T>(r: &mut T, position: NtfsPosition) -> Result<Self>
    where
        T: Read + Seek,
    {
        let header = r.read_le::<AttributeListEntryHeader>()?;

        let mut entry = Self {
            header,
            name: ArrayVec::from([0u8; NAME_MAX_SIZE]),
            position,
        };
        entry.validate_entry_and_name_length()?;
        entry.read_name(r)?;

        Ok(entry)
    }

    /// Returns a reference to the File Record where the attribute is stored.
    pub fn base_file_reference(&self) -> NtfsFileReference {
        self.header.base_file_reference
    }

    /// Returns the instance number of this attribute list entry.
    ///
    /// An instance number is unique within a single NTFS File Record.
    ///
    /// Multiple entries of the same type and instance number form a connected attribute,
    /// meaning an attribute whose value is stretched over multiple attributes.
    pub fn instance(&self) -> u16 {
        self.header.instance
    }

    /// Returns the length of this attribute list entry, in bytes.
    pub fn list_entry_length(&self) -> u16 {
        self.header.list_entry_length
    }

    /// Returns the offset of this attribute's value data as a Virtual Cluster Number (VCN).
    ///
    /// This is zero for all unconnected attributes and for the first attribute of a connected attribute.
    /// For subsequent attributes of a connected attribute, this value is nonzero.
    ///
    /// The lowest_vcn + data length of one attribute equal the lowest_vcn of its following connected attribute.
    pub fn lowest_vcn(&self) -> Vcn {
        self.header.lowest_vcn
    }

    /// Gets the attribute name and returns it wrapped in a [`U16StrLe`].
    pub fn name(&self) -> U16StrLe {
        U16StrLe(&self.name)
    }

    /// Returns the file name length, in bytes.
    ///
    /// A file name has a maximum length of 255 UTF-16 code points (510 bytes).
    pub fn name_length(&self) -> usize {
        self.header.name_length as usize * mem::size_of::<u16>()
    }

    /// Returns the absolute position of this attribute list entry within the filesystem, in bytes.
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    fn read_name<T>(&mut self, r: &mut T) -> Result<()>
    where
        T: Read + Seek,
    {
        debug_assert_eq!(self.name.len(), NAME_MAX_SIZE);

        let name_length = self.name_length();
        r.read_exact(&mut self.name[..name_length])?;
        self.name.truncate(name_length);

        Ok(())
    }

    /// Returns an [`NtfsAttribute`] for the attribute described by this list entry.
    ///
    /// Use [`NtfsAttributeListEntry::to_file`] first to get the required File Record.
    ///
    /// # Panics
    ///
    /// Panics if a wrong File Record has been passed.
    pub fn to_attribute<'n, 'f>(&self, file: &'f NtfsFile<'n>) -> Result<NtfsAttribute<'n, 'f>> {
        let file_record_number = self.base_file_reference().file_record_number();
        assert_eq!(
            file.file_record_number(),
            file_record_number,
            "The given NtfsFile's record number does not match the expected record number. \
            Always use NtfsAttributeListEntry::to_file to retrieve the correct NtfsFile."
        );

        let instance = self.instance();
        let ty = self.ty()?;

        file.find_resident_attribute(ty, None, Some(instance))
    }

    /// Reads the entire File Record referenced by this attribute and returns it.
    pub fn to_file<'n, T>(&self, ntfs: &'n Ntfs, fs: &mut T) -> Result<NtfsFile<'n>>
    where
        T: Read + Seek,
    {
        let file_record_number = self.base_file_reference().file_record_number();
        ntfs.file(fs, file_record_number)
    }

    /// Returns the type of this NTFS Attribute, or [`NtfsError::UnsupportedAttributeType`]
    /// if it's an unknown type.
    pub fn ty(&self) -> Result<NtfsAttributeType> {
        NtfsAttributeType::n(self.header.ty).ok_or(NtfsError::UnsupportedAttributeType {
            position: self.position(),
            actual: self.header.ty,
        })
    }

    fn validate_entry_and_name_length(&self) -> Result<()> {
        let total_size = ATTRIBUTE_LIST_ENTRY_HEADER_SIZE + self.name_length();

        if total_size > self.list_entry_length() as usize {
            return Err(NtfsError::InvalidStructuredValueSize {
                position: self.position(),
                ty: NtfsAttributeType::AttributeList,
                expected: self.list_entry_length() as u64,
                actual: total_size as u64,
            });
        }

        Ok(())
    }
}
