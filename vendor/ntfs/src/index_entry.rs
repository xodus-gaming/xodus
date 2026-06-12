// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::iter::FusedIterator;
use core::marker::PhantomData;
use core::ops::Range;
use core::{fmt, mem};

use alloc::vec::Vec;
use binrw::io::{Read, Seek};
use bitflags::bitflags;
use byteorder::{ByteOrder, LittleEndian};
use memoffset::offset_of;

use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::file_reference::NtfsFileReference;
use crate::indexes::{
    NtfsIndexEntryData, NtfsIndexEntryHasData, NtfsIndexEntryHasFileReference, NtfsIndexEntryKey,
    NtfsIndexEntryType,
};
use crate::ntfs::Ntfs;
use crate::types::NtfsPosition;
use crate::types::Vcn;

/// Size of all [`IndexEntryHeader`] fields plus some reserved bytes.
const INDEX_ENTRY_HEADER_SIZE: usize = 16;

#[repr(C, packed)]
struct IndexEntryHeader {
    // The following three fields are used for the u64 file reference if the entry type
    // has no data, but a file reference instead.
    // This is indicated by the entry type implementing `NtfsIndexEntryHasFileReference`.
    // Currently, only `NtfsFileNameIndex` has such a file reference.
    data_offset: u16,
    data_length: u16,
    padding: u32,

    index_entry_length: u16,
    key_length: u16,
    flags: u8,
}

bitflags! {
    /// Flags returned by [`NtfsIndexEntry::flags`].
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsIndexEntryFlags: u8 {
        /// This Index Entry points to a sub-node.
        const HAS_SUBNODE = 0x01;
        /// This is the last Index Entry in the list.
        const LAST_ENTRY = 0x02;
    }
}

impl fmt::Display for NtfsIndexEntryFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IndexEntryRange<E>
where
    E: NtfsIndexEntryType,
{
    range: Range<usize>,
    position: NtfsPosition,
    entry_type: PhantomData<E>,
}

impl<E> IndexEntryRange<E>
where
    E: NtfsIndexEntryType,
{
    pub(crate) fn new(range: Range<usize>, position: NtfsPosition) -> Self {
        let entry_type = PhantomData;
        Self {
            range,
            position,
            entry_type,
        }
    }

    pub(crate) fn to_entry<'s>(&self, slice: &'s [u8]) -> Result<NtfsIndexEntry<'s, E>> {
        NtfsIndexEntry::new(&slice[self.range.clone()], self.position)
    }
}

/// A single entry of an NTFS index.
///
/// NTFS uses B-tree indexes to quickly look up files, Object IDs, Reparse Points, Security Descriptors, etc.
/// They are described via [`NtfsIndexRoot`] and [`NtfsIndexAllocation`] attributes, which can be comfortably
/// accessed via [`NtfsIndex`].
///
/// The `E` type parameter of [`NtfsIndexEntryType`] specifies the type of the Index Entry.
/// The most common one is [`NtfsFileNameIndex`] for file name indexes, commonly known as "directories".
/// Check out [`NtfsFile::directory_index`] to return an [`NtfsIndex`] object for a directory without
/// any hassles.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/index_entry.html>
///
/// [`NtfsFileNameIndex`]: crate::indexes::NtfsFileNameIndex
/// [`NtfsIndex`]: crate::NtfsIndex
/// [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
/// [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot
#[derive(Clone, Debug)]
pub struct NtfsIndexEntry<'s, E>
where
    E: NtfsIndexEntryType,
{
    slice: &'s [u8],
    position: NtfsPosition,
    entry_type: PhantomData<E>,
}

impl<'s, E> NtfsIndexEntry<'s, E>
where
    E: NtfsIndexEntryType,
{
    pub(crate) fn new(slice: &'s [u8], position: NtfsPosition) -> Result<Self> {
        let entry_type = PhantomData;

        let mut entry = Self {
            slice,
            position,
            entry_type,
        };
        entry.validate_size()?;
        entry.slice = &entry.slice[..entry.index_entry_length() as usize];

        Ok(entry)
    }

    /// Returns the data of this Index Entry, if any and if supported by this Index Entry type.
    ///
    /// This function is mutually exclusive with [`NtfsIndexEntry::file_reference`].
    /// An Index Entry can either have data or a file reference.
    pub fn data(&self) -> Option<Result<E::DataType>>
    where
        E: NtfsIndexEntryHasData,
    {
        if self.data_offset() == 0 || self.data_length() == 0 {
            return None;
        }

        let start = self.data_offset() as usize;
        let end = start + self.data_length() as usize;
        let position = self.position + start;

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len() as u16
        }));

        let data = iter_try!(E::DataType::data_from_slice(slice, position));
        Some(Ok(data))
    }

    fn data_offset(&self) -> u16
    where
        E: NtfsIndexEntryHasData,
    {
        let start = offset_of!(IndexEntryHeader, data_offset);
        LittleEndian::read_u16(&self.slice[start..])
    }

    /// Returns the length of the data of this Index Entry (if supported by this Index Entry type).
    pub fn data_length(&self) -> u16
    where
        E: NtfsIndexEntryHasData,
    {
        let start = offset_of!(IndexEntryHeader, data_length);
        LittleEndian::read_u16(&self.slice[start..])
    }

    /// Returns an [`NtfsFileReference`] for the file referenced by this Index Entry
    /// (if supported by this Index Entry type).
    ///
    /// This function is mutually exclusive with [`NtfsIndexEntry::data`].
    /// An Index Entry can either have data or a file reference.
    pub fn file_reference(&self) -> NtfsFileReference
    where
        E: NtfsIndexEntryHasFileReference,
    {
        // The "file_reference_data" is at the same position as the `data_offset`, `data_length`, and `padding` fields.
        // There can either be extra data or a file reference!
        NtfsFileReference::new(self.slice[..mem::size_of::<u64>()].try_into().unwrap())
    }

    /// Returns flags set for this attribute as specified by [`NtfsIndexEntryFlags`].
    pub fn flags(&self) -> NtfsIndexEntryFlags {
        let flags = self.slice[offset_of!(IndexEntryHeader, flags)];
        NtfsIndexEntryFlags::from_bits_truncate(flags)
    }

    /// Returns the total length of this Index Entry, in bytes.
    ///
    /// The next Index Entry is exactly at [`NtfsIndexEntry::position`] + [`NtfsIndexEntry::index_entry_length`]
    /// on the filesystem, unless this is the last entry ([`NtfsIndexEntry::flags`] contains
    /// [`NtfsIndexEntryFlags::LAST_ENTRY`]).
    pub fn index_entry_length(&self) -> u16 {
        let start = offset_of!(IndexEntryHeader, index_entry_length);
        LittleEndian::read_u16(&self.slice[start..])
    }

    /// Returns the structured value of the key of this Index Entry,
    /// or `None` if this Index Entry has no key.
    ///
    /// The last Index Entry never has a key.
    pub fn key(&self) -> Option<Result<E::KeyType>> {
        // The key/stream is only set when the last entry flag is not set.
        // https://flatcap.github.io/linux-ntfs/ntfs/concepts/index_entry.html
        if self.key_length() == 0 || self.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            return None;
        }

        let start = INDEX_ENTRY_HEADER_SIZE;
        let end = start + self.key_length() as usize;
        let position = self.position + start;

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len() as u16
        }));

        let key = iter_try!(E::KeyType::key_from_slice(slice, position));
        Some(Ok(key))
    }

    /// Returns the length of the key of this Index Entry.
    pub fn key_length(&self) -> u16 {
        let start = offset_of!(IndexEntryHeader, key_length);
        LittleEndian::read_u16(&self.slice[start..])
    }

    /// Returns the absolute position of this NTFS Index Entry within the filesystem, in bytes.
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    /// Returns the Virtual Cluster Number (VCN) of the subnode of this Index Entry,
    /// or `None` if this Index Entry has no subnode.
    pub fn subnode_vcn(&self) -> Option<Result<Vcn>> {
        if !self.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE) {
            return None;
        }

        // Get the subnode VCN from the very end of the Index Entry, but at least after the header.
        let start = usize::max(
            self.index_entry_length() as usize - mem::size_of::<Vcn>(),
            INDEX_ENTRY_HEADER_SIZE,
        );
        let end = start + mem::size_of::<Vcn>();

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len() as u16
        }));

        let vcn = Vcn::from(LittleEndian::read_i64(slice));
        Some(Ok(vcn))
    }

    /// Returns an [`NtfsFile`] for the file referenced by this Index Entry.
    pub fn to_file<'n, T>(&self, ntfs: &'n Ntfs, fs: &mut T) -> Result<NtfsFile<'n>>
    where
        E: NtfsIndexEntryHasFileReference,
        T: Read + Seek,
    {
        self.file_reference().to_file(ntfs, fs)
    }

    fn validate_size(&self) -> Result<()> {
        if self.slice.len() < INDEX_ENTRY_HEADER_SIZE {
            return Err(NtfsError::InvalidIndexEntrySize {
                position: self.position,
                expected: INDEX_ENTRY_HEADER_SIZE as u16,
                actual: self.slice.len() as u16,
            });
        }

        if self.index_entry_length() as usize > self.slice.len() {
            return Err(NtfsError::InvalidIndexEntrySize {
                position: self.position,
                expected: self.index_entry_length(),
                actual: self.slice.len() as u16,
            });
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IndexNodeEntryRanges<E>
where
    E: NtfsIndexEntryType,
{
    data: Vec<u8>,
    range: Range<usize>,
    position: NtfsPosition,
    entry_type: PhantomData<E>,
}

impl<E> IndexNodeEntryRanges<E>
where
    E: NtfsIndexEntryType,
{
    pub(crate) fn new(data: Vec<u8>, range: Range<usize>, position: NtfsPosition) -> Self {
        debug_assert!(range.end <= data.len());
        let entry_type = PhantomData;

        Self {
            data,
            range,
            position,
            entry_type,
        }
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<E> Iterator for IndexNodeEntryRanges<E>
where
    E: NtfsIndexEntryType,
{
    type Item = Result<IndexEntryRange<E>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.is_empty() {
            return None;
        }

        // Get the current entry.
        let start = self.range.start;
        let position = self.position;
        let entry = iter_try!(NtfsIndexEntry::<E>::new(&self.data[start..], position));
        let end = start + entry.index_entry_length() as usize;

        if entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            // This is the last entry.
            // Ensure that we don't read any other entries by advancing `self.range.start` to the end.
            self.range.start = self.data.len();
        } else {
            // This is not the last entry.
            // Advance our iterator to the next entry.
            self.range.start = end;
            self.position += entry.index_entry_length();
        }

        Some(Ok(IndexEntryRange::new(start..end, position)))
    }
}

impl<E> FusedIterator for IndexNodeEntryRanges<E> where E: NtfsIndexEntryType {}

/// Iterator over
///   all index entries of a single index node,
///   sorted ascending by the index key,
///   returning an [`NtfsIndexEntry`] for each entry.
///
/// An index node can be an [`NtfsIndexRoot`] attribute or an [`NtfsIndexRecord`]
/// (which comes from an [`NtfsIndexAllocation`] attribute).
///
/// As such, this iterator is returned from the [`NtfsIndexRoot::entries`] and
/// [`NtfsIndexRecord::entries`] functions.
///
/// [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
/// [`NtfsIndexRecord`]: crate::NtfsIndexRecord
/// [`NtfsIndexRecord::entries`]: crate::NtfsIndexRecord::entries
/// [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot
/// [`NtfsIndexRoot::entries`]: crate::structured_values::NtfsIndexRoot::entries
#[derive(Clone, Debug)]
pub struct NtfsIndexNodeEntries<'s, E>
where
    E: NtfsIndexEntryType,
{
    slice: &'s [u8],
    position: NtfsPosition,
    entry_type: PhantomData<E>,
}

impl<'s, E> NtfsIndexNodeEntries<'s, E>
where
    E: NtfsIndexEntryType,
{
    pub(crate) fn new(slice: &'s [u8], position: NtfsPosition) -> Self {
        let entry_type = PhantomData;
        Self {
            slice,
            position,
            entry_type,
        }
    }
}

impl<'s, E> Iterator for NtfsIndexNodeEntries<'s, E>
where
    E: NtfsIndexEntryType,
{
    type Item = Result<NtfsIndexEntry<'s, E>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            return None;
        }

        // Get the current entry.
        let entry = iter_try!(NtfsIndexEntry::new(self.slice, self.position));

        if entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            // This is the last entry.
            // Ensure that we don't read any other entries by emptying the slice.
            self.slice = &[];
        } else {
            // This is not the last entry.
            // Advance our iterator to the next entry.
            let bytes_to_advance = entry.index_entry_length() as usize;
            self.slice = &self.slice[bytes_to_advance..];
            self.position += bytes_to_advance;
        }

        Some(Ok(entry))
    }
}

impl<'s, E> FusedIterator for NtfsIndexNodeEntries<'s, E> where E: NtfsIndexEntryType {}
