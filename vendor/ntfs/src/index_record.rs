// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::ops::Range;

use alloc::vec;
use binrw::io::{Read, Seek};
use byteorder::{ByteOrder, LittleEndian};
use memoffset::offset_of;

use crate::attribute_value::NtfsAttributeValue;
use crate::error::{NtfsError, Result};
use crate::index_entry::{IndexNodeEntryRanges, NtfsIndexNodeEntries};
use crate::indexes::NtfsIndexEntryType;
use crate::record::Record;
use crate::record::RecordHeader;
use crate::traits::NtfsReadSeek;
use crate::types::{NtfsPosition, Vcn};

/// Size of all [`IndexRecordHeader`] fields.
const INDEX_RECORD_HEADER_SIZE: u32 = 24;

#[repr(C, packed)]
struct IndexRecordHeader {
    record_header: RecordHeader,
    vcn: i64,
}

/// Size of all [`IndexNodeHeader`] fields plus some reserved bytes.
pub(crate) const INDEX_NODE_HEADER_SIZE: usize = 16;

#[repr(C, packed)]
pub(crate) struct IndexNodeHeader {
    pub(crate) entries_offset: u32,
    pub(crate) index_size: u32,
    pub(crate) allocated_size: u32,
    pub(crate) flags: u8,
}

/// A single NTFS Index Record.
///
/// These records are denoted via an `INDX` signature on the filesystem.
///
/// NTFS uses B-tree indexes to quickly look up files, Object IDs, Reparse Points, Security Descriptors, etc.
/// An Index Record is further comprised of Index Entries, which contain the actual key/data (see [`NtfsIndexEntry`],
/// iterated via [`NtfsIndexNodeEntries`]).
///
/// [`NtfsIndexEntry`]: crate::NtfsIndexEntry
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/index_record.html>
#[derive(Debug)]
pub struct NtfsIndexRecord {
    record: Record,
}

const HAS_SUBNODES_FLAG: u8 = 0x01;

impl NtfsIndexRecord {
    pub(crate) fn new<T>(
        fs: &mut T,
        mut value: NtfsAttributeValue,
        index_record_size: u32,
    ) -> Result<Self>
    where
        T: Read + Seek,
    {
        let data_position = value.data_position();

        let mut data = vec![0; index_record_size as usize];
        value.read_exact(fs, &mut data)?;

        let mut record = Record::new(data, data_position);
        Self::validate_signature(&record)?;
        record.fixup()?;

        let index_record = Self { record };
        index_record.validate_sizes()?;

        Ok(index_record)
    }

    /// Returns an iterator over all entries of this Index Record (cf. [`NtfsIndexEntry`]).
    ///
    /// [`NtfsIndexEntry`]: crate::NtfsIndexEntry
    pub fn entries<E>(&self) -> Result<NtfsIndexNodeEntries<E>>
    where
        E: NtfsIndexEntryType,
    {
        let (entries_range, position) = self.entries_range_and_position();
        let data = &self.record.data()[entries_range];

        Ok(NtfsIndexNodeEntries::new(data, position))
    }

    fn entries_range_and_position(&self) -> (Range<usize>, NtfsPosition) {
        let start = INDEX_RECORD_HEADER_SIZE as usize + self.index_entries_offset() as usize;
        let end = INDEX_RECORD_HEADER_SIZE as usize + self.index_data_size() as usize;
        let position = self.record.position() + start;

        (start..end, position)
    }

    /// Returns whether this index node has sub-nodes.
    /// Otherwise, this index node is a leaf node.
    pub fn has_subnodes(&self) -> bool {
        let start = INDEX_RECORD_HEADER_SIZE as usize + offset_of!(IndexNodeHeader, flags);
        let flags = self.record.data()[start];
        (flags & HAS_SUBNODES_FLAG) != 0
    }

    /// Returns the allocated size of this NTFS Index Record, in bytes.
    pub fn index_allocated_size(&self) -> u32 {
        let start = INDEX_RECORD_HEADER_SIZE as usize + offset_of!(IndexNodeHeader, allocated_size);
        LittleEndian::read_u32(&self.record.data()[start..])
    }

    /// Returns the size actually used by index data within this NTFS Index Record, in bytes.
    pub fn index_data_size(&self) -> u32 {
        let start = INDEX_RECORD_HEADER_SIZE as usize + offset_of!(IndexNodeHeader, index_size);
        LittleEndian::read_u32(&self.record.data()[start..])
    }

    pub(crate) fn index_entries_offset(&self) -> u32 {
        let start = INDEX_RECORD_HEADER_SIZE as usize + offset_of!(IndexNodeHeader, entries_offset);
        LittleEndian::read_u32(&self.record.data()[start..])
    }

    pub(crate) fn into_entry_ranges<E>(self) -> IndexNodeEntryRanges<E>
    where
        E: NtfsIndexEntryType,
    {
        let (entries_range, position) = self.entries_range_and_position();
        IndexNodeEntryRanges::new(self.record.into_data(), entries_range, position)
    }

    fn validate_signature(record: &Record) -> Result<()> {
        let signature = &record.signature();
        let expected = b"INDX";

        if signature == expected {
            Ok(())
        } else {
            Err(NtfsError::InvalidIndexSignature {
                position: record.position(),
                expected,
                actual: *signature,
            })
        }
    }

    fn validate_sizes(&self) -> Result<()> {
        let index_record_size = self.record.len();

        // The total size allocated for this Index Record must not be larger than
        // the size defined for all index records of this index.
        let total_allocated_size = INDEX_RECORD_HEADER_SIZE + self.index_allocated_size();
        if total_allocated_size > index_record_size {
            return Err(NtfsError::InvalidIndexAllocatedSize {
                position: self.record.position(),
                expected: index_record_size,
                actual: total_allocated_size,
            });
        }

        // Furthermore, the total used size for this Index Record must not be
        // larger than the total allocated size.
        let total_data_size = INDEX_RECORD_HEADER_SIZE + self.index_data_size();
        if total_data_size > total_allocated_size {
            return Err(NtfsError::InvalidIndexUsedSize {
                position: self.record.position(),
                expected: total_allocated_size,
                actual: total_data_size,
            });
        }

        Ok(())
    }

    /// Returns the Virtual Cluster Number (VCN) of this Index Record, as reported by the header of this Index Record.
    ///
    /// This can be used to double-check that an Index Record is the actually requested one.
    /// [`NtfsIndexAllocation::record_from_vcn`] uses it for that purpose.
    ///
    /// [`NtfsIndexAllocation::record_from_vcn`]: crate::structured_values::NtfsIndexAllocation::record_from_vcn
    pub fn vcn(&self) -> Vcn {
        let start = offset_of!(IndexRecordHeader, vcn);
        Vcn::from(LittleEndian::read_i64(&self.record.data()[start..]))
    }
}
