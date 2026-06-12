// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::iter::FusedIterator;

use binrw::io::{Read, Seek, SeekFrom};

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::NtfsAttributeValue;
use crate::error::{NtfsError, Result};
use crate::index_record::NtfsIndexRecord;
use crate::ntfs::Ntfs;
use crate::structured_values::NtfsStructuredValue;
use crate::traits::NtfsReadSeek;
use crate::types::Vcn;

/// Structure of an $INDEX_ALLOCATION attribute.
///
/// This attribute describes the sub-nodes of a B-tree.
/// The top-level nodes are managed via [`NtfsIndexRoot`].
///
/// NTFS uses B-trees for describing directories (as indexes of [`NtfsFileName`]s), looking up Object IDs,
/// Reparse Points, and Security Descriptors, to just name a few.
///
/// An $INDEX_ALLOCATION attribute can be resident or non-resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/index_allocation.html>
///
/// [`NtfsFileName`]: crate::structured_values::NtfsFileName
/// [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot
#[derive(Clone, Debug)]
pub struct NtfsIndexAllocation<'n, 'f> {
    ntfs: &'n Ntfs,
    value: NtfsAttributeValue<'n, 'f>,
}

impl<'n, 'f> NtfsIndexAllocation<'n, 'f> {
    /// Returns the [`NtfsIndexRecord`] located at the given Virtual Cluster Number (VCN).
    ///
    /// The record is fully read, fixed up, and validated.
    ///
    /// This function is usually called on the return value of [`NtfsIndexEntry::subnode_vcn`] to move further
    /// down in the B-tree.
    ///
    /// [`NtfsIndexEntry::subnode_vcn`]: crate::NtfsIndexEntry::subnode_vcn
    pub fn record_from_vcn<T>(
        &self,
        fs: &mut T,
        index_record_size: u32,
        vcn: Vcn,
    ) -> Result<NtfsIndexRecord>
    where
        T: Read + Seek,
    {
        // Seek to the byte offset of the given VCN.
        let mut value = self.value.clone();
        let offset = vcn.offset(self.ntfs)?;
        value.seek(fs, SeekFrom::Current(offset))?;

        if value.stream_position() >= value.len() {
            return Err(NtfsError::VcnOutOfBoundsInIndexAllocation {
                position: self.value.data_position(),
                vcn,
            });
        }

        // Get the record.
        let record = NtfsIndexRecord::new(fs, value, index_record_size)?;

        // Validate that the VCN in the record is the requested one.
        if record.vcn() != vcn {
            return Err(NtfsError::VcnMismatchInIndexAllocation {
                position: self.value.data_position(),
                expected: vcn,
                actual: record.vcn(),
            });
        }

        Ok(record)
    }

    /// Returns an iterator over all Index Records of this $INDEX_ALLOCATION attribute (cf. [`NtfsIndexRecord`]).
    ///
    /// Each Index Record is fully read, fixed up, and validated.
    pub fn records(&self, index_record_size: u32) -> NtfsIndexRecords<'n, 'f> {
        NtfsIndexRecords::new(self.clone(), index_record_size)
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsIndexAllocation<'n, 'f> {
    const TY: NtfsAttributeType = NtfsAttributeType::IndexAllocation;

    fn from_attribute_value<T>(_fs: &mut T, value: NtfsAttributeValue<'n, 'f>) -> Result<Self>
    where
        T: Read + Seek,
    {
        let ntfs = match &value {
            NtfsAttributeValue::AttributeListNonResident(value) => value.ntfs(),
            NtfsAttributeValue::NonResident(value) => value.ntfs(),
            NtfsAttributeValue::Resident(_) => {
                let position = value.data_position();
                return Err(NtfsError::UnexpectedResidentAttribute { position });
            }
        };

        Ok(Self { ntfs, value })
    }
}

/// Iterator over
///   all index records of an [`NtfsIndexAllocation`],
///   returning an [`NtfsIndexRecord`] for each record.
///
/// This iterator is returned from the [`NtfsIndexAllocation::records`] function.
///
/// See [`NtfsIndexRecordsAttached`] for an iterator that implements [`Iterator`] and [`FusedIterator`].
#[derive(Clone, Debug)]
pub struct NtfsIndexRecords<'n, 'f> {
    index_allocation: NtfsIndexAllocation<'n, 'f>,
    index_record_size: u32,
}

impl<'n, 'f> NtfsIndexRecords<'n, 'f> {
    fn new(index_allocation: NtfsIndexAllocation<'n, 'f>, index_record_size: u32) -> Self {
        Self {
            index_allocation,
            index_record_size,
        }
    }

    /// Returns a variant of this iterator that implements [`Iterator`] and [`FusedIterator`]
    /// by mutably borrowing the filesystem reader.
    pub fn attach<'a, T>(self, fs: &'a mut T) -> NtfsIndexRecordsAttached<'n, 'f, 'a, T>
    where
        T: Read + Seek,
    {
        NtfsIndexRecordsAttached::new(fs, self)
    }

    /// See [`Iterator::next`].
    pub fn next<T>(&mut self, fs: &mut T) -> Option<Result<NtfsIndexRecord>>
    where
        T: Read + Seek,
    {
        if self.index_allocation.value.stream_position() >= self.index_allocation.value.len() {
            return None;
        }

        // Get the current record.
        let record = iter_try!(NtfsIndexRecord::new(
            fs,
            self.index_allocation.value.clone(),
            self.index_record_size
        ));

        // Advance our iterator to the next record.
        iter_try!(self
            .index_allocation
            .value
            .seek(fs, SeekFrom::Current(self.index_record_size as i64)));

        Some(Ok(record))
    }
}

/// Iterator over
///   all index records of an [`NtfsIndexAllocation`],
///   returning an [`NtfsIndexRecord`] for each record,
///   implementing [`Iterator`] and [`FusedIterator`].
///
/// This iterator is returned from the [`NtfsIndexRecords::attach`] function.
/// Conceptually the same as [`NtfsIndexRecords`], but mutably borrows the filesystem
/// to implement aforementioned traits.
#[derive(Debug)]
pub struct NtfsIndexRecordsAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    fs: &'a mut T,
    index_records: NtfsIndexRecords<'n, 'f>,
}

impl<'n, 'f, 'a, T> NtfsIndexRecordsAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    fn new(fs: &'a mut T, index_records: NtfsIndexRecords<'n, 'f>) -> Self {
        Self { fs, index_records }
    }
    /// Consumes this iterator and returns the inner [`NtfsIndexRecords`].
    pub fn detach(self) -> NtfsIndexRecords<'n, 'f> {
        self.index_records
    }
}

impl<'n, 'f, 'a, T> Iterator for NtfsIndexRecordsAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    type Item = Result<NtfsIndexRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        self.index_records.next(self.fs)
    }
}

impl<'n, 'f, 'a, T> FusedIterator for NtfsIndexRecordsAttached<'n, 'f, 'a, T> where T: Read + Seek {}
