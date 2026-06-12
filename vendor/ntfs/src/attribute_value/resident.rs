// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! This module implements a reader for a value that is already in memory and can therefore be accessed via a slice.
//! This is the case for all resident attribute values and Index Record values.
//! Such values are part of NTFS records. NTFS records can't be directly read from the filesystem, which is why they
//! are always read into a buffer first and then fixed up in memory.
//! Further accesses to the record data can then happen via slices.

use binrw::io::{Read, Seek, SeekFrom};

use super::seek_contiguous;
use crate::error::Result;
use crate::traits::NtfsReadSeek;
use crate::types::NtfsPosition;

/// Reader for a value of a resident NTFS Attribute (which is entirely contained in the NTFS File Record).
#[derive(Clone, Debug)]
pub struct NtfsResidentAttributeValue<'f> {
    data: &'f [u8],
    position: NtfsPosition,
    stream_position: u64,
}

impl<'f> NtfsResidentAttributeValue<'f> {
    pub(crate) fn new(data: &'f [u8], position: NtfsPosition) -> Self {
        Self {
            data,
            position,
            stream_position: 0,
        }
    }

    /// Returns a slice of the entire value data.
    ///
    /// Remember that a resident attribute fits entirely inside the NTFS File Record
    /// of the requested file.
    /// Hence, the fixed up File Record is entirely in memory at this stage and a slice
    /// to a resident attribute value can be obtained easily.
    pub fn data(&self) -> &'f [u8] {
        self.data
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if the current seek position is outside the valid range.
    pub fn data_position(&self) -> NtfsPosition {
        if self.stream_position <= self.len() {
            self.position + self.stream_position
        } else {
            NtfsPosition::none()
        }
    }

    /// Returns `true` if the resident attribute value contains no data.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total length of the resident attribute value data, in bytes.
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn remaining_len(&self) -> u64 {
        self.len().saturating_sub(self.stream_position)
    }
}

impl<'f> NtfsReadSeek for NtfsResidentAttributeValue<'f> {
    fn read<T>(&mut self, _fs: &mut T, buf: &mut [u8]) -> Result<usize>
    where
        T: Read + Seek,
    {
        if self.remaining_len() == 0 {
            return Ok(0);
        }

        let bytes_to_read = usize::min(buf.len(), self.remaining_len() as usize);
        let work_slice = &mut buf[..bytes_to_read];

        let start = self.stream_position as usize;
        let end = start + bytes_to_read;
        work_slice.copy_from_slice(&self.data[start..end]);

        self.stream_position += bytes_to_read as u64;
        Ok(bytes_to_read)
    }

    fn seek<T>(&mut self, _fs: &mut T, pos: SeekFrom) -> Result<u64>
    where
        T: Read + Seek,
    {
        let length = self.len();
        seek_contiguous(&mut self.stream_position, length, pos)
    }

    fn stream_position(&self) -> u64 {
        self.stream_position
    }
}

#[cfg(test)]
mod tests {
    use binrw::io::SeekFrom;

    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;
    use crate::traits::NtfsReadSeek;

    #[test]
    fn test_read_and_seek() {
        let mut testfs1 = crate::helpers::tests::testfs1();
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "file-with-12345".
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "file-with-12345")
                .unwrap()
                .unwrap();
        let file = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Get its data attribute.
        let data_attribute_item = file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attribute = data_attribute_item.to_attribute().unwrap();
        assert!(data_attribute.is_resident());
        assert_eq!(data_attribute.value_length(), 5);

        let mut data_attribute_value = data_attribute.value(&mut testfs1).unwrap();
        assert_eq!(data_attribute_value.stream_position(), 0);
        assert_eq!(data_attribute_value.len(), 5);

        // TEST READING
        let data_position_before = data_attribute_value.data_position().value().unwrap();

        // We have a 6 bytes buffer, but the file is only 5 bytes long.
        // The last byte should be untouched.
        let mut buf = [0xCCu8; 6];
        let bytes_read = data_attribute_value.read(&mut testfs1, &mut buf).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(buf, [b'1', b'2', b'3', b'4', b'5', 0xCC]);

        // The internal position should have stopped directly after the last byte of the file,
        // and must also yield a valid data position.
        assert_eq!(data_attribute_value.stream_position(), 5);

        let data_position_after = data_attribute_value.data_position().value().unwrap();
        assert_eq!(
            data_position_after,
            data_position_before.checked_add(5).unwrap()
        );

        // TEST SEEKING
        // A seek to the beginning should yield the data position before the read.
        data_attribute_value
            .seek(&mut testfs1, SeekFrom::Start(0))
            .unwrap();
        assert_eq!(data_attribute_value.stream_position(), 0);
        assert_eq!(
            data_attribute_value.data_position().value().unwrap(),
            data_position_before
        );

        // A seek to one byte after the last read byte should yield the data position
        // after the read.
        data_attribute_value
            .seek(&mut testfs1, SeekFrom::Start(5))
            .unwrap();
        assert_eq!(data_attribute_value.stream_position(), 5);
        assert_eq!(
            data_attribute_value.data_position().value().unwrap(),
            data_position_after
        );

        // A seek beyond the size of the data must yield no valid data position.
        data_attribute_value
            .seek(&mut testfs1, SeekFrom::Start(6))
            .unwrap();
        assert_eq!(data_attribute_value.stream_position(), 6);
        assert_eq!(data_attribute_value.data_position().value(), None);
    }
}
