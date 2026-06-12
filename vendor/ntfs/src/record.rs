// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem;

use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};
use memoffset::{offset_of, span_of};

use crate::error::{NtfsError, Result};
use crate::types::NtfsPosition;

const NTFS_BLOCK_SIZE: usize = 512;

#[repr(C, packed)]
pub(crate) struct RecordHeader {
    signature: [u8; 4],
    update_sequence_offset: u16,
    update_sequence_count: u16,
    logfile_sequence_number: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct Record {
    data: Vec<u8>,
    position: NtfsPosition,
}

impl Record {
    pub(crate) fn new(data: Vec<u8>, position: NtfsPosition) -> Self {
        Self { data, position }
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn fixup(&mut self) -> Result<()> {
        let update_sequence_number = self.update_sequence_number()?;
        let array_count = self.update_sequence_array_count()?;

        let mut array_position = self.update_sequence_array_start() as usize;
        let array_end =
            self.update_sequence_offset() as usize + self.update_sequence_size() as usize;
        let sectors_end = array_count as usize * NTFS_BLOCK_SIZE;

        if array_end > self.data.len() || sectors_end > self.data.len() {
            return Err(NtfsError::UpdateSequenceArrayExceedsRecordSize {
                position: self.position,
                array_count,
                record_size: self.data.len(),
            });
        }

        // The Update Sequence Number (USN) is written to the last 2 bytes of each sector.
        let mut sector_position = NTFS_BLOCK_SIZE - mem::size_of::<u16>();

        while array_position < array_end {
            let array_position_end = array_position + mem::size_of::<u16>();
            let sector_position_end = sector_position + mem::size_of::<u16>();

            // The array contains the actual 2 bytes that need to be at `sector_position` after the fixup.
            let new_bytes: [u8; 2] = self.data[array_position..array_position_end]
                .try_into()
                .unwrap();

            // The current 2 bytes at `sector_position` before the fixup should equal the Update Sequence Number (USN).
            // Otherwise, this sector is corrupted.
            let bytes_to_update = &mut self.data[sector_position..sector_position_end];
            if bytes_to_update != update_sequence_number {
                return Err(NtfsError::UpdateSequenceNumberMismatch {
                    position: self.position + array_position,
                    expected: update_sequence_number,
                    actual: (&*bytes_to_update).try_into().unwrap(),
                });
            }

            // Perform the actual fixup.
            bytes_to_update.copy_from_slice(&new_bytes);

            // Advance to the next array entry and sector.
            array_position += mem::size_of::<u16>();
            sector_position += NTFS_BLOCK_SIZE;
        }

        Ok(())
    }

    pub(crate) fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub(crate) fn len(&self) -> u32 {
        // A record is never larger than a u32.
        // Usually, it shouldn't even exceed a u16, but our code could handle that.
        self.data.len() as u32
    }

    pub(crate) fn position(&self) -> NtfsPosition {
        self.position
    }

    pub(crate) fn signature(&self) -> [u8; 4] {
        self.data[span_of!(RecordHeader, signature)]
            .try_into()
            .unwrap()
    }

    fn update_sequence_array_count(&self) -> Result<u16> {
        let start = offset_of!(RecordHeader, update_sequence_count);
        let update_sequence_count = LittleEndian::read_u16(&self.data[start..]);

        // Subtract the Update Sequence Number (USN) element, so that only the number of array elements remains.
        update_sequence_count
            .checked_sub(1)
            .ok_or(NtfsError::InvalidUpdateSequenceCount {
                position: self.position,
                update_sequence_count,
            })
    }

    fn update_sequence_array_start(&self) -> u16 {
        // The Update Sequence Number (USN) comes first and the array begins right after that.
        self.update_sequence_offset() + mem::size_of::<u16>() as u16
    }

    fn update_sequence_number(&self) -> Result<[u8; 2]> {
        let start = self.update_sequence_offset() as usize;
        let end = start + mem::size_of::<u16>();
        self.data
            .get(start..end)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(NtfsError::InvalidUpdateSequenceNumberRange {
                position: self.position,
                range: start..end,
                size: self.data.len(),
            })
    }

    fn update_sequence_offset(&self) -> u16 {
        let start = offset_of!(RecordHeader, update_sequence_offset);
        LittleEndian::read_u16(&self.data[start..])
    }

    pub(crate) fn update_sequence_size(&self) -> u32 {
        let start = offset_of!(RecordHeader, update_sequence_count);
        let update_sequence_count = LittleEndian::read_u16(&self.data[start..]);
        update_sequence_count as u32 * mem::size_of::<u16>() as u32
    }
}
