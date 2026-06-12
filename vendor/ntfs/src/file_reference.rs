// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use binrw::io::{Read, Seek};
use binrw::BinRead;

use crate::error::Result;
use crate::file::NtfsFile;
use crate::ntfs::Ntfs;

/// Absolute reference to a File Record on the filesystem, composed out of a File Record Number and a Sequence Number.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/file_reference.html>
#[derive(BinRead, Clone, Copy, Debug)]
pub struct NtfsFileReference([u8; 8]);

impl NtfsFileReference {
    pub(crate) const fn new(file_reference_bytes: [u8; 8]) -> Self {
        Self(file_reference_bytes)
    }

    /// Returns the 48-bit File Record Number.
    ///
    /// This can be fed into [`Ntfs::file`] to create an [`NtfsFile`] object for the corresponding File Record
    /// (if you cannot use [`Self::to_file`] for some reason).
    pub fn file_record_number(&self) -> u64 {
        u64::from_le_bytes(self.0) & 0xffff_ffff_ffff
    }

    /// Returns the 16-bit sequence number of the File Record.
    ///
    /// In a consistent file system, this number matches what [`NtfsFile::sequence_number`] returns.
    pub fn sequence_number(&self) -> u16 {
        (u64::from_le_bytes(self.0) >> 48) as u16
    }

    /// Returns an [`NtfsFile`] for the file referenced by this object.
    pub fn to_file<'n, T>(&self, ntfs: &'n Ntfs, fs: &mut T) -> Result<NtfsFile<'n>>
    where
        T: Read + Seek,
    {
        ntfs.file(fs, self.file_record_number())
    }
}
