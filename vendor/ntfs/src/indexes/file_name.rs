// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use binrw::io::{Read, Seek};

use crate::error::Result;
use crate::index::NtfsIndexFinder;
use crate::index_entry::NtfsIndexEntry;
use crate::indexes::{NtfsIndexEntryHasFileReference, NtfsIndexEntryType};
use crate::ntfs::Ntfs;
use crate::structured_values::NtfsFileName;
use crate::upcase_table::UpcaseOrd;

/// Defines the [`NtfsIndexEntryType`] for filename indexes (commonly known as "directories").
#[derive(Clone, Copy, Debug)]
pub struct NtfsFileNameIndex;

impl NtfsFileNameIndex {
    /// Finds a file in a filename index by name and returns the [`NtfsIndexEntry`] (if any).
    /// The name is compared case-insensitively based on the filesystem's $UpCase table.
    ///
    /// # Panics
    ///
    /// Panics if [`read_upcase_table`][Ntfs::read_upcase_table] had not been called on the passed [`Ntfs`] object.
    pub fn find<'a, T>(
        index_finder: &'a mut NtfsIndexFinder<Self>,
        ntfs: &Ntfs,
        fs: &mut T,
        name: &str,
    ) -> Option<Result<NtfsIndexEntry<'a, Self>>>
    where
        T: Read + Seek,
    {
        // TODO: This always performs a case-insensitive comparison.
        // There are some corner cases where NTFS uses case-sensitive filenames. These need to be considered!
        index_finder.find(fs, |file_name| name.upcase_cmp(ntfs, &file_name.name()))
    }
}

impl NtfsIndexEntryType for NtfsFileNameIndex {
    type KeyType = NtfsFileName;
}

impl NtfsIndexEntryHasFileReference for NtfsFileNameIndex {}
