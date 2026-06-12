// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Various types of NTFS Attribute structured values.

mod attribute_list;
mod file_name;
mod index_allocation;
mod index_root;
mod object_id;
mod standard_information;
mod volume_information;
mod volume_name;

use core::fmt;

pub use attribute_list::*;
pub use file_name::*;
pub use index_allocation::*;
pub use index_root::*;
pub use object_id::*;
pub use standard_information::*;
pub use volume_information::*;
pub use volume_name::*;

use binrw::io::{Read, Seek};
use bitflags::bitflags;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::Result;

bitflags! {
    /// Flags that a user can set for a file (Read-Only, Hidden, System, Archive, etc.).
    /// Commonly called "File Attributes" in Windows Explorer.
    ///
    /// Not to be confused with [`NtfsAttribute`].
    ///
    /// Returned by [`NtfsStandardInformation::file_attributes`] and [`NtfsFileName::file_attributes`].
    ///
    /// [`NtfsAttribute`]: crate::attribute::NtfsAttribute
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsFileAttributeFlags: u32 {
        /// File is marked read-only.
        const READ_ONLY = 0x0001;
        /// File is hidden (in file browsers that care).
        const HIDDEN = 0x0002;
        /// File is marked as a system file.
        const SYSTEM = 0x0004;
        /// File is marked for archival (cf. <https://en.wikipedia.org/wiki/Archive_bit>).
        const ARCHIVE = 0x0020;
        /// File denotes a device.
        const DEVICE = 0x0040;
        /// Set when no other attributes are set.
        const NORMAL = 0x0080;
        /// File is a temporary file that is likely to be deleted.
        const TEMPORARY = 0x0100;
        /// File is stored sparsely.
        const SPARSE_FILE = 0x0200;
        /// File is a reparse point.
        const REPARSE_POINT = 0x0400;
        /// File is transparently compressed by the filesystem (using LZNT1 algorithm).
        /// For directories, this attribute denotes that compression is enabled by default for new files inside that directory.
        const COMPRESSED = 0x0800;
        const OFFLINE = 0x1000;
        /// File has not (yet) been indexed by the Windows Indexing Service.
        const NOT_CONTENT_INDEXED = 0x2000;
        /// File is encrypted via EFS.
        /// For directories, this attribute denotes that encryption is enabled by default for new files inside that directory.
        const ENCRYPTED = 0x4000;
        /// File is a directory.
        ///
        /// This attribute is only returned from [`NtfsFileName::file_attributes`].
        const IS_DIRECTORY = 0x1000_0000;
    }
}

impl fmt::Display for NtfsFileAttributeFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Trait implemented by every NTFS attribute structured value.
pub trait NtfsStructuredValue<'n, 'f>: Sized {
    const TY: NtfsAttributeType;

    /// Create a structured value from an arbitrary `NtfsAttributeValue`.
    fn from_attribute_value<T>(fs: &mut T, value: NtfsAttributeValue<'n, 'f>) -> Result<Self>
    where
        T: Read + Seek;
}

/// Trait implemented by NTFS Attribute structured values that are always in resident attributes.
pub trait NtfsStructuredValueFromResidentAttributeValue<'n, 'f>:
    NtfsStructuredValue<'n, 'f>
{
    /// Create a structured value from a resident attribute value.
    ///
    /// This is a fast path for the few structured values that are always in resident attributes.
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self>;
}
