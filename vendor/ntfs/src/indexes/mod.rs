// Copyright 2021-2022 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Various types of NTFS indexes and traits to work with them.
//!
//! Thanks to Rust's typesystem, the traits make using the various types of NTFS indexes (and their distinct key
//! and data types) possible in a typesafe way.
//!
//! NTFS uses B-tree indexes to quickly look up files, Object IDs, Reparse Points, Security Descriptors, etc.
//! They are described via [`NtfsIndexRoot`] and [`NtfsIndexAllocation`] attributes, which can be comfortably
//! accessed via [`NtfsIndex`].
//!
//! [`NtfsIndex`]: crate::NtfsIndex
//! [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
//! [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot

mod file_name;

pub use file_name::*;

use core::fmt;

use crate::error::Result;
use crate::types::NtfsPosition;

/// Trait implemented by structures that describe Index Entry types.
///
/// See also [`NtfsIndex`] and [`NtfsIndexEntry`], and [`NtfsFileNameIndex`] for the most popular Index Entry type.
///
/// [`NtfsFileNameIndex`]: crate::indexes::NtfsFileNameIndex
/// [`NtfsIndex`]: crate::NtfsIndex
/// [`NtfsIndexEntry`]: crate::NtfsIndexEntry
pub trait NtfsIndexEntryType: Clone + fmt::Debug {
    type KeyType: NtfsIndexEntryKey;
}

/// Trait implemented by a structure that describes an Index Entry key.
pub trait NtfsIndexEntryKey: fmt::Debug + Sized {
    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self>;
}

/// Indicates that the Index Entry type has additional data (of [`NtfsIndexEntryData`] datatype).
///
/// This trait and [`NtfsIndexEntryHasFileReference`] are mutually exclusive.
// TODO: Use negative trait bounds of future Rust to enforce mutual exclusion.
pub trait NtfsIndexEntryHasData: NtfsIndexEntryType {
    type DataType: NtfsIndexEntryData;
}

/// Trait implemented by a structure that describes Index Entry data.
pub trait NtfsIndexEntryData: fmt::Debug + Sized {
    fn data_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self>;
}

/// Indicates that the Index Entry type has a file reference.
///
/// This trait and [`NtfsIndexEntryHasData`] are mutually exclusive.
// TODO: Use negative trait bounds of future Rust to enforce mutual exclusion.
pub trait NtfsIndexEntryHasFileReference: NtfsIndexEntryType {}
