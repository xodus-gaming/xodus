// Copyright 2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! A low-level NTFS filesystem library implemented in Rust.
//!
//! [NTFS](https://en.wikipedia.org/wiki/NTFS) is the primary filesystem in all versions of Windows (since Windows NT 3.1 in 1993).
//! This crate is geared towards the NTFS 3.x versions used in Windows 2000 up to the current Windows 11.
//! However, the basics are expected to be compatible to even earlier versions.
//!
//! The crate is `no_std`-compatible and therefore usable from firmware level code up to user-mode applications.
//!
//! # Getting started
//! 1. Create an [`Ntfs`] structure from a reader by calling [`Ntfs::new`].
//! 2. Retrieve the [`NtfsFile`] of the root directory via [`Ntfs::root_directory`].
//! 3. Dig into its attributes via [`NtfsFile::attributes`], go even deeper via [`NtfsFile::attributes_raw`] or use one of the convenience functions, like [`NtfsFile::directory_index`], [`NtfsFile::info`] or [`NtfsFile::name`].
//!
//! # Example
//! The following example dumps the names of all files and folders in the root directory of a given NTFS filesystem.  
//! The list is directly taken from the NTFS index, hence it's sorted in ascending order with respect to NTFS's understanding of case-insensitive string comparison.
//!
//! ```ignore
//! let mut ntfs = Ntfs::new(&mut fs).unwrap();
//! let root_dir = ntfs.root_directory(&mut fs).unwrap();
//! let index = root_dir.directory_index(&mut fs).unwrap();
//! let mut iter = index.entries();
//!
//! while let Some(entry) = iter.next(&mut fs) {
//!     let entry = entry.unwrap();
//!     let file_name = entry.key().unwrap();
//!     println!("{}", file_name.name());
//! }
//! ```
//!
//! Check out the [docs](https://docs.rs/ntfs), the tests, and the supplied [`ntfs-shell`](https://github.com/ColinFinck/ntfs/tree/master/examples/ntfs-shell) application for more examples on how to use the `ntfs` library.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;

#[macro_use]
mod helpers;

mod attribute;
pub mod attribute_value;
mod boot_sector;
mod error;
mod file;
mod file_reference;
mod guid;
mod index;
mod index_entry;
mod index_record;
pub mod indexes;
mod ntfs;
mod record;
pub mod structured_values;
mod time;
mod traits;
pub mod types;
mod upcase_table;

pub use crate::attribute::*;
pub use crate::error::*;
pub use crate::file::*;
pub use crate::file_reference::*;
pub use crate::guid::*;
pub use crate::index::*;
pub use crate::index_entry::*;
pub use crate::index_record::*;
pub use crate::ntfs::*;
pub use crate::time::*;
pub use crate::traits::*;
pub use crate::upcase_table::*;
