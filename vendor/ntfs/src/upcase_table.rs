// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cmp::Ordering;
use core::mem;

use alloc::vec;
use alloc::vec::Vec;
use binrw::io::{Read, Seek};
use nt_string::u16strle::U16StrLe;

use crate::attribute::NtfsAttributeType;
use crate::error::{NtfsError, Result};
use crate::file::KnownNtfsFileRecordNumber;
use crate::ntfs::Ntfs;
use crate::traits::NtfsReadSeek;

/// The Upcase Table contains an uppercase character for each Unicode character of the Basic Multilingual Plane.
const UPCASE_CHARACTER_COUNT: usize = 65536;

/// Hence, the table has a size of 128 KiB.
const UPCASE_TABLE_SIZE: u64 = (UPCASE_CHARACTER_COUNT * mem::size_of::<u16>()) as u64;

/// Manages a table for converting characters to uppercase.
/// This table is used for case-insensitive file name comparisons.
///
/// NTFS stores such a table in the special $UpCase file on every filesystem.
/// As this table is slightly different depending on the Windows version used for creating the filesystem,
/// it is very important to always read the table from the filesystem itself.
/// Hence, this table is not hardcoded into the crate.
#[derive(Clone, Debug)]
pub(crate) struct UpcaseTable {
    uppercase_characters: Vec<u16>,
}

impl UpcaseTable {
    /// Reads the $UpCase file from the given filesystem into a new [`UpcaseTable`] object.
    pub(crate) fn read<T>(ntfs: &Ntfs, fs: &mut T) -> Result<Self>
    where
        T: Read + Seek,
    {
        // Lookup the $UpCase file and its $DATA attribute.
        let upcase_file = ntfs.file(fs, KnownNtfsFileRecordNumber::UpCase as u64)?;
        let data_item = upcase_file
            .data(fs, "")
            .ok_or(NtfsError::AttributeNotFound {
                position: upcase_file.position(),
                ty: NtfsAttributeType::Data,
            })??;

        let data_attribute = data_item.to_attribute()?;
        if data_attribute.value_length() != UPCASE_TABLE_SIZE {
            return Err(NtfsError::InvalidUpcaseTableSize {
                expected: UPCASE_TABLE_SIZE,
                actual: data_attribute.value_length(),
            });
        }

        // Read the entire raw data from the $DATA attribute.
        let mut data_value = data_attribute.value(fs)?;
        let mut data = vec![0u8; UPCASE_TABLE_SIZE as usize];
        data_value.read_exact(fs, &mut data)?;

        // Store it in an array of `u16` uppercase characters.
        // Any endianness conversion is done here once, which makes `u16_to_uppercase` fast.
        let uppercase_characters = data
            .chunks_exact(2)
            .map(|two_bytes| u16::from_le_bytes(two_bytes.try_into().unwrap()))
            .collect();

        Ok(Self {
            uppercase_characters,
        })
    }

    /// Returns the uppercase variant of the given UCS-2 character (i.e. a Unicode character
    /// from the Basic Multilingual Plane) based on the stored conversion table.
    /// A character without an uppercase equivalent is returned as-is.
    pub(crate) fn u16_to_uppercase(&self, character: u16) -> u16 {
        self.uppercase_characters[character as usize]
    }
}

/// Trait for a case-insensitive ordering with respect to the $UpCase table read from the filesystem.
pub trait UpcaseOrd<Rhs> {
    /// Performs a case-insensitive ordering based on the $UpCase table read from the filesystem.
    ///
    /// # Panics
    ///
    /// Panics if [`read_upcase_table`][Ntfs::read_upcase_table] had not been called on the passed [`Ntfs`] object.
    fn upcase_cmp(&self, ntfs: &Ntfs, other: &Rhs) -> Ordering;
}

impl<'a, 'b> UpcaseOrd<U16StrLe<'a>> for U16StrLe<'b> {
    fn upcase_cmp(&self, ntfs: &Ntfs, other: &U16StrLe<'a>) -> Ordering {
        upcase_cmp_iter(self.u16_iter(), other.u16_iter(), ntfs)
    }
}

impl<'a> UpcaseOrd<&str> for U16StrLe<'a> {
    fn upcase_cmp(&self, ntfs: &Ntfs, other: &&str) -> Ordering {
        upcase_cmp_iter(self.u16_iter(), other.encode_utf16(), ntfs)
    }
}

impl<'a> UpcaseOrd<U16StrLe<'a>> for &str {
    fn upcase_cmp(&self, ntfs: &Ntfs, other: &U16StrLe<'a>) -> Ordering {
        upcase_cmp_iter(self.encode_utf16(), other.u16_iter(), ntfs)
    }
}

fn upcase_cmp_iter<TI, OI>(mut this_iter: TI, mut other_iter: OI, ntfs: &Ntfs) -> Ordering
where
    TI: Iterator<Item = u16>,
    OI: Iterator<Item = u16>,
{
    let upcase_table = ntfs.upcase_table();

    loop {
        match (this_iter.next(), other_iter.next()) {
            (Some(this_code_unit), Some(other_code_unit)) => {
                // We have two UTF-16 code units to compare.
                let this_upper = upcase_table.u16_to_uppercase(this_code_unit);
                let other_upper = upcase_table.u16_to_uppercase(other_code_unit);

                if this_upper != other_upper {
                    return this_upper.cmp(&other_upper);
                }
            }
            (Some(_), None) => {
                // `this_iter` is longer than `other_iter` but otherwise equal.
                return Ordering::Greater;
            }
            (None, Some(_)) => {
                // `other_iter` is longer than `this_iter` but otherwise equal.
                return Ordering::Less;
            }
            (None, None) => {
                // We made it to the end of both strings, so they must be equal.
                return Ordering::Equal;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upcase_table() {
        let mut testfs1 = crate::helpers::tests::testfs1();
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let upcase_table = UpcaseTable::read(&ntfs, &mut testfs1).unwrap();

        // Prove that at least the lowercase English characters are mapped to their uppercase equivalents.
        // It makes no sense to check everything here.
        for (lowercase, uppercase) in (b'a'..=b'z').zip(b'A'..=b'Z') {
            assert_eq!(
                upcase_table.u16_to_uppercase(lowercase as u16),
                uppercase as u16
            );
        }
    }
}
