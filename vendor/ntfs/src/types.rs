// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Supplementary helper types.

use core::fmt;
use core::num::NonZeroU64;
use core::ops::{Add, AddAssign};

use binrw::BinRead;
use derive_more::{Binary, Display, From, LowerHex, Octal, UpperHex};

use crate::error::{NtfsError, Result};
use crate::ntfs::Ntfs;

/// An absolute nonzero byte position on the NTFS filesystem.
/// Can be used to seek, but even more often in [`NtfsError`] variants to assist with debugging.
///
/// Note that there may be cases when no valid position can be given for the current situation.
/// For example, this may happen when a reader is on a sparse Data Run or it has been seeked to a
/// position outside the valid range.
/// Therefore, this structure internally uses an [`Option`] of a [`NonZeroU64`] to alternatively
/// store a `None` value if no valid position can be given.
#[derive(Clone, Copy, Debug, Eq, From, Ord, PartialEq, PartialOrd)]
pub struct NtfsPosition(Option<NonZeroU64>);

impl NtfsPosition {
    const NONE_STR: &'static str = "<NONE>";

    pub(crate) const fn new(position: u64) -> Self {
        Self(NonZeroU64::new(position))
    }

    pub(crate) const fn none() -> Self {
        Self(None)
    }

    /// Returns the stored position, or `None` if there is no valid position.
    pub const fn value(&self) -> Option<NonZeroU64> {
        self.0
    }
}

impl Add<u16> for NtfsPosition {
    type Output = Self;

    fn add(self, other: u16) -> Self {
        self + other as u64
    }
}

impl Add<u64> for NtfsPosition {
    type Output = Self;

    fn add(self, other: u64) -> Self {
        let new_value = self
            .0
            .and_then(|position| NonZeroU64::new(position.get().wrapping_add(other)));
        Self(new_value)
    }
}

impl Add<usize> for NtfsPosition {
    type Output = Self;

    fn add(self, other: usize) -> Self {
        self + other as u64
    }
}

impl AddAssign<u16> for NtfsPosition {
    fn add_assign(&mut self, other: u16) {
        *self = *self + other;
    }
}

impl AddAssign<u64> for NtfsPosition {
    fn add_assign(&mut self, other: u64) {
        *self = *self + other;
    }
}

impl AddAssign<usize> for NtfsPosition {
    fn add_assign(&mut self, other: usize) {
        *self = *self + other;
    }
}

impl fmt::Binary for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::Binary::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl fmt::Display for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::Display::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl fmt::LowerHex for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::LowerHex::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl fmt::Octal for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::Octal::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl fmt::UpperHex for NtfsPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(position) => fmt::UpperHex::fmt(&position, f),
            None => fmt::Display::fmt(Self::NONE_STR, f),
        }
    }
}

impl From<NonZeroU64> for NtfsPosition {
    fn from(value: NonZeroU64) -> Self {
        Self(Some(value))
    }
}

/// A Logical Cluster Number (LCN).
///
/// NTFS divides a filesystem into clusters of a given size (power of two), see [`Ntfs::cluster_size`].
/// The LCN is an absolute cluster index into the filesystem.
#[derive(
    Binary,
    BinRead,
    Clone,
    Copy,
    Debug,
    Display,
    Eq,
    From,
    LowerHex,
    Octal,
    Ord,
    PartialEq,
    PartialOrd,
    UpperHex,
)]
pub struct Lcn(u64);

impl Lcn {
    /// Performs a checked addition of the given Virtual Cluster Number (VCN), returning a new LCN.
    pub fn checked_add(&self, vcn: Vcn) -> Option<Lcn> {
        if vcn.0 >= 0 {
            self.0.checked_add(vcn.0 as u64).map(Into::into)
        } else {
            self.0
                .checked_sub(vcn.0.wrapping_neg() as u64)
                .map(Into::into)
        }
    }

    /// Returns the absolute byte position of this LCN within the filesystem.
    pub fn position(&self, ntfs: &Ntfs) -> Result<NtfsPosition> {
        let value = self
            .0
            .checked_mul(ntfs.cluster_size() as u64)
            .ok_or(NtfsError::LcnTooBig { lcn: *self })?;
        Ok(NtfsPosition::new(value))
    }

    /// Returns the stored Logical Cluster Number.
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// A Virtual Cluster Number (VCN).
///
/// NTFS divides a filesystem into clusters of a given size (power of two), see [`Ntfs::cluster_size`].
/// The VCN is a cluster index into the filesystem that is relative to a Logical Cluster Number (LCN)
/// or relative to the start of an attribute value.
#[derive(
    Binary,
    BinRead,
    Clone,
    Copy,
    Debug,
    Display,
    Eq,
    From,
    LowerHex,
    Octal,
    Ord,
    PartialEq,
    PartialOrd,
    UpperHex,
)]
pub struct Vcn(i64);

impl Vcn {
    /// Converts this VCN into a byte offset (with respect to the cluster size of the provided [`Ntfs`] filesystem).
    pub fn offset(&self, ntfs: &Ntfs) -> Result<i64> {
        self.0
            .checked_mul(ntfs.cluster_size() as i64)
            .ok_or(NtfsError::VcnTooBig { vcn: *self })
    }

    /// Returns the stored Virtual Cluster Number.
    pub fn value(&self) -> i64 {
        self.0
    }
}
