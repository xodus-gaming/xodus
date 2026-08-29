use std::ops::{Add, Sub};

pub const PAGE_SIZE: usize = 0x1000;
pub const BLOCK_SIZE: usize = 0xAA000;
pub const SECTOR_SIZE: usize = 4096;
pub const LEGACY_SECTOR_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pages(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(pub u64);

impl Pages {
    /// Returns the number of bytes that this many pages span.
    pub fn to_bytes(self) -> Bytes {
        Bytes(self.0 * PAGE_SIZE as u64)
    }
}

impl Bytes {
    /// Returns whether the byte offset is page-aligned or not.
    pub fn is_page_aligned(self) -> bool {
        self.0.is_multiple_of(PAGE_SIZE as u64)
    }

    /// Returns the index of the page to which the byte offset belongs.
    pub fn to_page_index(self) -> Pages {
        Pages(self.0 / PAGE_SIZE as u64)
    }

    /// Returns the number of pages that this many bytes span.
    pub fn to_page_count(self) -> Pages {
        Pages(self.0.div_ceil(PAGE_SIZE as u64))
    }

    /// If the byte offset is page-aligned then returns its page index, else
    /// returns `None`.
    pub fn to_page_index_aligned(self) -> Option<Pages> {
        self.is_page_aligned().then(|| self.to_page_index())
    }
}

impl Add<Pages> for Pages {
    type Output = Pages;

    fn add(self, rhs: Pages) -> Self::Output {
        Pages(self.0 + rhs.0)
    }
}

impl Add<Bytes> for Bytes {
    type Output = Bytes;

    fn add(self, rhs: Bytes) -> Self::Output {
        Bytes(self.0 + rhs.0)
    }
}

impl Sub<Pages> for Pages {
    type Output = Pages;

    fn sub(self, rhs: Pages) -> Self::Output {
        Pages(self.0 - rhs.0)
    }
}

impl Sub<Bytes> for Bytes {
    type Output = Bytes;

    fn sub(self, rhs: Bytes) -> Self::Output {
        Bytes(self.0 - rhs.0)
    }
}
