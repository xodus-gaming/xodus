use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Sub};

use msixvc_common::parse::byteorder::{Be, Le};
use msixvc_common::parse::{BinaryParse, BytesReader, EmptyReader};

pub const PAGE_SIZE: usize = 0x1000;
pub const BLOCK_SIZE: usize = 0xAA000;
pub const SECTOR_SIZE: usize = 4096;
pub const LEGACY_SECTOR_SIZE: usize = 512;

pub const PAGES_PER_BLOCK: usize = BLOCK_SIZE / PAGE_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pages(
    /// `u32` is enough to store every possible page index:
    ///
    /// `u32::MAX` = 4_294_967_295 pages (about 17.6 TiB)
    ///
    /// Also, the hash tree can have at up to 4 levels, each one with at most
    /// 170 entries (`PAGE_SIZE` / 24), so in total the hash tree can cover only
    /// 170^4 = 835_210_000 pages (about 3.11TiB).
    pub u32,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(
    /// `u64` is needed in order to store every possible byte index, as
    /// `u32::MAX` = 4_294_967_295 bytes (about 4.29 GiB), way below the maximum
    /// package size threshold.
    ///
    /// Any value over `(u32::MAX as u64) * (PAGE_SIZE as u64)` is invalid in
    /// order to guarantee that every `Bytes` can be indexed by its corresponding
    /// `Page`.
    pub u64,
);

impl Pages {
    /// Returns the number of bytes that this many pages span.
    pub const fn to_bytes(self) -> Bytes {
        Bytes((self.0 as u64) * PAGE_SIZE as u64)
    }
}

impl Bytes {
    /// Returns whether the byte offset is page-aligned or not.
    pub const fn is_page_aligned(self) -> bool {
        self.0.is_multiple_of(PAGE_SIZE as u64)
    }

    /// Returns the index of the page to which the byte offset belongs.
    pub const fn to_page_index(self) -> Pages {
        Pages((self.0 / PAGE_SIZE as u64) as u32)
    }

    /// Returns the number of pages that this many bytes span.
    pub const fn to_page_count(self) -> Pages {
        Pages(self.0.div_ceil(PAGE_SIZE as u64) as u32)
    }

    /// If the byte offset is page-aligned then returns its page index, else
    /// returns `None`.
    pub const fn to_page_index_aligned(self) -> Option<Pages> {
        if self.is_page_aligned() {
            Some(self.to_page_index())
        } else {
            None
        }
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

impl AddAssign for Pages {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl AddAssign for Bytes {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
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

/// Marker type for parsing integers through [`BinaryParse`] into a [`Pages`].
pub struct PagesParse<T>(PhantomData<T>);

/// Marker type for parsing integers through [`BinaryParse`] into a [`Bytes`].
pub struct BytesParse<T>(PhantomData<T>);

macro_rules! impl_pages_parse {
    ($int:ty) => {
        impl BinaryParse for PagesParse<$int> {
            type Output = Pages;
            type Size = <$int as BinaryParse>::Size;

            #[inline]
            fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Pages, EmptyReader<'a>) {
                let (n, r) = r.read::<$int>();
                (Pages(u32::from(n)), r)
            }
        }
    };
}

macro_rules! impl_bytes_parse {
    ($int:ty) => {
        impl BinaryParse for BytesParse<$int> {
            type Output = Bytes;
            type Size = <$int as BinaryParse>::Size;

            #[inline]
            fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Bytes, EmptyReader<'a>) {
                let (n, r) = r.read::<$int>();
                (Bytes(u64::from(n)), r)
            }
        }
    };
}

impl_pages_parse!(u8);
impl_pages_parse!(Le<u16>);
impl_pages_parse!(Be<u16>);
impl_pages_parse!(Le<u32>);
impl_pages_parse!(Be<u32>);

impl_bytes_parse!(u8);
impl_bytes_parse!(Le<u16>);
impl_bytes_parse!(Be<u16>);
impl_bytes_parse!(Le<u32>);
impl_bytes_parse!(Be<u32>);
impl_bytes_parse!(Le<u64>);
impl_bytes_parse!(Be<u64>);
