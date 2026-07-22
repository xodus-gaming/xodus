use super::RegionDecryptor;
use crate::models::xvd::PAGE_SIZE;

use std::cmp::Ordering;
use std::range::Range;

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Region<Units> {
    pages: Range<u64>,
    decryptor: Option<RegionDecryptor<Units>>,
}

#[derive(Debug, Error)]
pub enum NewRegionError {
    #[error("region page range is inverted: {0:?}")]
    InvalidPageRange(Range<u64>),

    #[error("expected {expected} data units to match page count, found {found}")]
    InvalidDataUnitCount { expected: u64, found: u64 },
}

impl<Units> Region<Units>
where
    Units: AsRef<[u32]>,
{
    pub fn new(
        pages: Range<u64>,
        decryptor: Option<RegionDecryptor<Units>>,
    ) -> Result<Self, NewRegionError> {
        // Make sure the range makes sense.
        if pages.end < pages.start {
            return Err(NewRegionError::InvalidPageRange(pages));
        }

        let num_pages = pages.end - pages.start;

        // If the decryptor provides data units, make sure there is one data unit for each page.
        if let Some(dec) = &decryptor
            && let data_units @ 1.. = dec.data_units.as_ref().len() as u64
            && data_units != num_pages
        {
            return Err(NewRegionError::InvalidDataUnitCount {
                expected: num_pages,
                found: data_units,
            });
        }

        Ok(Self { pages, decryptor })
    }

    pub fn decrypt_at(&self, absolute_page_index: u64, page: &mut [u8; PAGE_SIZE]) {
        let Some(dec) = &self.decryptor else {
            return;
        };

        let page_in_region = absolute_page_index - self.pages.start;
        dec.decrypt_at(page_in_region as usize, page);
    }
}

#[derive(Clone, Debug)]
pub struct RegionTable<Units> {
    /// List of each region: the indices of the pages it spans and its decryptor (if encrypted).
    regions: Vec<Region<Units>>,

    /// The range of pages this region table spans in total. `self.pages.start` doesn't
    /// need to be 0. The value is precomputed from `regions` in order to avoid having to
    /// calculate it on every read.
    pages: Range<u64>,

    /// The number of bytes this region table spans in total. The value is precomputed
    /// from `regions` in order to avoid having to calculate it on every read.
    reader_len: u64,
}

#[derive(Debug, Error)]
#[error("all regions must be consecutive")]
pub struct NonConsecutiveRegionsError<Units>(Vec<Region<Units>>);

impl<Units> RegionTable<Units>
where
    Units: AsRef<[u32]>,
{
    pub fn new(regions: Vec<Region<Units>>) -> Result<Self, NonConsecutiveRegionsError<Units>> {
        // All regions must be consecutive.
        if regions
            .array_windows()
            .any(|[curr, next]| curr.pages.end != next.pages.start)
        {
            return Err(NonConsecutiveRegionsError(regions));
        };

        // Precompute the values that are frequently read into the struct for cheaper access.

        let pages = Range::from(
            regions.first().map(|r| r.pages.start).unwrap_or_default()
                ..regions.last().map(|r| r.pages.end).unwrap_or_default(),
        );

        let reader_len = (pages.end - pages.start) * PAGE_SIZE as u64;

        Ok(Self {
            regions,
            pages,
            reader_len,
        })
    }
}

impl<Units> TryFrom<Vec<Region<Units>>> for RegionTable<Units>
where
    Units: AsRef<[u32]>,
{
    type Error = NonConsecutiveRegionsError<Units>;

    fn try_from(value: Vec<Region<Units>>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<Units> RegionTable<Units> {
    #[inline]
    pub fn pages(&self) -> Range<u64> {
        self.pages
    }

    #[inline]
    pub fn reader_len(&self) -> u64 {
        self.reader_len
    }

    #[inline]
    pub fn region_at(&self, page: u64) -> &Region<Units> {
        assert!(self.pages.contains(&page));

        &self.regions[self
            .regions
            .binary_search_by(|r| match page {
                p if p < r.pages.start => Ordering::Greater,
                p if p >= r.pages.end => Ordering::Less,
                _ => Ordering::Equal,
            })
            .expect("page must be in some region")]
    }
}
