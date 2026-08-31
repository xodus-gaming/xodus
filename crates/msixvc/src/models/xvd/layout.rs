use super::XvdHeader;
use crate::layout::{Bytes, PAGE_SIZE, Pages};

use std::cmp;
use std::iter::FusedIterator;
use std::range::Range;

pub const HASH_ENTRY_LENGTH: usize = 0x18;
pub const HASH_ENTRIES_IN_PAGE: u32 = (PAGE_SIZE / HASH_ENTRY_LENGTH) as u32;

/// Maximum number of pages that the hash tree may cover.
pub const MAX_HASHED_PAGES: Pages = Pages(HASH_ENTRIES_IN_PAGE.pow(4));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XvdSection {
    pub start: Pages,
    pub len: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XvdLayout {
    // It is guaranteed that no sections overlap.
    header: XvdSection,
    embedded_xvd: XvdSection,
    mutable_data: XvdSection,
    hash_tree: (XvdSection, HashTreeLayout),
    user_data: XvdSection,
    xvc_info: XvdSection,
    dynamic_header: XvdSection,
    drive_data: XvdSection,
}

impl XvdHeader {
    pub fn number_of_hashed_pages(&self) -> Pages {
        self.user_data_length.to_page_count()
            + self.xvc_data_length.to_page_count()
            + self.dynamic_header_length.to_page_count()
            + self.drive_size.to_page_count()
    }

    pub fn layout(&self) -> XvdLayout {
        let mut current_page = Pages(0);
        let mut next_section = |len: Bytes| -> XvdSection {
            let section = XvdSection {
                start: current_page,
                len,
            };
            current_page += len.to_page_count();
            section
        };

        // Calculate the layout of the hash tree first because it's the only
        // section whose length can't be accessed directly, but has to be
        // calculated.
        let hash_tree_layout = HashTreeLayout::new(self.number_of_hashed_pages());

        let header_section = next_section(Bytes(PAGE_SIZE as u64 * 3));
        let embedded_xvd = next_section(self.embedded_xvd_length);
        let mutable_data = next_section(self.mutable_page_count.to_bytes());
        let hash_tree = next_section(hash_tree_layout.pages().to_bytes());
        let user_data = next_section(self.user_data_length);
        let xvc_info = next_section(self.xvc_data_length);
        let dynamic_header = next_section(self.dynamic_header_length);
        let drive_data = next_section(self.drive_size);

        XvdLayout {
            header: header_section,
            embedded_xvd,
            mutable_data,
            hash_tree: (hash_tree, hash_tree_layout),
            user_data,
            xvc_info,
            dynamic_header,
            drive_data,
        }
    }
}

impl XvdLayout {
    #[inline]
    pub fn header(&self) -> XvdSection {
        self.header
    }

    #[inline]
    pub fn embedded_xvd(&self) -> XvdSection {
        self.embedded_xvd
    }

    #[inline]
    pub fn mutable_data(&self) -> XvdSection {
        self.mutable_data
    }

    #[inline]
    pub fn hash_tree(&self) -> (XvdSection, HashTreeLayout) {
        self.hash_tree
    }

    #[inline]
    pub fn user_data(&self) -> XvdSection {
        self.user_data
    }

    #[inline]
    pub fn xvc_info(&self) -> XvdSection {
        self.xvc_info
    }

    #[inline]
    pub fn dynamic_header(&self) -> XvdSection {
        self.dynamic_header
    }

    #[inline]
    pub fn drive_data(&self) -> XvdSection {
        self.drive_data
    }
}

/// The layout of a hash tree level.
///
/// Each hash tree level contains the hashes of the pages of the level below it.
/// For the level 0 it contains the hashes of the pages of the drive data.
///
/// Because the size of each hash entry (24 bytes) is not divisible by
/// `PAGE_SIZE`, the last 16 bytes of each page are zeroes. For that reason,
/// not all the hashes in the same level are consecutive, but stored in "runs".
/// The number of hash entries in each "run" can be retrieved via
/// [`Self::hash_entry_runs`]. See [`HashTreeLevelRunIterator`] for more
/// information on how to parse the runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashTreeLevel {
    /// Range of pages that this tree level occupies, relative to the start of
    /// the hash tree.
    page_range: Range<Pages>,
    /// The number of hash entries stored in this hash tree level, which is
    /// equal to the number of pages that the hash tree level covers.
    ///
    /// The possible values for `num_hashes` are:
    /// - For level 0: `1..` (the level 0 hash tree must contain at least one
    ///   hash entry).
    /// - For levels 1-3: `0` or `2..` (the other levels can't contain only one
    ///   hash entry, because when there's only one entry it goes in the header
    ///   instead).
    num_hashes: Pages,
}

impl HashTreeLevel {
    #[inline]
    pub fn page_range(&self) -> Range<Pages> {
        self.page_range
    }

    /// The number of pages that this hash tree level occupies.
    #[inline]
    pub fn num_pages(&self) -> Pages {
        self.page_range.end - self.page_range.start
    }

    /// The number of hash entries stored in this hash tree level. It's equal
    /// to the number of pages covered by this hash tree level.
    #[inline]
    pub fn num_hashes(&self) -> Pages {
        self.num_hashes
    }

    /// Returns an iterator over the "runs" of entries that this hash tree
    /// level contains.
    ///
    /// See [`HashTreeLevelRunIterator`].
    #[inline]
    pub fn hash_entry_runs(&self) -> HashTreeLevelRunIterator {
        HashTreeLevelRunIterator {
            num_hashes: self.num_hashes.0,
        }
    }
}

/// An iterator over the number of hash entries in each run of hashes for this
/// hash tree level.
///
/// After reading [`Self::next`] hash entries from the page, the remaining bytes
/// of the page must be discarded (16 bytes if the page is full of hash entries,
/// or more if it's the last run).
#[derive(Debug, PartialEq, Eq)]
pub struct HashTreeLevelRunIterator {
    num_hashes: u32,
}

impl Iterator for HashTreeLevelRunIterator {
    // `u8` is enough because he maximum run length (`HASH_ENTRIES_IN_PAGE`) is
    // less than `u8::MAX`
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.num_hashes == 0 {
            return None;
        }

        let run_hashes = cmp::min(self.num_hashes, HASH_ENTRIES_IN_PAGE);
        self.num_hashes -= run_hashes;
        Some(run_hashes as u8)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let runs = self.num_hashes.div_ceil(HASH_ENTRIES_IN_PAGE) as usize;
        (runs, Some(runs))
    }
}

impl FusedIterator for HashTreeLevelRunIterator {}
impl ExactSizeIterator for HashTreeLevelRunIterator {}

/// Calculates how many hash entries are stored in the hash tree level, if the
/// level covers `hashed_pages` many pages.
///
/// It returns its input unchanged unless `hashed_pages` is 1, then returns 0,
/// as the hash would be stored in the XVD header instead.
fn stored_hashes(hashed_pages: Pages) -> Pages {
    // If the level only covers one page, its hash is stored directly in the
    // header instead of the hash tree.
    if hashed_pages == Pages(1) {
        Pages(0)
    } else {
        hashed_pages
    }
}

/// Calculates how many pages the hash tree level occupies, given the number of
/// pages it covers.
fn hash_tree_level_pages(hashed_pages: Pages) -> Pages {
    let num_hashes = stored_hashes(hashed_pages).0;
    Pages(num_hashes.div_ceil(HASH_ENTRIES_IN_PAGE))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashTreeLayout {
    level3: HashTreeLevel,
    level2: HashTreeLevel,
    level1: HashTreeLevel,
    level0: HashTreeLevel,
}

impl HashTreeLayout {
    /// `drive_data_pages` must be in the range `1..MAX_HASHED_PAGES`.
    fn new(drive_data_pages: Pages) -> HashTreeLayout {
        assert!(drive_data_pages > Pages(0));
        assert!(drive_data_pages <= MAX_HASHED_PAGES);

        // The level 0 hash tree must always exist, even when there's a single drive data page.
        let level0_pages = cmp::max(hash_tree_level_pages(drive_data_pages), Pages(1));
        let level1_pages = hash_tree_level_pages(level0_pages);
        let level2_pages = hash_tree_level_pages(level1_pages);
        let level3_pages = hash_tree_level_pages(level2_pages);

        // The level 3 hash tree level must be at most one page long.
        assert!(level3_pages.0 <= 1);

        // Compute the start, number of pages and number of hashes of each level.

        fn range(start: Pages, length: Pages) -> Range<Pages> {
            Range::from(start..start + length)
        }

        let level3 = HashTreeLevel {
            page_range: range(Pages(0), level3_pages),
            num_hashes: stored_hashes(level2_pages),
        };

        let level2 = HashTreeLevel {
            page_range: range(level3.page_range.end, level2_pages),
            num_hashes: stored_hashes(level1_pages),
        };

        let level1 = HashTreeLevel {
            page_range: range(level2.page_range.end, level1_pages),
            num_hashes: stored_hashes(level0_pages),
        };

        let level0 = HashTreeLevel {
            page_range: range(level1.page_range.end, level0_pages),
            // Don't use `stored_hashes` here, as the level 0 hash tree always
            // contains at least one entry.
            num_hashes: drive_data_pages,
        };

        HashTreeLayout {
            level3,
            level2,
            level1,
            level0,
        }
    }

    /// Returns the length of the hash tree section (in `Pages`).
    #[inline]
    pub fn pages(&self) -> Pages {
        self.level0.page_range.end
    }

    #[inline]
    pub fn level3(&self) -> HashTreeLevel {
        self.level3
    }

    #[inline]
    pub fn level2(&self) -> HashTreeLevel {
        self.level2
    }

    #[inline]
    pub fn level1(&self) -> HashTreeLevel {
        self.level1
    }

    #[inline]
    pub fn level0(&self) -> HashTreeLevel {
        self.level0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_level(level: HashTreeLevel, len: Pages, num_hashes: Pages) {
        assert_eq!(level.num_pages(), len);
        assert_eq!(level.num_hashes, num_hashes);
    }

    fn assert_empty_level(level: HashTreeLevel) {
        assert_level(level, Pages(0), Pages(0));
    }

    #[test]
    #[should_panic]
    fn test_empty() {
        HashTreeLayout::new(Pages(0));
    }

    #[test]
    #[should_panic]
    fn test_overflow() {
        HashTreeLayout::new(MAX_HASHED_PAGES + Pages(1));
    }

    #[test]
    fn test_single_hashed_page() {
        // Even when there's a single hashed page, the level 0 tree level
        // must contain an entry.
        let layout = HashTreeLayout::new(Pages(1));
        assert_empty_level(layout.level3);
        assert_empty_level(layout.level2);
        assert_empty_level(layout.level1);
        assert_level(layout.level0, Pages(1), Pages(1));
    }

    #[test]
    fn test_level0_boundary() {
        // While there's less than `HASH_ENTRIES_IN_PAGE` pages, it fits within
        // a single level 0 page, so the level 1 hash tree is not needed.
        let layout = HashTreeLayout::new(Pages(HASH_ENTRIES_IN_PAGE));
        assert_empty_level(layout.level3);
        assert_empty_level(layout.level2);
        assert_empty_level(layout.level1);
        assert_level(layout.level0, Pages(1), Pages(HASH_ENTRIES_IN_PAGE));

        // If there's more than `HASH_ENTRIES_IN_PAGE` pages, it won't fit
        // within a single level 0 page.
        let layout = HashTreeLayout::new(Pages(HASH_ENTRIES_IN_PAGE + 1));
        assert_empty_level(layout.level3);
        assert_empty_level(layout.level2);

        // The level 1 hash tree must be 1 page long and contain 2 hashes (one
        // for each level 0 page).
        assert_level(layout.level1, Pages(1), Pages(2));

        // The level 0 hash tree must be 2 pages long.
        assert_level(layout.level0, Pages(2), Pages(HASH_ENTRIES_IN_PAGE + 1));
    }

    #[test]
    fn test_level1_boundary() {
        let layout = HashTreeLayout::new(Pages(HASH_ENTRIES_IN_PAGE.pow(2)));
        assert_empty_level(layout.level3);
        assert_empty_level(layout.level2);
        assert_level(layout.level1, Pages(1), Pages(HASH_ENTRIES_IN_PAGE));
        assert_level(
            layout.level0,
            Pages(HASH_ENTRIES_IN_PAGE),
            Pages(HASH_ENTRIES_IN_PAGE.pow(2)),
        );

        let layout = HashTreeLayout::new(Pages(HASH_ENTRIES_IN_PAGE.pow(2) + 1));
        assert_empty_level(layout.level3);
        assert_level(layout.level2, Pages(1), Pages(2));
        assert_level(layout.level1, Pages(2), Pages(HASH_ENTRIES_IN_PAGE + 1));
        assert_level(
            layout.level0,
            Pages(HASH_ENTRIES_IN_PAGE + 1),
            Pages(HASH_ENTRIES_IN_PAGE.pow(2) + 1),
        );
    }

    #[test]
    fn test_level2_boundary() {
        let layout = HashTreeLayout::new(Pages(HASH_ENTRIES_IN_PAGE.pow(3)));
        assert_empty_level(layout.level3);
        assert_level(layout.level2, Pages(1), Pages(HASH_ENTRIES_IN_PAGE));
        assert_level(
            layout.level1,
            Pages(HASH_ENTRIES_IN_PAGE),
            Pages(HASH_ENTRIES_IN_PAGE.pow(2)),
        );
        assert_level(
            layout.level0,
            Pages(HASH_ENTRIES_IN_PAGE.pow(2)),
            Pages(HASH_ENTRIES_IN_PAGE.pow(3)),
        );

        let layout = HashTreeLayout::new(Pages(HASH_ENTRIES_IN_PAGE.pow(3) + 1));
        assert_level(layout.level3, Pages(1), Pages(2));
        assert_level(layout.level2, Pages(2), Pages(HASH_ENTRIES_IN_PAGE + 1));
        assert_level(
            layout.level1,
            Pages(HASH_ENTRIES_IN_PAGE + 1),
            Pages(HASH_ENTRIES_IN_PAGE.pow(2) + 1),
        );
        assert_level(
            layout.level0,
            Pages(HASH_ENTRIES_IN_PAGE.pow(2) + 1),
            Pages(HASH_ENTRIES_IN_PAGE.pow(3) + 1),
        );
    }

    #[test]
    fn test_max() {
        let layout = HashTreeLayout::new(MAX_HASHED_PAGES);
        assert_level(layout.level3, Pages(1), Pages(HASH_ENTRIES_IN_PAGE));
        assert_level(
            layout.level2,
            Pages(HASH_ENTRIES_IN_PAGE),
            Pages(HASH_ENTRIES_IN_PAGE.pow(2)),
        );
        assert_level(
            layout.level1,
            Pages(HASH_ENTRIES_IN_PAGE.pow(2)),
            Pages(HASH_ENTRIES_IN_PAGE.pow(3)),
        );
        assert_level(
            layout.level0,
            Pages(HASH_ENTRIES_IN_PAGE.pow(3)),
            Pages(HASH_ENTRIES_IN_PAGE.pow(4)),
        );
    }
}
