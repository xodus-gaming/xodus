// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cmp::Ordering;
use core::marker::PhantomData;

use alloc::vec;
use alloc::vec::Vec;
use binrw::io::{Read, Seek};

use crate::attribute::{NtfsAttributeItem, NtfsAttributeType};
use crate::error::{NtfsError, Result};
use crate::index_entry::{
    IndexEntryRange, IndexNodeEntryRanges, NtfsIndexEntry, NtfsIndexEntryFlags,
};
use crate::indexes::NtfsIndexEntryType;
use crate::structured_values::{NtfsIndexAllocation, NtfsIndexRoot};
use crate::types::NtfsPosition;

/// Helper structure to iterate over all entries of an index or find a specific one.
///
/// The `E` type parameter of [`NtfsIndexEntryType`] specifies the type of the index entries.
/// The most common one is [`NtfsFileNameIndex`] for file name indexes, commonly known as "directories".
/// Check out [`NtfsFile::directory_index`] to return an [`NtfsIndex`] object for a directory without
/// any hassles.
///
/// [`NtfsFile::directory_index`]: crate::NtfsFile::directory_index
/// [`NtfsFileNameIndex`]: crate::indexes::NtfsFileNameIndex
#[derive(Clone, Debug)]
pub struct NtfsIndex<'n, 'f, E>
where
    E: NtfsIndexEntryType,
{
    index_record_size: u32,
    index_root_entry_ranges: IndexNodeEntryRanges<E>,
    index_root_position: NtfsPosition,
    index_allocation_item: Option<NtfsAttributeItem<'n, 'f>>,
    entry_type: PhantomData<E>,
}

impl<'n, 'f, E> NtfsIndex<'n, 'f, E>
where
    E: NtfsIndexEntryType,
{
    /// Creates a new [`NtfsIndex`] object from a previously looked up [`NtfsIndexRoot`] attribute
    /// (contained in an [`NtfsAttributeItem`]) and, in case of a large index, a matching
    /// [`NtfsIndexAllocation`] attribute (also contained in an [`NtfsAttributeItem`]).
    ///
    /// If you just want to look up files in a directory, check out [`NtfsFile::directory_index`],
    /// which looks up the correct [`NtfsIndexRoot`] and [`NtfsIndexAllocation`] attributes for you.
    ///
    /// [`NtfsFile::directory_index`]: crate::NtfsFile::directory_index
    pub fn new(
        index_root_item: NtfsAttributeItem<'n, 'f>,
        index_allocation_item: Option<NtfsAttributeItem<'n, 'f>>,
    ) -> Result<Self> {
        let index_root_attribute = index_root_item.to_attribute()?;
        index_root_attribute.ensure_ty(NtfsAttributeType::IndexRoot)?;
        let index_root = index_root_attribute.resident_structured_value::<NtfsIndexRoot>()?;

        if let Some(item) = &index_allocation_item {
            let attribute = item.to_attribute()?;
            attribute.ensure_ty(NtfsAttributeType::IndexAllocation)?;
        } else if index_root.is_large_index() {
            return Err(NtfsError::MissingIndexAllocation {
                position: index_root.position(),
            });
        }

        let index_record_size = index_root.index_record_size();
        let index_root_entry_ranges = index_root.entry_ranges();
        let index_root_position = index_root.position();
        let entry_type = PhantomData;

        Ok(Self {
            index_record_size,
            index_root_entry_ranges,
            index_root_position,
            index_allocation_item,
            entry_type,
        })
    }

    /// Returns an [`NtfsIndexEntries`] iterator to perform an in-order traversal of this index.
    pub fn entries<'i>(&'i self) -> NtfsIndexEntries<'n, 'f, 'i, E> {
        NtfsIndexEntries::new(self)
    }

    /// Returns an [`NtfsIndexFinder`] structure to efficiently find an entry in this index.
    pub fn finder<'i>(&'i self) -> NtfsIndexFinder<'n, 'f, 'i, E> {
        NtfsIndexFinder::new(self)
    }
}

/// Iterator over
///   all index entries of an index,
///   sorted ascending by the index key,
///   returning an [`NtfsIndexEntry`] for each entry.
///
/// This iterator is returned from the [`NtfsIndex::entries`] function.
#[derive(Clone, Debug)]
pub struct NtfsIndexEntries<'n, 'f, 'i, E>
where
    E: NtfsIndexEntryType,
{
    index: &'i NtfsIndex<'n, 'f, E>,
    inner_iterators: Vec<IndexNodeEntryRanges<E>>,
    following_entries: Vec<Option<IndexEntryRange<E>>>,
}

impl<'n, 'f, 'i, E> NtfsIndexEntries<'n, 'f, 'i, E>
where
    E: NtfsIndexEntryType,
{
    fn new(index: &'i NtfsIndex<'n, 'f, E>) -> Self {
        let inner_iterators = vec![index.index_root_entry_ranges.clone()];
        let following_entries = Vec::new();

        Self {
            index,
            inner_iterators,
            following_entries,
        }
    }

    /// See [`Iterator::next`].
    pub fn next<'a, T>(&'a mut self, fs: &mut T) -> Option<Result<NtfsIndexEntry<'a, E>>>
    where
        T: Read + Seek,
    {
        // NTFS B-tree indexes are composed out of nodes, with multiple entries per node.
        // Each entry may have a reference to a subnode.
        // If that is the case, the subnode entries comes before the parent entry lexicographically.
        //
        // An example for an unbalanced, but otherwise valid and sorted tree:
        //
        //                                   -------------
        // INDEX ROOT NODE:                  | 4 | 5 | 6 |
        //                                   -------------
        //                                     |
        //                                 ---------
        // INDEX ALLOCATION SUBNODE:       | 1 | 3 |
        //                                 ---------
        //                                       |
        //                                     -----
        // INDEX ALLOCATION SUBNODE:           | 2 |
        //                                     -----
        //
        let entry_range = loop {
            // Get the iterator from the current node level, if any.
            let iter = self.inner_iterators.last_mut()?;

            // Get the next `IndexEntryRange` from it.
            if let Some(entry_range) = iter.next() {
                let entry_range = iter_try!(entry_range);

                // Convert that `IndexEntryRange` to a (lifetime-bound) `NtfsIndexEntry`.
                let entry = iter_try!(entry_range.to_entry(iter.data()));
                let is_last_entry = entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY);

                // Does this entry have a subnode that needs to be iterated first?
                if let Some(subnode_vcn) = entry.subnode_vcn() {
                    let subnode_vcn = iter_try!(subnode_vcn);

                    // Read the subnode from the filesystem and get an iterator for it.
                    let index_allocation_item =
                        iter_try!(self.index.index_allocation_item.as_ref().ok_or(
                            NtfsError::MissingIndexAllocation {
                                position: self.index.index_root_position,
                            }
                        ));
                    let index_allocation_attribute =
                        iter_try!(index_allocation_item.to_attribute());
                    let index_allocation =
                        iter_try!(index_allocation_attribute
                            .structured_value::<_, NtfsIndexAllocation>(fs));

                    let subnode = iter_try!(index_allocation.record_from_vcn(
                        fs,
                        self.index.index_record_size,
                        subnode_vcn
                    ));
                    let subnode_iter = subnode.into_entry_ranges();

                    let following_entry = if !is_last_entry {
                        // This entry comes after the subnode lexicographically, so save it.
                        // We'll pick it up again after the subnode iterator has been fully iterated.
                        Some(entry_range)
                    } else {
                        None
                    };

                    // Save this subnode's iterator and any following entry.
                    // We'll pick up the iterator through `self.inner_iterators.last_mut()` in the next loop iteration.
                    self.inner_iterators.push(subnode_iter);
                    self.following_entries.push(following_entry);
                } else if !is_last_entry {
                    // There is no subnode, and this is not the empty "last entry",
                    // so our entry comes next lexicographically.
                    break entry_range;
                }
            } else {
                // The iterator for this subnode level has been fully iterated.
                // Drop it.
                self.inner_iterators.pop();

                // The entry, whose subnode we just fully iterated, may have been saved in `following_entries`.
                // This depends on its `is_last_entry` flag:
                //   * If it was not the last entry, it contains an entry that comes next lexicographically,
                //     and has therefore been saved in `following_entries`.
                //   * If it was the last entry, it contains no further information.
                //     `None` has been saved in `following_entries`, so that `following_entries.len()` always
                //     matches `inner_iterators.len() - 1`.
                //
                // If we just finished iterating the root-level node, `following_entries` is empty and we are done.
                // Otherwise, we can be sure that `inner_iterators.last()` is the matching iterator for converting
                // `IndexEntryRange` to a (lifetime-bound) `NtfsIndexEntry`.
                if let Some(entry_range) = self.following_entries.pop()? {
                    break entry_range;
                }
            }
        };

        let iter = self.inner_iterators.last().unwrap();
        let entry = iter_try!(entry_range.to_entry(iter.data()));

        Some(Ok(entry))
    }
}

/// Helper structure to efficiently find an entry in an index, created by [`NtfsIndex::finder`].
///
/// This helper is required, because the returned entry borrows from the iterator it was created from.
/// The idea is that you copy the field(s) you need from the returned entry and then drop the entry and the finder.
pub struct NtfsIndexFinder<'n, 'f, 'i, E>
where
    E: NtfsIndexEntryType,
{
    index: &'i NtfsIndex<'n, 'f, E>,
    inner_iterator: IndexNodeEntryRanges<E>,
}

impl<'n, 'f, 'i, E> NtfsIndexFinder<'n, 'f, 'i, E>
where
    E: NtfsIndexEntryType,
{
    fn new(index: &'i NtfsIndex<'n, 'f, E>) -> Self {
        // This is superfluous and done again in `find`, but doesn't justify using an `Option` here.
        let inner_iterator = index.index_root_entry_ranges.clone();

        Self {
            index,
            inner_iterator,
        }
    }

    /// Finds an entry in this index using the given comparison function and returns an [`NtfsIndexEntry`]
    /// (if there is one).
    pub fn find<'a, T, F>(&'a mut self, fs: &mut T, cmp: F) -> Option<Result<NtfsIndexEntry<'a, E>>>
    where
        T: Read + Seek,
        F: Fn(&E::KeyType) -> Ordering,
    {
        // Always (re)start by iterating through the Index Root entry ranges.
        self.inner_iterator = self.index.index_root_entry_ranges.clone();

        loop {
            // Get the next entry.
            //
            // A textbook B-tree search algorithm would get the middle entry and perform binary search.
            // But we can't do that here, as we are dealing with variable-length entries.
            let entry_range = iter_try!(self.inner_iterator.next()?);
            let entry = iter_try!(entry_range.to_entry(self.inner_iterator.data()));

            // Check if this entry has a key.
            if let Some(key) = entry.key() {
                // The entry has a key, so compare it using the given function.
                let key = iter_try!(key);

                match cmp(&key) {
                    Ordering::Equal => {
                        // We found what we were looking for!
                        // Recreate `entry` from the last `self.inner_iterator` to please the borrow checker.
                        let entry = iter_try!(entry_range.to_entry(self.inner_iterator.data()));
                        return Some(Ok(entry));
                    }
                    Ordering::Less => {
                        // What we are looking for comes BEFORE this entry.
                        // Hence, it must be in a subnode of this entry and we continue below.
                    }
                    Ordering::Greater => {
                        // What we are looking for comes AFTER this entry.
                        // Keep searching on the same subnode level.
                        continue;
                    }
                }
            }

            // Either this entry has no key (= is the last one on this subnode level) or
            // it comes lexicographically AFTER what we're looking for.
            // In both cases, we have to continue iterating in the subnode of this entry (if there is any).
            let subnode_vcn = iter_try!(entry.subnode_vcn()?);
            let index_allocation_item = iter_try!(self.index.index_allocation_item.as_ref().ok_or(
                NtfsError::MissingIndexAllocation {
                    position: self.index.index_root_position,
                }
            ));
            let index_allocation_attribute = iter_try!(index_allocation_item.to_attribute());
            let index_allocation = iter_try!(
                index_allocation_attribute.structured_value::<_, NtfsIndexAllocation>(fs)
            );

            let subnode = iter_try!(index_allocation.record_from_vcn(
                fs,
                self.index.index_record_size,
                subnode_vcn
            ));
            self.inner_iterator = subnode.into_entry_ranges();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;

    #[test]
    fn test_index_find() {
        let mut testfs1 = crate::helpers::tests::testfs1();
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "many_subdirs" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "many_subdirs")
                .unwrap()
                .unwrap();
        let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Prove that we can find all 512 indexed subdirectories.
        let subdir_index = subdir.directory_index(&mut testfs1).unwrap();
        let mut subdir_finder = subdir_index.finder();

        for i in 1..=512 {
            let dir_name = format!("{i}");
            let entry = NtfsFileNameIndex::find(&mut subdir_finder, &ntfs, &mut testfs1, &dir_name)
                .unwrap()
                .unwrap();
            let entry_name = entry.key().unwrap().unwrap();
            assert_eq!(entry_name.name(), dir_name.as_str());
        }
    }

    #[test]
    fn test_index_iter() {
        let mut testfs1 = crate::helpers::tests::testfs1();
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "many_subdirs" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "many_subdirs")
                .unwrap()
                .unwrap();
        let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Prove that we can iterate through all 512 indexed subdirectories in order.
        // Keep in mind that subdirectories are ordered like "1", "10", "100", "101", ...
        // We can create the same order by adding them to a vector and sorting that vector.
        let mut dir_names = Vec::with_capacity(512);
        for i in 1..=512 {
            dir_names.push(format!("{i}"));
        }

        dir_names.sort_unstable();

        let subdir_index = subdir.directory_index(&mut testfs1).unwrap();
        let mut subdir_iter = subdir_index.entries();

        for dir_name in dir_names {
            let entry = subdir_iter.next(&mut testfs1).unwrap().unwrap();
            let entry_name = entry.key().unwrap().unwrap();
            assert_eq!(entry_name.name(), dir_name.as_str());
        }

        assert!(subdir_iter.next(&mut testfs1).is_none());
    }
}
