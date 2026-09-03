//! Processes a Resource Map Section into a flat `index property ->
//! item` table.
//!
//! The item-to-iteminfo-group / iteminfo-group / iteminfo tables exist purely to
//! compress long runs of consecutively-increasing indices; the table-extension
//! block's `u32` entries extend the same three tables. Both are merged into a
//! single flat [`ResolvedItem`] per index property here, up front, so a later
//! lookup is a plain hash-map access instead of re-walking the group indirection
//! every time.

use std::collections::HashMap;

use bytes::Bytes;

use crate::resources::error::PriParseError;
use crate::resources::structs::{
    Candidate, ItemInfoEntry, ItemInfoEntryExt, ItemInfoGroupEntry, ItemInfoGroupEntryExt,
    ItemToItemInfoGroupEntry, ItemToItemInfoGroupEntryExt, ResourceMapHeader, ResourceValueType,
    ResourceValueTypeEntry, TableExtensionHeader,
};

use super::util::{Cursor, bytes_slice};

/// A single resolved resource candidate, with its data pinned down to either this
/// section's own embedded data block, a Data Item Section, or (for `source_file !=
/// 0`) a Data Item Section in another, externally-referenced PRI file.
#[derive(Debug, Clone)]
pub enum CandidateValue {
    Embedded {
        resource_value_type_index: u8,
        data: Bytes,
    },
    DataItem {
        resource_value_type_index: u8,
        section_index: u16,
        data_item_index: u16,
    },
    External {
        resource_value_type_index: u8,
        referenced_file_index: u16,
        section_index: u16,
        data_item_index: u16,
    },
    Unknown {
        candidate_type: u8,
    },
}

#[derive(Debug, Clone)]
pub struct ResolvedItem {
    pub decision_index: u32,
    pub first_candidate_index: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceMap {
    pub hierarchical_schema_section_index: u16,
    pub decision_info_section_index: u16,
    pub resource_value_types: Vec<ResourceValueType>,
    /// Keyed by index property (see [`super::schema`]) - sparse, since only items
    /// (never scopes) appear here.
    pub items: HashMap<u32, ResolvedItem>,
    /// All candidates, flat; a given item's candidates are the slice starting at
    /// its `first_candidate_index`, one per qualifier set of its decision (the
    /// count isn't stored here, since it's the associated
    /// [`super::decisions::Decision`]'s qualifier set count).
    pub candidates: Vec<CandidateValue>,
}

pub(crate) fn build(data: &Bytes) -> Result<ResourceMap, PriParseError> {
    let mut cursor = Cursor::new(data, 0);
    let header = cursor
        .read::<ResourceMapHeader>()
        .ok_or(PriParseError::truncated("resource map header"))?;

    // Environment references and the hierarchical schema reference block aren't
    // modeled yet - their contents are duplicated, for our purposes, by
    // `hierarchical_schema_section_index`/the Decision Info Section itself, so
    // it's enough to skip over them.
    cursor
        .take(header.environment_references_block_length as usize)
        .ok_or(PriParseError::truncated("environment references block"))?;
    cursor
        .take(header.hierarchical_schema_reference_block_length as usize)
        .ok_or(PriParseError::truncated(
            "hierarchical schema reference block",
        ))?;

    let resource_value_types = (0..header.resource_value_type_table_entries)
        .map(|_| {
            cursor
                .try_read::<ResourceValueTypeEntry>("resource value type entry")
                .map(|entry| entry.resource_value_type)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut item_to_group: Vec<(u32, u32)> = (0..header.item_to_iteminfo_group_table_entries)
        .map(|_| {
            cursor
                .read::<ItemToItemInfoGroupEntry>()
                .ok_or(PriParseError::truncated("item to iteminfo group entry"))
                .map(|e| {
                    (
                        e.first_item_index_property as u32,
                        e.iteminfo_group_index as u32,
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut groups: Vec<(u32, u32)> = (0..header.iteminfo_group_table_entries)
        .map(|_| {
            cursor
                .read::<ItemInfoGroupEntry>()
                .ok_or(PriParseError::truncated("iteminfo group entry"))
                .map(|e| (e.number_of_iteminfos as u32, e.first_iteminfo_index as u32))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut iteminfos: Vec<(u32, u32)> = (0..header.iteminfo_table_entries)
        .map(|_| {
            cursor
                .read::<ItemInfoEntry>()
                .ok_or(PriParseError::truncated("iteminfo entry"))
                .map(|e| (e.decision_index as u32, e.first_candidate_index as u32))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // The table extension block's 12-byte header is entirely omitted  when its declared length is zero
    let table_extension = if header.table_extension_block_length > 0 {
        cursor
            .read::<TableExtensionHeader>()
            .ok_or(PriParseError::truncated("table extension header"))?
    } else {
        TableExtensionHeader {
            additional_item_to_iteminfo_group_entries: 0,
            additional_iteminfo_group_entries: 0,
            additional_iteminfo_entries: 0,
        }
    };
    for _ in 0..table_extension.additional_item_to_iteminfo_group_entries {
        let e = cursor
            .read::<ItemToItemInfoGroupEntryExt>()
            .ok_or(PriParseError::truncated("item to iteminfo group ext entry"))?;
        item_to_group.push((e.first_item_index_property, e.iteminfo_group_index));
    }
    for _ in 0..table_extension.additional_iteminfo_group_entries {
        let e = cursor
            .read::<ItemInfoGroupEntryExt>()
            .ok_or(PriParseError::truncated("iteminfo group ext entry"))?;
        groups.push((e.number_of_iteminfos, e.first_iteminfo_index));
    }
    for _ in 0..table_extension.additional_iteminfo_entries {
        let e = cursor
            .read::<ItemInfoEntryExt>()
            .ok_or(PriParseError::truncated("iteminfo ext entry"))?;
        iteminfos.push((e.decision_index, e.first_candidate_index));
    }

    let candidate_entries = (0..header.number_of_candidates)
        .map(|_| {
            cursor
                .read::<Candidate>()
                .ok_or(PriParseError::truncated("candidate"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let embedded_data = cursor.take_bytes(
        header.embedded_data_block_length as usize,
        "embedded data block",
    )?;

    let candidates = candidate_entries
        .into_iter()
        .map(|c| resolve_candidate(c, &embedded_data))
        .collect::<Result<Vec<_>, _>>()?;

    let mut items = HashMap::new();
    for (first_index_property, group_index) in item_to_group {
        let group_index = group_index as usize;
        // A group index at or beyond the group table encodes a group of exactly one
        // iteminfo, at index `group_index - groups.len()`.
        let (count, first_iteminfo_index) = if group_index >= groups.len() {
            (1u32, (group_index - groups.len()) as u32)
        } else {
            groups[group_index]
        };

        for offset in 0..count {
            let index_property = first_index_property + offset;
            let iteminfo_index = (first_iteminfo_index + offset) as usize;
            let &(decision_index, first_candidate_index) = iteminfos
                .get(iteminfo_index)
                .ok_or(PriParseError::truncated("iteminfo group's iteminfo index"))?;
            items.insert(
                index_property,
                ResolvedItem {
                    decision_index,
                    first_candidate_index,
                },
            );
        }
    }

    Ok(ResourceMap {
        hierarchical_schema_section_index: header.hierarchical_schema_section_index,
        decision_info_section_index: header.decision_info_section_index,
        resource_value_types,
        items,
        candidates,
    })
}

fn resolve_candidate(
    candidate: Candidate,
    embedded_data: &Bytes,
) -> Result<CandidateValue, PriParseError> {
    Ok(match candidate {
        Candidate::Embedded {
            resource_value_type_index,
            embedded_data_length,
            embedded_data_offset,
        } => CandidateValue::Embedded {
            resource_value_type_index,
            data: bytes_slice(
                embedded_data,
                embedded_data_offset as usize,
                embedded_data_length as usize,
                "embedded candidate data",
            )?,
        },
        Candidate::Referenced {
            resource_value_type_index,
            source_file: 0,
            data_item_index,
            data_item_section_index,
        } => CandidateValue::DataItem {
            resource_value_type_index,
            section_index: data_item_section_index,
            data_item_index,
        },
        Candidate::Referenced {
            resource_value_type_index,
            source_file,
            data_item_index,
            data_item_section_index,
        } => CandidateValue::External {
            resource_value_type_index,
            referenced_file_index: source_file - 1,
            section_index: data_item_section_index,
            data_item_index,
        },
        Candidate::Unknown { candidate_type, .. } => CandidateValue::Unknown { candidate_type },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal Resource Map Section with no environment references, a
    /// hierarchical schema/decision info pair, one resource value type, a single
    /// item (index property 20) resolved through the general group table, and one
    /// item (index property 99) resolved through the table extension's `u32`
    /// tables - each with two candidates (one embedded string, one data-item ref).
    fn sample_section() -> Bytes {
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(&0u16.to_le_bytes()); // env refs block length
        data.extend_from_slice(&0u16.to_le_bytes()); // env refs count
        data.extend_from_slice(&5u16.to_le_bytes()); // hierarchical schema section index
        data.extend_from_slice(&0u16.to_le_bytes()); // hschema ref block length
        data.extend_from_slice(&7u16.to_le_bytes()); // decision info section index
        data.extend_from_slice(&1u16.to_le_bytes()); // resource value type table entries
        data.extend_from_slice(&1u16.to_le_bytes()); // item to iteminfo group entries
        data.extend_from_slice(&1u16.to_le_bytes()); // iteminfo group entries
        data.extend_from_slice(&1u32.to_le_bytes()); // iteminfo table entries
        data.extend_from_slice(&4u32.to_le_bytes()); // number of candidates
        data.extend_from_slice(&4u32.to_le_bytes()); // embedded data block length ("hi\0\0" -> just 2 bytes needed, pad to 4)
        // Table extension block length: 12 (header) + 8 (one item-to-group ext
        // entry) + 8 (one iteminfo ext entry) = 28. A length of zero would mean the
        // block - including its header - is omitted entirely (see `build`'s
        // handling of `table_extension_block_length`).
        data.extend_from_slice(&28u32.to_le_bytes());

        // Resource value type table: unknown=4, resource_value_type=String(0)
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        // Item to iteminfo group table: first_item_index_property=20, group_index=0
        data.extend_from_slice(&20u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        // Iteminfo group table: number_of_iteminfos=1, first_iteminfo_index=0
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        // Iteminfo table: decision_index=0, first_candidate_index=0
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        // Table extension header: 1 additional item-to-group, 0 additional groups,
        // 1 additional iteminfo
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());

        // Additional item-to-group entry: index_property=99, group_index=2. Since
        // groups.len() == 1, this is >= the group table's length, so it encodes a
        // single-iteminfo group at iteminfo index `2 - 1 = 1` - the additional
        // iteminfo entry below, appended right after the base iteminfo table.
        data.extend_from_slice(&99u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());

        // Additional iteminfo entry (index 1 overall): decision_index=0,
        // first_candidate_index=2
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());

        // Candidates:
        // 0: embedded, resource_value_type_index=0, length=2, offset=0
        data.push(0);
        data.push(0);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        // 1: referenced (same file), resource_value_type_index=0, source_file=0,
        // data_item_index=3, section_index=9
        data.push(1);
        data.push(0);
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&9u16.to_le_bytes());
        // 2: embedded, resource_value_type_index=0, length=2, offset=2
        data.push(0);
        data.push(0);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        // 3: referenced (external), resource_value_type_index=0, source_file=2
        // (referenced file index 1), data_item_index=4, section_index=9
        data.push(1);
        data.push(0);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&9u16.to_le_bytes());

        // Embedded data block: "hi" then "yo" (as raw bytes, 2 candidates x 2 bytes)
        data.extend_from_slice(b"hiyo");

        Bytes::from(data)
    }

    #[test]
    fn test_build_resolves_group_and_extended_items() {
        let map = build(&sample_section()).unwrap();

        assert_eq!(map.hierarchical_schema_section_index, 5);
        assert_eq!(map.decision_info_section_index, 7);
        assert_eq!(map.candidates.len(), 4);

        let item = map
            .items
            .get(&20)
            .expect("index property 20 via group table");
        assert_eq!(item.decision_index, 0);
        assert_eq!(item.first_candidate_index, 0);

        let extended_item = map
            .items
            .get(&99)
            .expect("index property 99 via table extension");
        assert_eq!(extended_item.first_candidate_index, 2);

        match &map.candidates[0] {
            CandidateValue::Embedded { data, .. } => assert_eq!(data.as_ref(), b"hi"),
            other => panic!("expected embedded candidate, got {other:?}"),
        }
        match &map.candidates[1] {
            CandidateValue::DataItem {
                section_index,
                data_item_index,
                ..
            } => {
                assert_eq!(*section_index, 9);
                assert_eq!(*data_item_index, 3);
            }
            other => panic!("expected data item candidate, got {other:?}"),
        }
        match &map.candidates[3] {
            CandidateValue::External {
                referenced_file_index,
                ..
            } => assert_eq!(*referenced_file_index, 1),
            other => panic!("expected external candidate, got {other:?}"),
        }
    }
}
