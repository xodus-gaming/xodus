//! Utility for parsing and navigating the Package Resource Index.
//!
//! Resolving a single resource candidate can involve jumping between the
//! Hierarchical Schema Section, a Decision Info Section, a Resource Map Section
//! and a Data Item Section - sections aren't consumable in one sequential pass -
//! so [`Pri::read`] buffers the whole stream into memory once and builds a
//! [`PriIndex`] up front. Every subsequent [`Pri::resolve`] call is then a handful
//! of hash-map lookups against that index, never touching the raw tables again.

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::parse::{BinaryParse, BinaryTryParse};
use crate::resources::error::PriParseError;
use crate::resources::index::PriIndex;
use crate::resources::index::util::{Cursor, bytes_slice, slice_range};
use crate::resources::query::{QualifierContext, ResolvedValue};
use crate::resources::structs::{
    PriDescriptor, ResourceHeader, SectionFooter, SectionHeader, SectionType, TableOfContentsEntry,
};

/// A parsed Package Resource Index file, ready to be queried repeatedly via
/// [`Pri::resolve`].
pub struct Pri {
    index: PriIndex,
}

/// A table of contents entry alongside its section's data, addressable by the
/// section index used throughout the format (the position of its entry in the
/// table of contents).
pub(crate) struct SectionTable {
    entries: Vec<TableOfContentsEntry>,
    data: Vec<Bytes>,
}

impl SectionTable {
    pub(crate) fn get(&self, index: u16) -> Result<(&TableOfContentsEntry, &Bytes), PriParseError> {
        match (
            self.entries.get(index as usize),
            self.data.get(index as usize),
        ) {
            (Some(entry), Some(data)) => Ok((entry, data)),
            _ => Err(PriParseError::MissingSection(index)),
        }
    }
}

/// The section index arrays following a `PriDescriptor`'s fixed fields - the
/// variable-size part of the PRI Descriptor Section that the main parser owns.
#[derive(Debug, Default)]
pub(crate) struct DescriptorSectionIndices {
    pub(crate) hierarchical_schema: Vec<u16>,
    pub(crate) decision_info: Vec<u16>,
    pub(crate) resource_map: Vec<u16>,
    // Referenced File Section resolution is deferred - kept here so the descriptor's
    // section-index arrays are parsed in full, even though nothing reads it yet.
    #[allow(dead_code)]
    pub(crate) referenced_file: Vec<u16>,
    pub(crate) data_item: Vec<u16>,
}

impl Pri {
    pub async fn read<R: AsyncRead + Unpin>(mut r: R) -> Result<Self, PriParseError> {
        let mut buffer = Vec::new();
        r.read_to_end(&mut buffer).await?;
        let buffer = Bytes::from(buffer);

        let header = ResourceHeader::try_from_slice(
            slice_range(&buffer, 0, ResourceHeader::SIZE)
                .ok_or(PriParseError::truncated("resource header"))?,
        )?;

        let mut offset = header.table_of_contents_offset as usize;
        let mut entries = Vec::with_capacity(header.number_of_sections as usize);
        for _ in 0..header.number_of_sections {
            let entry = TableOfContentsEntry::from_slice(
                slice_range(&buffer, offset, TableOfContentsEntry::SIZE)
                    .ok_or(PriParseError::truncated("table of contents entry"))?,
            );
            offset += TableOfContentsEntry::SIZE;
            entries.push(entry);
        }

        let mut data = Vec::with_capacity(entries.len());
        for entry in &entries {
            data.push(section_data(&buffer, header.first_section_offset, entry)?);
        }
        let sections = SectionTable { entries, data };

        let descriptor_index = sections
            .entries
            .iter()
            .position(|entry| entry.section_type == SectionType::Descriptor)
            .ok_or(PriParseError::DescriptorMissing)?;
        let descriptor_data = &sections.data[descriptor_index];

        let descriptor = PriDescriptor::from_slice(
            slice_range(descriptor_data, 0, PriDescriptor::SIZE)
                .ok_or(PriParseError::truncated("pri descriptor"))?,
        );

        let mut cursor = Cursor::new(descriptor_data, PriDescriptor::SIZE);
        let section_indices = DescriptorSectionIndices {
            hierarchical_schema: cursor
                .read_u16_array(descriptor.hierarchical_schema_count as usize)
                .ok_or(PriParseError::truncated(
                    "hierarchical schema section indices",
                ))?,
            decision_info: cursor
                .read_u16_array(descriptor.decision_info_count as usize)
                .ok_or(PriParseError::truncated("decision info section indices"))?,
            resource_map: cursor
                .read_u16_array(descriptor.resource_map_count as usize)
                .ok_or(PriParseError::truncated("resource map section indices"))?,
            referenced_file: cursor
                .read_u16_array(descriptor.referenced_file_sections_count as usize)
                .ok_or(PriParseError::truncated("referenced file section indices"))?,
            data_item: cursor
                .read_u16_array(descriptor.data_item_section_count as usize)
                .ok_or(PriParseError::truncated("data item section indices"))?,
        };

        let index = PriIndex::build(&descriptor, &section_indices, &sections)?;

        Ok(Self { index })
    }

    /// Resolves `path` (as it appears in [`Pri::resource_paths`]) against `ctx`,
    /// returning the value of the best-matching candidate, or `None` if `path`
    /// doesn't exist or none of its candidates are satisfied by `ctx`.
    pub fn resolve(
        &self,
        path: &str,
        ctx: &QualifierContext,
    ) -> Result<Option<ResolvedValue>, PriParseError> {
        crate::resources::query::resolve(&self.index, path, ctx)
    }

    /// Enumerates every resource path known to the primary resource map's schema.
    pub fn resource_paths(&self) -> impl Iterator<Item = &str> {
        self.index.resource_paths()
    }

    /// Returns every qualifier set defined for `path`'s decision, in file order,
    /// each paired with the score it received against `ctx` (`None` if it didn't
    /// match) and the candidate it selects - this is what [`Pri::resolve`] picks
    /// the best of, exposed for inspecting *why* a value was (or wasn't) chosen.
    /// Returns `None` if `path` doesn't resolve to an item at all.
    pub fn explain(
        &self,
        path: &str,
        ctx: &QualifierContext,
    ) -> Result<Option<Vec<crate::resources::query::QualifierSetMatch>>, PriParseError> {
        crate::resources::query::explain(&self.index, path, ctx)
    }
}

fn section_data(
    buffer: &Bytes,
    first_section_offset: u32,
    entry: &TableOfContentsEntry,
) -> Result<Bytes, PriParseError> {
    let header_start = first_section_offset as usize + entry.section_offset as usize;
    let header = SectionHeader::from_slice(
        slice_range(buffer, header_start, SectionHeader::SIZE)
            .ok_or(PriParseError::truncated("section header"))?,
    );

    // A section's declared length covers its header, data, padding and footer
    // together, not the data alone - confirmed against every section of a
    // real-world sample file, where this is exactly the byte offset from the
    // section's header to its footer's magic.
    let data_length = (header.section_length as usize)
        .checked_sub(SectionHeader::SIZE + SectionFooter::SIZE)
        .ok_or(PriParseError::truncated(
            "section length (shorter than its own header and footer)",
        ))?;

    let data_start = header_start + SectionHeader::SIZE;
    bytes_slice(buffer, data_start, data_length, "section data")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    struct SectionSpec {
        id: [u8; 16],
        data: Vec<u8>,
    }

    /// Assembles a full, minimal PRI file (header, table of contents, and each
    /// section's own header immediately followed by its data) out of the given
    /// sections, in table-of-contents order. Omits footers and padding - [`Pri::read`]
    /// never reads that far as long as the declared section length still accounts
    /// for them (see `section_data`).
    fn build_pri(sections: Vec<SectionSpec>) -> Vec<u8> {
        let toc_offset = ResourceHeader::SIZE;
        let first_section_offset = toc_offset + sections.len() * TableOfContentsEntry::SIZE;

        let mut section_bytes = Vec::new();
        let mut toc_rows = Vec::new();
        for spec in &sections {
            let section_offset = section_bytes.len() as u32;
            // The declared section length covers the header and footer too, not
            // just the data (see `section_data`) - even though this builder never
            // actually emits footer bytes, since nothing reads that far.
            let section_length =
                (spec.data.len() + SectionHeader::SIZE + SectionFooter::SIZE) as u32;

            section_bytes.extend_from_slice(&spec.id); // section_id
            section_bytes.extend_from_slice(&0u32.to_le_bytes()); // section_qualifier
            section_bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
            section_bytes.extend_from_slice(&0u16.to_le_bytes()); // section_flags
            section_bytes.extend_from_slice(&section_length.to_le_bytes());
            section_bytes.extend_from_slice(&0u32.to_le_bytes()); // unknown
            section_bytes.extend_from_slice(&spec.data);

            toc_rows.push((spec.id, section_offset, section_length));
        }

        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"mrm_pri2");
        buffer.extend_from_slice(&0u16.to_le_bytes()); // unknown, zero
        buffer.extend_from_slice(&1u16.to_le_bytes()); // unknown, one
        buffer.extend_from_slice(
            &((first_section_offset + section_bytes.len()) as u32).to_le_bytes(),
        );
        buffer.extend_from_slice(&(toc_offset as u32).to_le_bytes());
        buffer.extend_from_slice(&(first_section_offset as u32).to_le_bytes());
        buffer.extend_from_slice(&(sections.len() as u16).to_le_bytes());
        buffer.extend_from_slice(&0xFFFFu16.to_le_bytes());
        buffer.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(buffer.len(), toc_offset);

        for (id, section_offset, section_length) in &toc_rows {
            buffer.extend_from_slice(id);
            buffer.extend_from_slice(&0u16.to_le_bytes()); // flags
            buffer.extend_from_slice(&0u16.to_le_bytes()); // section_flags
            buffer.extend_from_slice(&0u32.to_le_bytes()); // section_qualifier
            buffer.extend_from_slice(&section_offset.to_le_bytes());
            buffer.extend_from_slice(&section_length.to_le_bytes());
        }
        assert_eq!(buffer.len(), first_section_offset);

        buffer.extend_from_slice(&section_bytes);
        buffer
    }

    fn descriptor_data(
        hierarchical_schema_index: u16,
        decision_info_index: u16,
        resource_map_index: u16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // flags
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // included_file_list_section_index
        data.extend_from_slice(&0u16.to_le_bytes()); // unknown
        data.extend_from_slice(&1u16.to_le_bytes()); // hierarchical_schema_count
        data.extend_from_slice(&1u16.to_le_bytes()); // decision_info_count
        data.extend_from_slice(&1u16.to_le_bytes()); // resource_map_count
        data.extend_from_slice(&resource_map_index.to_le_bytes()); // primary_resource_map_index
        data.extend_from_slice(&0u16.to_le_bytes()); // referenced_file_sections_count
        data.extend_from_slice(&0u16.to_le_bytes()); // data_item_section_count
        data.extend_from_slice(&0u16.to_le_bytes()); // unknown

        data.extend_from_slice(&hierarchical_schema_index.to_le_bytes());
        data.extend_from_slice(&decision_info_index.to_le_bytes());
        data.extend_from_slice(&resource_map_index.to_le_bytes());
        data
    }

    /// A single root item, "icon.png" (index property 0), no scopes.
    fn hierarchical_schema_data() -> Vec<u8> {
        let mut data = Vec::new();
        let name_block = "icon.png\0";

        data.extend_from_slice(&1u16.to_le_bytes()); // unknown, one
        data.extend_from_slice(&1u16.to_le_bytes()); // unique_name_length
        data.extend_from_slice(&1u16.to_le_bytes()); // name_length
        data.extend_from_slice(&0u16.to_le_bytes()); // unknown

        data.extend_from_slice(&[0u8; 20]); // HSCHEMA_VERSION_INFO

        data.extend_from_slice(&0u16.to_le_bytes()); // unique name (null terminator only)
        data.extend_from_slice(&0u16.to_le_bytes()); // name (null terminator only)

        data.extend_from_slice(&0u16.to_le_bytes()); // unknown
        data.extend_from_slice(&8u16.to_le_bytes()); // longest_full_path_length
        data.extend_from_slice(&0u16.to_le_bytes()); // unknown
        data.extend_from_slice(&1u32.to_le_bytes()); // number_of_resource_names
        data.extend_from_slice(&0u32.to_le_bytes()); // number_of_scopes
        data.extend_from_slice(&1u32.to_le_bytes()); // number_of_items
        data.extend_from_slice(&(name_block.encode_utf16().count() as u32).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // total_length

        // Resource name entry: "icon.png", root (parent = self), index property 0.
        data.extend_from_slice(&0u16.to_le_bytes()); // parent_scope_index
        data.extend_from_slice(&8u16.to_le_bytes()); // full_path_length
        data.extend_from_slice(&(b'I' as u16).to_le_bytes()); // uppercase first char
        data.push(8); // name_length
        data.push(0); // flags: item, unicode
        data.extend_from_slice(&0u16.to_le_bytes()); // name_offset
        data.extend_from_slice(&0u16.to_le_bytes()); // index_property

        data.extend_from_slice(&0u16.to_le_bytes()); // item entry: table position 0

        for unit in name_block.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }

        data
    }

    /// A single decision with two qualifier sets: `lang=en-US`, then an empty
    /// neutral fallback.
    fn decision_info_data() -> Vec<u8> {
        let mut data = Vec::new();
        let value = "en-US\0";

        data.extend_from_slice(&1u16.to_le_bytes()); // number_of_distinct_qualifiers
        data.extend_from_slice(&1u16.to_le_bytes()); // number_of_qualifiers
        data.extend_from_slice(&2u16.to_le_bytes()); // number_of_qualifier_sets
        data.extend_from_slice(&1u16.to_le_bytes()); // number_of_decisions
        data.extend_from_slice(&3u16.to_le_bytes()); // number_of_index_table_entries
        data.extend_from_slice(&(value.encode_utf16().count() as u16).to_le_bytes());

        data.extend_from_slice(&0u16.to_le_bytes()); // decision: first qualifier set index
        data.extend_from_slice(&2u16.to_le_bytes()); // decision: number of qualifier sets

        data.extend_from_slice(&2u16.to_le_bytes()); // set 0: first qualifier index
        data.extend_from_slice(&1u16.to_le_bytes()); // set 0: number of qualifiers
        data.extend_from_slice(&3u16.to_le_bytes()); // set 1: first qualifier index (unused)
        data.extend_from_slice(&0u16.to_le_bytes()); // set 1: number of qualifiers

        data.extend_from_slice(&0u16.to_le_bytes()); // qualifier: distinct qualifier index
        data.extend_from_slice(&0u16.to_le_bytes()); // qualifier: priority
        data.extend_from_slice(&1000u16.to_le_bytes()); // qualifier: fallback score
        data.extend_from_slice(&0u16.to_le_bytes()); // unknown

        data.extend_from_slice(&0u16.to_le_bytes()); // distinct qualifier: env ref index
        data.extend_from_slice(&0u16.to_le_bytes()); // distinct qualifier: type = Language
        data.extend_from_slice(&0u16.to_le_bytes()); // distinct qualifier: condition operator
        data.extend_from_slice(&0u16.to_le_bytes()); // distinct qualifier: value type
        data.extend_from_slice(&0u32.to_le_bytes()); // distinct qualifier: value offset

        data.extend_from_slice(&0u16.to_le_bytes()); // index table: [qualifier_set0,
        data.extend_from_slice(&1u16.to_le_bytes()); //               qualifier_set1,
        data.extend_from_slice(&0u16.to_le_bytes()); //               qualifier0]

        for unit in value.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }

        data
    }

    /// A single item (index property 0) with two embedded candidates, "A" and "B",
    /// aligned with the decision's two qualifier sets.
    fn resource_map_data(hierarchical_schema_index: u16, decision_info_index: u16) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&0u16.to_le_bytes()); // environment references block length
        data.extend_from_slice(&0u16.to_le_bytes()); // environment references count
        data.extend_from_slice(&hierarchical_schema_index.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // hierarchical schema reference block length
        data.extend_from_slice(&decision_info_index.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes()); // resource value type table entries
        data.extend_from_slice(&1u16.to_le_bytes()); // item to iteminfo group entries
        data.extend_from_slice(&1u16.to_le_bytes()); // iteminfo group entries
        data.extend_from_slice(&1u32.to_le_bytes()); // iteminfo table entries
        data.extend_from_slice(&2u32.to_le_bytes()); // number of candidates
        data.extend_from_slice(&4u32.to_le_bytes()); // embedded data block length
        data.extend_from_slice(&0u32.to_le_bytes()); // table extension block length

        data.extend_from_slice(&4u32.to_le_bytes()); // resource value type entry: unknown
        data.extend_from_slice(&0u32.to_le_bytes()); //   .. resource value type = String

        data.extend_from_slice(&0u16.to_le_bytes()); // item to iteminfo group: index property 0
        data.extend_from_slice(&0u16.to_le_bytes()); //   .. group index 0

        data.extend_from_slice(&1u16.to_le_bytes()); // iteminfo group: 1 iteminfo
        data.extend_from_slice(&0u16.to_le_bytes()); //   .. starting at index 0

        data.extend_from_slice(&0u16.to_le_bytes()); // iteminfo: decision 0
        data.extend_from_slice(&0u16.to_le_bytes()); //   .. first candidate 0

        // No table extension header here: a `table_extension_block_length` of zero
        // means the whole block (including its header) is omitted, not present with
        // all-zero counts (see `resource_map::build`).

        data.push(0); // candidate 0: embedded
        data.push(0); //   .. resource value type index 0
        data.extend_from_slice(&2u16.to_le_bytes()); //   .. length 2
        data.extend_from_slice(&0u32.to_le_bytes()); //   .. offset 0 ("A")

        data.push(0); // candidate 1: embedded
        data.push(0); //   .. resource value type index 0
        data.extend_from_slice(&2u16.to_le_bytes()); //   .. length 2
        data.extend_from_slice(&2u32.to_le_bytes()); //   .. offset 2 ("B")

        data.extend_from_slice(&[b'A', 0, b'B', 0]); // embedded data block

        data
    }

    #[tokio::test]
    async fn test_read_and_resolve_end_to_end() {
        let sections = vec![
            SectionSpec {
                id: *b"[mrm_pridescex]\0",
                data: descriptor_data(1, 2, 3),
            },
            SectionSpec {
                id: *b"[mrm_hschema]  \0",
                data: hierarchical_schema_data(),
            },
            SectionSpec {
                id: *b"[mrm_decn_info]\0",
                data: decision_info_data(),
            },
            SectionSpec {
                id: *b"[mrm_res_map2_]\0",
                data: resource_map_data(1, 2),
            },
        ];
        let buffer = build_pri(sections);

        let pri = Pri::read(buffer.as_slice())
            .await
            .expect("valid synthetic PRI file");

        let paths: Vec<&str> = pri.resource_paths().collect();
        assert_eq!(paths, vec!["icon.png"]);

        let en_us = QualifierContext {
            language: vec![Arc::from("en-US")],
            ..Default::default()
        };
        match pri.resolve("icon.png", &en_us).unwrap() {
            Some(ResolvedValue::String(value)) => assert_eq!(&*value, "A"),
            other => panic!("expected the en-US candidate, got {other:?}"),
        }

        let fr_fr = QualifierContext {
            language: vec![Arc::from("fr-FR")],
            ..Default::default()
        };
        match pri.resolve("icon.png", &fr_fr).unwrap() {
            Some(ResolvedValue::String(value)) => assert_eq!(&*value, "B"),
            other => panic!("expected the neutral fallback candidate, got {other:?}"),
        }

        assert!(pri.resolve("missing.png", &en_us).unwrap().is_none());
    }
}
