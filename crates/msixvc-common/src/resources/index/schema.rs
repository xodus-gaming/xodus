//! Processes a Hierarchical Schema Section into a flat
//! `full path -> index property` lookup, built once so that
//! [`super::super::query::resolve`] never has to walk the scope/item tree again.
//!
//! Note the two distinct numbering schemes at play here: a resource name's
//! *index* is its position in this section's own name table (used by
//! `parent_scope_index` to link a name to its parent scope), while its *index
//! property* is a separate, unrelated value carried in the entry itself - that's
//! the value a Resource Map Section actually keys its items by.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;

use crate::parse::byteorder::little_endian::U32;
use crate::resources::error::PriParseError;
use crate::resources::structs::{
    HSchemaVersionInfo, HierarchicalSchemaHeader, HierarchicalSchemaTrailer, ItemEntry,
    ResourceNameEntry, ScopeEntry,
};

use super::util::{Cursor, decode_ascii_at, decode_ascii_z, decode_utf16_at, decode_utf16_z};

#[derive(Debug, Clone, Default)]
pub struct HierarchicalSchema {
    /// Full item resource path (segments joined by `/`) -> index property. Scopes
    /// (folders) are walked to build these paths but aren't keyed here themselves -
    /// see [`build`].
    pub paths: HashMap<Arc<str>, u32>,
}

pub(crate) fn build(data: &Bytes, extended: bool) -> Result<HierarchicalSchema, PriParseError> {
    let mut cursor = Cursor::new(data, 0);
    let prefix = cursor
        .read::<HierarchicalSchemaHeader>()
        .ok_or(PriParseError::truncated("hierarchical schema header"))?;

    if extended {
        // hname identifier - only distinguishes the ascii-name-block variant, which
        // is already reflected in `extended`/the trailer's ascii block length below.
        cursor
            .take(16)
            .ok_or(PriParseError::truncated("hname identifier"))?;
    }

    cursor
        .read::<HSchemaVersionInfo>()
        .ok_or(PriParseError::truncated("hierarchical schema version info"))?;

    // wcharz unique name, then wcharz name of the resource map - lengths (including
    // the null terminator) were already given in `prefix`.
    cursor
        .take(prefix.unique_name_length as usize * 2)
        .ok_or(PriParseError::truncated("resource map unique name"))?;
    cursor
        .take(prefix.name_length as usize * 2)
        .ok_or(PriParseError::truncated("resource map name"))?;

    let trailer = cursor
        .read::<HierarchicalSchemaTrailer>()
        .ok_or(PriParseError::truncated("hierarchical schema trailer"))?;

    let ascii_name_block_length = if extended {
        cursor
            .read::<U32>()
            .ok_or(PriParseError::truncated("ascii name block length"))? as usize
    } else {
        0
    };

    let names = (0..trailer.number_of_resource_names)
        .map(|_| {
            cursor
                .read::<ResourceNameEntry>()
                .ok_or(PriParseError::truncated("resource name entry"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    for _ in 0..trailer.number_of_scopes {
        cursor
            .read::<ScopeEntry>()
            .ok_or(PriParseError::truncated("scope entry"))?;
    }
    for _ in 0..trailer.number_of_items {
        cursor
            .read::<ItemEntry>()
            .ok_or(PriParseError::truncated("item entry"))?;
    }

    let unicode_name_block = cursor
        .take(trailer.unicode_name_block_length as usize * 2)
        .ok_or(PriParseError::truncated("unicode name block"))?;
    let ascii_name_block = cursor
        .take(ascii_name_block_length)
        .ok_or(PriParseError::truncated("ascii name block"))?;

    let short_names: Vec<String> = names
        .iter()
        .map(|entry| resolve_name(unicode_name_block, ascii_name_block, entry))
        .collect();

    // A scope's `index_property` is *not* an alias into the same numbering space as
    // items' - a real-world sample file shows scopes' values coinciding with
    // unrelated items' index properties, resolving to nonsensical values if treated
    // the same way. Only items are ever looked up in a Resource Map Section, so
    // only items are worth keying here.
    let mut paths = HashMap::with_capacity(names.len());
    for (table_index, name) in names.iter().enumerate() {
        if name.is_scope {
            continue;
        }
        let path = full_path(table_index, &names, &short_names);
        paths.insert(Arc::from(path), name.index_property as u32);
    }

    Ok(HierarchicalSchema { paths })
}

fn resolve_name(unicode_block: &[u8], ascii_block: &[u8], entry: &ResourceNameEntry) -> String {
    let offset = entry.name_offset as usize;
    match (entry.is_ascii, entry.name_length) {
        (true, 0) => decode_ascii_z(ascii_block, offset),
        (true, len) => decode_ascii_at(ascii_block, offset, len as usize),
        (false, 0) => decode_utf16_z(unicode_block, offset),
        (false, len) => decode_utf16_at(unicode_block, offset, len as usize),
    }
}

/// Walks `parent_scope_index` links (by table position, *not* index property) to
/// build a name's full path. Self-referencing or out-of-range parent is treated as
/// the root; the walk is bounded by `names.len()` so a corrupt/cyclic chain can't
/// hang the parser.
fn full_path(index: usize, names: &[ResourceNameEntry], short_names: &[String]) -> String {
    let mut segments = vec![short_names[index].as_str()];
    let mut current = index;
    for _ in 0..names.len() {
        let parent = names[current].parent_scope_index as usize;
        if parent == current || parent >= names.len() {
            break;
        }
        segments.push(short_names[parent].as_str());
        current = parent;
    }
    segments.reverse();
    segments.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal compact Hierarchical Schema Section describing a single
    /// scope "Files" (index property 10) containing one item "icon.png" (index
    /// property 20), both stored in the Unicode name block.
    fn sample_section() -> Bytes {
        let mut data = Vec::new();

        // Header: unknown(one)=1, unique_name_length=1, name_length=1, unknown=0
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        // HSCHEMA_VERSION_INFO (20 bytes)
        data.extend_from_slice(&[0u8; 20]);

        // wcharz unique name + wcharz name, 1 char each (just the null terminator)
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        // Trailer: unknown(2), longest_full_path_length, unknown(2),
        // number_of_resource_names=2, number_of_scopes=1, number_of_items=1,
        // unicode_name_block_length (chars), total_length
        let names_block = "Files\0icon.png\0";
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&20u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&(names_block.encode_utf16().count() as u32).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        // Resource name entries: index 0 = "Files" (scope, root), index 1 = "icon.png"
        // (item, parented to index 0).
        // "Files": parent_scope_index=0 (self -> root), full_path_length, uppercase
        // first char 'F', name_length=5, flags (bit4=scope), name_offset=0, index
        // property=10
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&(b'F' as u16).to_le_bytes());
        data.push(5);
        data.push(1 << 4);
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&10u16.to_le_bytes());

        // "icon.png": parent_scope_index=0, full_path_length, uppercase first char
        // 'I', name_length=8, flags (item, not scope), name_offset=6, index
        // property=20
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&14u16.to_le_bytes());
        data.extend_from_slice(&(b'I' as u16).to_le_bytes());
        data.push(8);
        data.push(0);
        data.extend_from_slice(&6u16.to_le_bytes());
        data.extend_from_slice(&20u16.to_le_bytes());

        // Scope entries: scope_index=0 (table position of "Files"), child_count=1,
        // first_child_index=1, unknown=0
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        // Item entries: item_index=1 (table position of "icon.png")
        data.extend_from_slice(&1u16.to_le_bytes());

        // Unicode name block
        for unit in names_block.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }

        Bytes::from(data)
    }

    #[test]
    fn test_build_resolves_full_paths_and_index_properties() {
        let schema = build(&sample_section(), false).unwrap();

        // "Files" is a scope, not an item - it isn't resolvable on its own (see
        // `build`'s doc comment), even though it does contribute the "Files/" path
        // prefix to its child item below.
        assert_eq!(schema.paths.get("Files"), None);
        assert_eq!(schema.paths.get("Files/icon.png"), Some(&20));
        assert_eq!(schema.paths.len(), 1);
    }
}
