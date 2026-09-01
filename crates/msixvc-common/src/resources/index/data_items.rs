//! Processes a Data Item Section into a flat, combined-index table
//! of owned, cheaply-clonable [`Bytes`] slices.
//!
//! A stored string's bytes aren't decoded here: a Data Item Section entry backs
//! resource value types as different as `String` (UTF-16), `Utf8String` and
//! `AsciiString`, and only the candidate that references it (via its resource value
//! type) knows which one applies - see [`super::super::query::resolve`].

use bytes::Bytes;

use crate::resources::error::PriParseError;
use crate::resources::structs::{BlobEntry, DataItemHeader, StringEntry};

use super::util::{Cursor, bytes_slice};

#[derive(Debug, Clone, Default)]
pub struct DataItemSection {
    /// Strings first, then blobs, matching the combined index space
    items: Vec<Bytes>,
}

impl DataItemSection {
    pub fn get(&self, index: u16) -> Option<&Bytes> {
        self.items.get(index as usize)
    }
}

pub(crate) fn build(data: &Bytes) -> Result<DataItemSection, PriParseError> {
    let mut cursor = Cursor::new(data, 0);
    let header = cursor.read::<DataItemHeader>("data item header")?;

    let string_entries = (0..header.number_of_strings)
        .map(|_| cursor.read::<StringEntry>("string entry"))
        .collect::<Result<Vec<_>, _>>()?;
    let blob_entries = (0..header.number_of_blobs)
        .map(|_| cursor.read::<BlobEntry>("blob entry"))
        .collect::<Result<Vec<_>, _>>()?;
    let stored_data =
        cursor.take_bytes(header.total_data_length as usize, "data item stored data")?;

    let mut items = Vec::with_capacity(string_entries.len() + blob_entries.len());
    for entry in &string_entries {
        items.push(bytes_slice(
            &stored_data,
            entry.offset as usize,
            entry.length as usize,
            "data item string",
        )?);
    }
    for entry in &blob_entries {
        items.push(bytes_slice(
            &stored_data,
            entry.offset as usize,
            entry.length as usize,
            "data item blob",
        )?);
    }

    Ok(DataItemSection { items })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_combines_strings_then_blobs() {
        let mut data = Vec::new();
        // Header: unknown(4), 1 string, 1 blob, total_data_length
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&6u32.to_le_bytes()); // "hi" (4 bytes UTF-16) + 2 blob bytes

        // String entry: offset=0, length=4 bytes ("hi" as UTF-16LE)
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());

        // Blob entry: offset=4, length=2
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());

        // Stored data: "hi" (UTF-16LE) + [0xAB, 0xCD]
        data.extend_from_slice(&[b'h', 0, b'i', 0]);
        data.extend_from_slice(&[0xAB, 0xCD]);

        let section = build(&Bytes::from(data)).unwrap();
        assert_eq!(section.get(0).unwrap().as_ref(), &[b'h', 0, b'i', 0]);
        assert_eq!(section.get(1).unwrap().as_ref(), &[0xAB, 0xCD]);
        assert!(section.get(2).is_none());
    }
}
