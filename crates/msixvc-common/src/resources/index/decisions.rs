//! Processes a Decision Info Section into owned, cross-referenced
//! [`Decision`]s: each qualifier's distinct-qualifier value is resolved eagerly out
//! of the qualifier value block (it's short textual data, cheap to own), so
//! evaluating a decision against a [`super::super::query::QualifierContext`] later
//! never has to touch the raw tables again.

use std::sync::Arc;

use bytes::Bytes;

use crate::resources::error::PriParseError;
use crate::resources::structs::{
    DecisionEntry, DecisionInfoHeader, DistinctQualifierEntry, QualifierEntry, QualifierSetEntry,
    QualifierType,
};

use super::util::{Cursor, decode_utf16_z};

#[derive(Debug, Clone)]
pub struct Qualifier {
    pub qualifier_type: QualifierType,
    pub value: Arc<str>,
    pub priority: u16,
    pub fallback_score: u16,
}

#[derive(Debug, Clone)]
pub struct QualifierSet {
    pub qualifiers: Vec<Qualifier>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub qualifier_sets: Vec<QualifierSet>,
}

#[derive(Debug, Clone, Default)]
pub struct DecisionInfo {
    pub decisions: Vec<Decision>,
}

/// Resolves an index-table sub-range (`first..first + count`) into owned clones of
/// the referenced table entries.
fn resolve_range<T: Clone>(
    index_table: &[u16],
    first: u16,
    count: u16,
    table: &[T],
) -> Option<Vec<T>> {
    let start = first as usize;
    let end = start.checked_add(count as usize)?;
    let indices = index_table.get(start..end)?;
    indices
        .iter()
        .map(|&i| table.get(i as usize).cloned())
        .collect()
}

pub(crate) fn build(data: &Bytes) -> Result<DecisionInfo, PriParseError> {
    let mut cursor = Cursor::new(data, 0);
    let header = cursor
        .read::<DecisionInfoHeader>()
        .ok_or(PriParseError::truncated("decision info header"))?;

    let decision_entries = (0..header.number_of_decisions)
        .map(|_| cursor.read::<DecisionEntry>())
        .collect::<Option<Vec<_>>>()
        .ok_or(PriParseError::truncated("decision entry"))?;
    let qualifier_set_entries = (0..header.number_of_qualifier_sets)
        .map(|_| cursor.read::<QualifierSetEntry>())
        .collect::<Option<Vec<_>>>()
        .ok_or(PriParseError::truncated("qualifier set entry"))?;
    let qualifier_entries = (0..header.number_of_qualifiers)
        .map(|_| cursor.read::<QualifierEntry>())
        .collect::<Option<Vec<_>>>()
        .ok_or(PriParseError::truncated("qualifier entry"))?;
    let distinct_qualifier_entries = (0..header.number_of_distinct_qualifiers)
        .map(|_| cursor.try_read::<DistinctQualifierEntry>("distinct qualifier entry"))
        .collect::<Result<Vec<_>, _>>()?;
    let index_table = cursor
        .read_u16_array(header.number_of_index_table_entries as usize)
        .ok_or(PriParseError::truncated("index table"))?;
    let value_block = cursor
        .take(header.qualifier_value_block_length as usize * 2)
        .ok_or(PriParseError::truncated("qualifier value block"))?;

    let distinct_qualifiers: Vec<(QualifierType, Arc<str>)> = distinct_qualifier_entries
        .iter()
        .map(|dq| {
            (
                dq.qualifier_type,
                Arc::from(decode_utf16_z(
                    value_block,
                    dq.qualifier_value_offset as usize,
                )),
            )
        })
        .collect();

    let qualifiers = qualifier_entries
        .iter()
        .map(|q| {
            let (qualifier_type, value) = distinct_qualifiers
                .get(q.distinct_qualifier_index as usize)
                .cloned()
                .ok_or(PriParseError::truncated(
                    "qualifier's distinct qualifier index",
                ))?;
            Ok(Qualifier {
                qualifier_type,
                value,
                priority: q.priority,
                fallback_score: q.fallback_score,
            })
        })
        .collect::<Result<Vec<_>, PriParseError>>()?;

    let qualifier_sets = qualifier_set_entries
        .iter()
        .map(|set| {
            let qualifiers = resolve_range(
                &index_table,
                set.first_qualifier_index,
                set.number_of_qualifiers,
                &qualifiers,
            )
            .ok_or(PriParseError::truncated("qualifier set's qualifier range"))?;
            Ok(QualifierSet { qualifiers })
        })
        .collect::<Result<Vec<_>, PriParseError>>()?;

    let decisions = decision_entries
        .iter()
        .map(|decision| {
            let qualifier_sets = resolve_range(
                &index_table,
                decision.first_qualifier_set_index,
                decision.number_of_qualifier_sets,
                &qualifier_sets,
            )
            .ok_or(PriParseError::truncated("decision's qualifier set range"))?;
            Ok(Decision { qualifier_sets })
        })
        .collect::<Result<Vec<_>, PriParseError>>()?;

    Ok(DecisionInfo { decisions })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal Decision Info Section with a single decision made up of two
    /// qualifier sets: `lang=en-US` and a qualifier-less neutral fallback.
    fn sample_section() -> Bytes {
        let mut data = Vec::new();

        // Header: 1 distinct qualifier, 1 qualifier, 2 qualifier sets, 1 decision,
        // 3 index table entries, qualifier value block length in characters.
        let value = "en-US\0";
        data.extend_from_slice(&1u16.to_le_bytes()); // number_of_distinct_qualifiers
        data.extend_from_slice(&1u16.to_le_bytes()); // number_of_qualifiers
        data.extend_from_slice(&2u16.to_le_bytes()); // number_of_qualifier_sets
        data.extend_from_slice(&1u16.to_le_bytes()); // number_of_decisions
        data.extend_from_slice(&3u16.to_le_bytes()); // number_of_index_table_entries
        data.extend_from_slice(&(value.encode_utf16().count() as u16).to_le_bytes());

        // Decisions: first_qualifier_set_index=0, number_of_qualifier_sets=2
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());

        // Qualifier sets: set 0 -> qualifier[0] (index table position 2); set 1 ->
        // empty (neutral fallback). Positions 0-1 of the index table are already
        // used by the decision's own qualifier-set range above, so this set's
        // range has to start past it.
        data.extend_from_slice(&2u16.to_le_bytes()); // first_qualifier_index
        data.extend_from_slice(&1u16.to_le_bytes()); // number_of_qualifiers
        data.extend_from_slice(&3u16.to_le_bytes()); // first_qualifier_index (unused, count=0)
        data.extend_from_slice(&0u16.to_le_bytes()); // number_of_qualifiers

        // Qualifiers: distinct_qualifier_index=0, priority=0, fallback_score=1000, pad
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&1000u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        // Distinct qualifiers: env ref index=0, qualifier_type=Language(0),
        // condition operator=0, value type=0, value offset=0
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        // Index table: [qualifier_set0, qualifier_set1, qualifier0]
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        // Qualifier value block
        for unit in value.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }

        Bytes::from(data)
    }

    #[test]
    fn test_build_resolves_decisions_and_qualifier_sets() {
        let info = build(&sample_section()).unwrap();
        assert_eq!(info.decisions.len(), 1);

        let decision = &info.decisions[0];
        assert_eq!(decision.qualifier_sets.len(), 2);

        let language_set = &decision.qualifier_sets[0];
        assert_eq!(language_set.qualifiers.len(), 1);
        assert_eq!(
            language_set.qualifiers[0].qualifier_type,
            QualifierType::Language
        );
        assert_eq!(&*language_set.qualifiers[0].value, "en-US");
        assert_eq!(language_set.qualifiers[0].fallback_score, 1000);

        let neutral_set = &decision.qualifier_sets[1];
        assert!(neutral_set.qualifiers.is_empty());
    }
}
