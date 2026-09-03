//! Turns the raw sections of a parsed PRI file into a queryable [`PriIndex`],
//! built once by [`crate::resources::pri::Pri::read`] and reused by every
//! subsequent [`crate::resources::pri::Pri::resolve`] call.
//!
//! Each submodule processes exactly one section type; see their
//! docs for how each one is turned from raw tables into owned, cross-referenced
//! data. [`util`] holds the runtime-sized parsing helpers they all share.

pub mod data_items;
pub mod decisions;
pub mod resource_map;
pub mod schema;
pub(crate) mod util;

use std::collections::HashMap;

use crate::resources::error::PriParseError;
use crate::resources::pri::{DescriptorSectionIndices, SectionTable};
use crate::resources::structs::{PriDescriptor, SectionType};

/// The queryable, fully cross-referenced result of processing every section a
/// `PriDescriptor` points at. Holds no borrowed data - every section's owned
/// [`bytes::Bytes`] slices keep the underlying file buffer alive independently, so
/// a `PriIndex` (and the [`crate::resources::pri::Pri`] wrapping it) can be freely
/// cloned/cached/shared without lifetimes tying it back to anything.
#[derive(Debug, Clone, Default)]
pub struct PriIndex {
    primary_resource_map: Option<u16>,
    pub(crate) resource_maps: HashMap<u16, resource_map::ResourceMap>,
    pub(crate) hierarchical_schemas: HashMap<u16, schema::HierarchicalSchema>,
    pub(crate) decision_infos: HashMap<u16, decisions::DecisionInfo>,
    pub(crate) data_item_sections: HashMap<u16, data_items::DataItemSection>,
}

impl PriIndex {
    pub(crate) fn build(
        descriptor: &PriDescriptor,
        section_indices: &DescriptorSectionIndices,
        sections: &SectionTable,
    ) -> Result<Self, PriParseError> {
        let mut hierarchical_schemas =
            HashMap::with_capacity(section_indices.hierarchical_schema.len());
        for &index in &section_indices.hierarchical_schema {
            let (entry, data) = sections.get(index)?;
            let SectionType::HierarchicalSchema(extended) = entry.section_type else {
                return Err(unexpected_type(
                    index,
                    "Hierarchical Schema",
                    &entry.section_type,
                ));
            };
            hierarchical_schemas.insert(index, schema::build(data, extended)?);
        }

        let mut decision_infos = HashMap::with_capacity(section_indices.decision_info.len());
        for &index in &section_indices.decision_info {
            let (entry, data) = sections.get(index)?;
            if entry.section_type != SectionType::DecisionInfo {
                return Err(unexpected_type(index, "Decision Info", &entry.section_type));
            }
            decision_infos.insert(index, decisions::build(data)?);
        }

        let mut data_item_sections = HashMap::with_capacity(section_indices.data_item.len());
        for &index in &section_indices.data_item {
            let (entry, data) = sections.get(index)?;
            if entry.section_type != SectionType::DataItem {
                return Err(unexpected_type(index, "Data Item", &entry.section_type));
            }
            data_item_sections.insert(index, data_items::build(data)?);
        }

        let mut resource_maps = HashMap::with_capacity(section_indices.resource_map.len());
        for &index in &section_indices.resource_map {
            let (entry, data) = sections.get(index)?;
            if !matches!(entry.section_type, SectionType::ResourceMap(_)) {
                return Err(unexpected_type(index, "Resource Map", &entry.section_type));
            }
            resource_maps.insert(index, resource_map::build(data)?);
        }

        let primary_resource_map = (descriptor.primary_resource_map_index != 0xFFFF)
            .then_some(descriptor.primary_resource_map_index);

        Ok(Self {
            primary_resource_map,
            resource_maps,
            hierarchical_schemas,
            decision_infos,
            data_item_sections,
        })
    }

    pub(crate) fn primary_resource_map(&self) -> Option<&resource_map::ResourceMap> {
        self.primary_resource_map
            .and_then(|index| self.resource_maps.get(&index))
    }

    pub(crate) fn primary_schema(&self) -> Option<&schema::HierarchicalSchema> {
        let resource_map = self.primary_resource_map()?;
        self.hierarchical_schemas
            .get(&resource_map.hierarchical_schema_section_index)
    }

    pub fn resource_paths(&self) -> impl Iterator<Item = &str> {
        self.primary_schema()
            .into_iter()
            .flat_map(|schema| schema.paths.keys().map(std::convert::AsRef::as_ref))
    }
}

fn unexpected_type(index: u16, expected: &'static str, found: &SectionType) -> PriParseError {
    PriParseError::UnexpectedSectionType {
        index,
        expected,
        found: found.clone(),
    }
}
