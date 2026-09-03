use bitflags::bitflags;
use num_enum::TryFromPrimitive;

use crate::parse::byteorder::little_endian::{U16, U32};
use crate::parse::{BinaryParse, BinaryTryParse, BytesReader, EmptyReader};
use crate::resources::error::PriParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionId {
    Pri0,
    Pri1,
    PriF,
    Pri2,
    Pri3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum QualifierType {
    Language = 0,
    Contrast = 1,
    Scale = 2,
    HomeRegion = 3,
    TargetSize = 4,
    LayoutDirection = 5,
    Theme = 6,
    AlternateForm = 7,
    DXFeatureLevel = 8,
    Configuration = 9,
    DeviceFamily = 10,
    Custom = 11,
}

impl BinaryTryParse for QualifierType {
    type Output = Self;
    type Size = typenum::U2;
    type Error = <Self as TryFrom<u16>>::Error;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        let (value, r) = r.read::<U16>();
        Self::try_from(value).map(|value| (value, r))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionType {
    Descriptor,
    HierarchicalSchema(bool),
    DecisionInfo,
    ResourceMap(u8),
    DataItem,
    FileList,
    Unknown([u8; 16]),
}

impl BinaryParse for SectionType {
    type Output = Self;
    type Size = typenum::U16;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (section_id, r) = r.read::<[u8; 16]>();
        let section_type = match &section_id {
            b"[mrm_pridescex]\0" => Self::Descriptor,
            b"[mrm_hschema]  \0" => Self::HierarchicalSchema(false),
            b"[mrm_hschemaex] " => Self::HierarchicalSchema(true),
            b"[mrm_decn_info]\0" => Self::DecisionInfo,
            b"[mrm_res_map__]\0" => Self::ResourceMap(1),
            b"[mrm_res_map2_]\0" => Self::ResourceMap(2),
            b"[mrm_dataitem] \0" => Self::DataItem,
            b"[def_file_list]\0" => Self::FileList,
            unk => Self::Unknown(*unk),
        };
        (section_type, r)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct PriDescriptorFlags: u16 {
        const AutoMerge = 1 << 0;
        const IsDeploymentMergeable = 1 << 1;
        const IsDeploymentMergeResult = 1 << 2;
        const IsAutomergeMergeResult = 1 << 3;
    }
}

impl BinaryParse for PriDescriptorFlags {
    type Output = Self;
    type Size = typenum::U2;
    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (flag, r) = r.read::<U16>();
        (Self::from_bits_retain(flag), r)
    }
}

#[derive(Debug, Clone)]
pub struct ResourceHeader {
    pub version_id: VersionId,
    pub total_file_size: u32,
    pub table_of_contents_offset: u32,
    pub first_section_offset: u32,
    pub number_of_sections: u16,
}

impl BinaryTryParse for ResourceHeader {
    type Output = Self;
    type Size = typenum::U32;
    type Error = PriParseError;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        let (version_identifier, r) = r.read::<[u8; 8]>();

        let version_id = match &version_identifier {
            b"mrm_pri0" => VersionId::Pri0,
            b"mrm_pri1" => VersionId::Pri1,
            b"mrm_prif" => VersionId::PriF,
            b"mrm_pri2" => VersionId::Pri2,
            b"mrm_pri3" => VersionId::Pri3,
            _ => return Err(PriParseError::UnknownMagic),
        };

        // uint16 	unknown, zero
        // uint16 	unknown, one
        let (_unknown1, r) = r.read::<U16>();
        let (_unknown2, r) = r.read::<U16>();

        let (total_file_size, r) = r.read::<U32>();
        let (table_of_contents_offset, r) = r.read::<U32>();
        let (first_section_offset, r) = r.read::<U32>();
        let (number_of_sections, r) = r.read::<U16>();

        // uint16 	unknown, 0xFFFF
        // uint32 	unknown, zero
        let (_unknown3, r) = r.read::<U16>();
        let (_unknown4, r) = r.read::<U32>();

        Ok((
            Self {
                version_id,
                total_file_size,
                table_of_contents_offset,
                first_section_offset,
                number_of_sections,
            },
            r,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct TableOfContentsEntry {
    pub section_type: SectionType,
    pub flags: u16,
    pub section_flags: u16,
    pub section_qualifier: u32,
    pub section_offset: u32,
    pub section_length: u32,
}

impl BinaryParse for TableOfContentsEntry {
    type Output = Self;
    type Size = typenum::U32;
    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (section_type, r) = r.read::<SectionType>();

        let (flags, r) = r.read::<U16>();
        let (section_flags, r) = r.read::<U16>();
        let (section_qualifier, r) = r.read::<U32>();
        let (section_offset, r) = r.read::<U32>();
        let (section_length, r) = r.read::<U32>();

        (
            Self {
                section_type,
                flags,
                section_flags,
                section_qualifier,
                section_offset,
                section_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub section_id: [u8; 16],
    pub section_qualifier: u32,
    pub flags: u16,
    pub section_flags: u16,
    pub section_length: u32,
}

impl BinaryParse for SectionHeader {
    type Output = Self;
    type Size = typenum::U32;
    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (section_id, r) = r.read::<[u8; 16]>();
        let (section_qualifier, r) = r.read::<U32>();
        let (flags, r) = r.read::<U16>();
        let (section_flags, r) = r.read::<U16>();
        let (section_length, r) = r.read::<U32>();
        // uint32  unknown, zero
        let (_unknown, r) = r.read::<U32>();

        (
            Self {
                section_id,
                section_qualifier,
                flags,
                section_flags,
                section_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct SectionFooter {
    pub magic: u32,
    pub section_length: u32,
}

impl BinaryParse for SectionFooter {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (magic, r) = r.read::<U32>();
        let (section_length, r) = r.read::<U32>();

        (
            Self {
                magic,
                section_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct PriDescriptor {
    pub flags: PriDescriptorFlags,
    pub included_file_list_section_index: u16,
    pub hierarchical_schema_count: u16,
    pub decision_info_count: u16,
    pub resource_map_count: u16,
    pub primary_resource_map_index: u16,
    pub referenced_file_sections_count: u16,
    pub data_item_section_count: u16,
}

impl BinaryParse for PriDescriptor {
    type Output = Self;
    type Size = typenum::U20;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (flags, r) = r.read::<PriDescriptorFlags>();
        let (included_file_list_section_index, r) = r.read::<U16>();
        // uint16   unknown, zero
        let (_unknown1, r) = r.read::<U16>();
        let (hierarchical_schema_count, r) = r.read::<U16>();
        let (decision_info_count, r) = r.read::<U16>();
        let (resource_map_count, r) = r.read::<U16>();
        let (primary_resource_map_index, r) = r.read::<U16>();
        let (referenced_file_sections_count, r) = r.read::<U16>();
        let (data_item_section_count, r) = r.read::<U16>();
        // uint16   unknown, zero
        let (_unknown2, r) = r.read::<U16>();

        (
            Self {
                flags,
                included_file_list_section_index,
                hierarchical_schema_count,
                decision_info_count,
                resource_map_count,
                primary_resource_map_index,
                referenced_file_sections_count,
                data_item_section_count,
            },
            r,
        )
    }
}

// The section indices following a `PriDescriptor` and the name/path data
// referenced by the structs below are variable-length and are read directly
// by the main `Pri` parser rather than through `BinaryParse`/`BinaryTryParse`.

// ---------------------------------------------------------------------
// Hierarchical Schema Section
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HSchemaVersionInfo {
    pub major_version: u16,
    pub minor_version: u16,
    pub checksum: u32,
    pub number_of_scopes: u32,
    pub number_of_items: u32,
}

impl BinaryParse for HSchemaVersionInfo {
    type Output = Self;
    type Size = typenum::U20;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (major_version, r) = r.read::<U16>();
        let (minor_version, r) = r.read::<U16>();
        // uint32   unknown, zero
        let (_unknown, r) = r.read::<U32>();
        let (checksum, r) = r.read::<U32>();
        let (number_of_scopes, r) = r.read::<U32>();
        let (number_of_items, r) = r.read::<U32>();

        (
            Self {
                major_version,
                minor_version,
                checksum,
                number_of_scopes,
                number_of_items,
            },
            r,
        )
    }
}

/// The fixed-size prefix of a Hierarchical Schema Section, common to both the
/// compact and extended layouts. The (optional, extended-only) [`HNameIdentifier`],
/// [`HSchemaVersionInfo`] and the variable-length resource map names follow and
/// are read by the main `Pri` parser.
#[derive(Debug, Clone)]
pub struct HierarchicalSchemaHeader {
    pub unique_name_length: u16,
    pub name_length: u16,
}

impl BinaryParse for HierarchicalSchemaHeader {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        // uint16   unknown, one
        let (_unknown1, r) = r.read::<U16>();
        let (unique_name_length, r) = r.read::<U16>();
        let (name_length, r) = r.read::<U16>();
        // uint16   unknown, zero
        let (_unknown2, r) = r.read::<U16>();

        (
            Self {
                unique_name_length,
                name_length,
            },
            r,
        )
    }
}

/// Identifies the hname block of an extended Hierarchical Schema Section.
/// Only present when the section uses the extended layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HNameIdentifier {
    Plain,
    Extended,
    Unknown([u8; 16]),
}

impl BinaryParse for HNameIdentifier {
    type Output = Self;
    type Size = typenum::U16;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (id, r) = r.read::<[u8; 16]>();
        let identifier = match &id {
            b"[def_hnames]   \0" => Self::Plain,
            b"[def_hnamesx]  \0" => Self::Extended,
            unk => Self::Unknown(*unk),
        };
        (identifier, r)
    }
}

#[derive(Debug, Clone)]
pub struct HierarchicalSchemaTrailer {
    pub longest_full_path_length: u16,
    pub number_of_resource_names: u32,
    pub number_of_scopes: u32,
    pub number_of_items: u32,
    pub unicode_name_block_length: u32,
    pub total_length: u32,
}

impl BinaryParse for HierarchicalSchemaTrailer {
    type Output = Self;
    type Size = typenum::U26;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        // uint16   unknown, zero
        let (_unknown1, r) = r.read::<U16>();
        let (longest_full_path_length, r) = r.read::<U16>();
        // uint16   unknown, zero
        let (_unknown2, r) = r.read::<U16>();
        let (number_of_resource_names, r) = r.read::<U32>();
        let (number_of_scopes, r) = r.read::<U32>();
        let (number_of_items, r) = r.read::<U32>();
        let (unicode_name_block_length, r) = r.read::<U32>();
        let (total_length, r) = r.read::<U32>();

        (
            Self {
                longest_full_path_length,
                number_of_resource_names,
                number_of_scopes,
                number_of_items,
                unicode_name_block_length,
                total_length,
            },
            r,
        )
    }
}

/// An entry describing a single resource name, i.e. a scope or an item.
#[derive(Debug, Clone)]
pub struct ResourceNameEntry {
    pub parent_scope_index: u16,
    pub full_path_length: u16,
    pub uppercase_first_char: u16,
    pub name_length: u8,
    pub is_scope: bool,
    pub is_ascii: bool,
    pub name_offset: u32,
    pub index_property: u16,
}

impl BinaryParse for ResourceNameEntry {
    type Output = Self;
    type Size = typenum::U12;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (parent_scope_index, r) = r.read::<U16>();
        let (full_path_length, r) = r.read::<U16>();
        let (uppercase_first_char, r) = r.read::<U16>();
        let (name_length, r) = r.read::<u8>();
        let (flags, r) = r.read::<u8>();
        let (name_offset_low, r) = r.read::<U16>();
        let (index_property, r) = r.read::<U16>();

        let is_scope = flags & (1 << 4) != 0;
        let is_ascii = flags & (1 << 5) != 0;
        let name_offset_high = u32::from(flags & 0x0F);
        let name_offset = (name_offset_high << 16) | u32::from(name_offset_low);

        (
            Self {
                parent_scope_index,
                full_path_length,
                uppercase_first_char,
                name_length,
                is_scope,
                is_ascii,
                name_offset,
                index_property,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ScopeEntry {
    pub scope_index: u16,
    pub child_count: u16,
    pub first_child_index: u16,
}

impl BinaryParse for ScopeEntry {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (scope_index, r) = r.read::<U16>();
        let (child_count, r) = r.read::<U16>();
        let (first_child_index, r) = r.read::<U16>();
        // uint16   unknown, zero
        let (_unknown, r) = r.read::<U16>();

        (
            Self {
                scope_index,
                child_count,
                first_child_index,
            },
            r,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ItemEntry {
    pub item_index: u16,
}

impl BinaryParse for ItemEntry {
    type Output = Self;
    type Size = typenum::U2;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (item_index, r) = r.read::<U16>();
        (Self { item_index }, r)
    }
}

#[derive(Debug, Clone)]
pub struct DecisionInfoHeader {
    pub number_of_distinct_qualifiers: u16,
    pub number_of_qualifiers: u16,
    pub number_of_qualifier_sets: u16,
    pub number_of_decisions: u16,
    pub number_of_index_table_entries: u16,
    pub qualifier_value_block_length: u16,
}

impl BinaryParse for DecisionInfoHeader {
    type Output = Self;
    type Size = typenum::U12;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (number_of_distinct_qualifiers, r) = r.read::<U16>();
        let (number_of_qualifiers, r) = r.read::<U16>();
        let (number_of_qualifier_sets, r) = r.read::<U16>();
        let (number_of_decisions, r) = r.read::<U16>();
        let (number_of_index_table_entries, r) = r.read::<U16>();
        let (qualifier_value_block_length, r) = r.read::<U16>();

        (
            Self {
                number_of_distinct_qualifiers,
                number_of_qualifiers,
                number_of_qualifier_sets,
                number_of_decisions,
                number_of_index_table_entries,
                qualifier_value_block_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct DecisionEntry {
    pub first_qualifier_set_index: u16,
    pub number_of_qualifier_sets: u16,
}

impl BinaryParse for DecisionEntry {
    type Output = Self;
    type Size = typenum::U4;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (first_qualifier_set_index, r) = r.read::<U16>();
        let (number_of_qualifier_sets, r) = r.read::<U16>();

        (
            Self {
                first_qualifier_set_index,
                number_of_qualifier_sets,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct QualifierSetEntry {
    pub first_qualifier_index: u16,
    pub number_of_qualifiers: u16,
}

impl BinaryParse for QualifierSetEntry {
    type Output = Self;
    type Size = typenum::U4;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (first_qualifier_index, r) = r.read::<U16>();
        let (number_of_qualifiers, r) = r.read::<U16>();

        (
            Self {
                first_qualifier_index,
                number_of_qualifiers,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct QualifierEntry {
    pub distinct_qualifier_index: u16,
    pub priority: u16,
    pub fallback_score: u16,
}

impl BinaryParse for QualifierEntry {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (distinct_qualifier_index, r) = r.read::<U16>();
        let (priority, r) = r.read::<U16>();
        let (fallback_score, r) = r.read::<U16>();
        // uint16   unknown, zero
        let (_unknown, r) = r.read::<U16>();

        (
            Self {
                distinct_qualifier_index,
                priority,
                fallback_score,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct DistinctQualifierEntry {
    pub environment_qualifier_index: u16,
    pub qualifier_type: QualifierType,
    pub condition_operator_index: u16,
    pub value_type_index: u16,
    pub qualifier_value_offset: u32,
}

impl BinaryTryParse for DistinctQualifierEntry {
    type Output = Self;
    type Size = typenum::U12;
    type Error = PriParseError;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        let (environment_qualifier_index, r) = r.read::<U16>();
        let (qualifier_type, r) = r.try_read::<QualifierType>()?;
        let (condition_operator_index, r) = r.read::<U16>();
        let (value_type_index, r) = r.read::<U16>();
        let (qualifier_value_offset, r) = r.read::<U32>();

        Ok((
            Self {
                environment_qualifier_index,
                qualifier_type,
                condition_operator_index,
                value_type_index,
                qualifier_value_offset,
            },
            r,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ResourceMapHeader {
    pub environment_references_block_length: u16,
    pub number_of_environment_references: u16,
    pub hierarchical_schema_section_index: u16,
    pub hierarchical_schema_reference_block_length: u16,
    pub decision_info_section_index: u16,
    pub resource_value_type_table_entries: u16,
    pub item_to_iteminfo_group_table_entries: u16,
    pub iteminfo_group_table_entries: u16,
    pub iteminfo_table_entries: u32,
    pub number_of_candidates: u32,
    pub embedded_data_block_length: u32,
    pub table_extension_block_length: u32,
}

impl BinaryParse for ResourceMapHeader {
    type Output = Self;
    type Size = typenum::U32;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (environment_references_block_length, r) = r.read::<U16>();
        let (number_of_environment_references, r) = r.read::<U16>();
        let (hierarchical_schema_section_index, r) = r.read::<U16>();
        let (hierarchical_schema_reference_block_length, r) = r.read::<U16>();
        let (decision_info_section_index, r) = r.read::<U16>();
        let (resource_value_type_table_entries, r) = r.read::<U16>();
        let (item_to_iteminfo_group_table_entries, r) = r.read::<U16>();
        let (iteminfo_group_table_entries, r) = r.read::<U16>();
        let (iteminfo_table_entries, r) = r.read::<U32>();
        let (number_of_candidates, r) = r.read::<U32>();
        let (embedded_data_block_length, r) = r.read::<U32>();
        let (table_extension_block_length, r) = r.read::<U32>();

        (
            Self {
                environment_references_block_length,
                number_of_environment_references,
                hierarchical_schema_section_index,
                hierarchical_schema_reference_block_length,
                decision_info_section_index,
                resource_value_type_table_entries,
                item_to_iteminfo_group_table_entries,
                iteminfo_group_table_entries,
                iteminfo_table_entries,
                number_of_candidates,
                embedded_data_block_length,
                table_extension_block_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct EnvironmentReference {
    pub environment_name: [u16; 256],
    pub major_version: u16,
    pub minor_version: u16,
    pub version_checksum: u32,
    pub number_of_qualifier_types: u16,
    pub number_of_qualifiers: u16,
    pub number_of_item_types: u16,
    pub number_of_resource_value_types: u16,
    pub number_of_value_locators: u16,
    pub number_of_condition_operators: u16,
    pub qualifier_type_table_offset: u32,
    pub qualifier_table_offset: u32,
    pub item_type_table_offset: u32,
    pub resource_value_type_table_offset: u32,
    pub value_locator_table_offset: u32,
    pub condition_operator_table_offset: u32,
}

impl BinaryParse for EnvironmentReference {
    type Output = Self;
    type Size = typenum::U556;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (environment_name, r) = r.read::<[U16; 256]>();
        let (major_version, r) = r.read::<U16>();
        let (minor_version, r) = r.read::<U16>();
        let (version_checksum, r) = r.read::<U32>();
        let (number_of_qualifier_types, r) = r.read::<U16>();
        let (number_of_qualifiers, r) = r.read::<U16>();
        let (number_of_item_types, r) = r.read::<U16>();
        let (number_of_resource_value_types, r) = r.read::<U16>();
        let (number_of_value_locators, r) = r.read::<U16>();
        let (number_of_condition_operators, r) = r.read::<U16>();
        let (qualifier_type_table_offset, r) = r.read::<U32>();
        let (qualifier_table_offset, r) = r.read::<U32>();
        let (item_type_table_offset, r) = r.read::<U32>();
        let (resource_value_type_table_offset, r) = r.read::<U32>();
        let (value_locator_table_offset, r) = r.read::<U32>();
        let (condition_operator_table_offset, r) = r.read::<U32>();

        (
            Self {
                environment_name,
                major_version,
                minor_version,
                version_checksum,
                number_of_qualifier_types,
                number_of_qualifiers,
                number_of_item_types,
                number_of_resource_value_types,
                number_of_value_locators,
                number_of_condition_operators,
                qualifier_type_table_offset,
                qualifier_table_offset,
                item_type_table_offset,
                resource_value_type_table_offset,
                value_locator_table_offset,
                condition_operator_table_offset,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct HierarchicalSchemaReferenceHeader {
    pub version_info: HSchemaVersionInfo,
    pub unique_id_length: u16,
}

impl BinaryParse for HierarchicalSchemaReferenceHeader {
    type Output = Self;
    type Size = typenum::U32;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (version_info, r) = r.read::<HSchemaVersionInfo>();
        let (unique_id_length, r) = r.read::<U16>();
        // uint16   unknown, zero
        // uint32   unknown, 7
        // uint32   unknown, 7
        let (_unknown1, r) = r.read::<U16>();
        let (_unknown2, r) = r.read::<U32>();
        let (_unknown3, r) = r.read::<U32>();

        (
            Self {
                version_info,
                unique_id_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum ResourceValueType {
    String = 0,
    Path = 1,
    EmbeddedData = 2,
    AsciiString = 3,
    Utf8String = 4,
    AsciiPath = 5,
    Utf8Path = 6,
}

impl BinaryTryParse for ResourceValueType {
    type Output = Self;
    type Size = typenum::U4;
    type Error = <Self as TryFrom<u32>>::Error;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        let (value, r) = r.read::<U32>();
        Self::try_from(value).map(|value| (value, r))
    }
}

#[derive(Debug, Clone)]
pub struct ResourceValueTypeEntry {
    pub resource_value_type: ResourceValueType,
}

impl BinaryTryParse for ResourceValueTypeEntry {
    type Output = Self;
    type Size = typenum::U8;
    type Error = PriParseError;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        // uint32   unknown, 4
        let (_unknown, r) = r.read::<U32>();
        let (resource_value_type, r) = r.try_read::<ResourceValueType>()?;

        Ok((
            Self {
                resource_value_type,
            },
            r,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ItemToItemInfoGroupEntry {
    pub first_item_index_property: u16,
    pub iteminfo_group_index: u16,
}

impl BinaryParse for ItemToItemInfoGroupEntry {
    type Output = Self;
    type Size = typenum::U4;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (first_item_index_property, r) = r.read::<U16>();
        let (iteminfo_group_index, r) = r.read::<U16>();

        (
            Self {
                first_item_index_property,
                iteminfo_group_index,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ItemInfoGroupEntry {
    pub number_of_iteminfos: u16,
    pub first_iteminfo_index: u16,
}

impl BinaryParse for ItemInfoGroupEntry {
    type Output = Self;
    type Size = typenum::U4;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (number_of_iteminfos, r) = r.read::<U16>();
        let (first_iteminfo_index, r) = r.read::<U16>();

        (
            Self {
                number_of_iteminfos,
                first_iteminfo_index,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ItemInfoEntry {
    pub decision_index: u16,
    pub first_candidate_index: u16,
}

impl BinaryParse for ItemInfoEntry {
    type Output = Self;
    type Size = typenum::U4;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (decision_index, r) = r.read::<U16>();
        let (first_candidate_index, r) = r.read::<U16>();

        (
            Self {
                decision_index,
                first_candidate_index,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct TableExtensionHeader {
    pub additional_item_to_iteminfo_group_entries: u32,
    pub additional_iteminfo_group_entries: u32,
    pub additional_iteminfo_entries: u32,
}

impl BinaryParse for TableExtensionHeader {
    type Output = Self;
    type Size = typenum::U12;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (additional_item_to_iteminfo_group_entries, r) = r.read::<U32>();
        let (additional_iteminfo_group_entries, r) = r.read::<U32>();
        let (additional_iteminfo_entries, r) = r.read::<U32>();

        (
            Self {
                additional_item_to_iteminfo_group_entries,
                additional_iteminfo_group_entries,
                additional_iteminfo_entries,
            },
            r,
        )
    }
}

/// A uint32 counterpart to [`ItemToItemInfoGroupEntry`], used for the entries
/// appended by the table extension block.
#[derive(Debug, Clone)]
pub struct ItemToItemInfoGroupEntryExt {
    pub first_item_index_property: u32,
    pub iteminfo_group_index: u32,
}

impl BinaryParse for ItemToItemInfoGroupEntryExt {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (first_item_index_property, r) = r.read::<U32>();
        let (iteminfo_group_index, r) = r.read::<U32>();

        (
            Self {
                first_item_index_property,
                iteminfo_group_index,
            },
            r,
        )
    }
}

/// A uint32 counterpart to [`ItemInfoGroupEntry`], used for the entries
/// appended by the table extension block.
#[derive(Debug, Clone)]
pub struct ItemInfoGroupEntryExt {
    pub number_of_iteminfos: u32,
    pub first_iteminfo_index: u32,
}

impl BinaryParse for ItemInfoGroupEntryExt {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (number_of_iteminfos, r) = r.read::<U32>();
        let (first_iteminfo_index, r) = r.read::<U32>();

        (
            Self {
                number_of_iteminfos,
                first_iteminfo_index,
            },
            r,
        )
    }
}

/// A uint32 counterpart to [`ItemInfoEntry`], used for the entries appended by
/// the table extension block.
#[derive(Debug, Clone)]
pub struct ItemInfoEntryExt {
    pub decision_index: u32,
    pub first_candidate_index: u32,
}

impl BinaryParse for ItemInfoEntryExt {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (decision_index, r) = r.read::<U32>();
        let (first_candidate_index, r) = r.read::<U32>();

        (
            Self {
                decision_index,
                first_candidate_index,
            },
            r,
        )
    }
}

/// A single resource candidate. Depending on the candidate type, the resource
/// data is either embedded directly in the section's embedded data block, or
/// referenced from a Data Item Section.
#[derive(Debug, Clone)]
pub enum Candidate {
    Embedded {
        resource_value_type_index: u8,
        embedded_data_length: u16,
        embedded_data_offset: u32,
    },
    Referenced {
        resource_value_type_index: u8,
        source_file: u16,
        data_item_index: u16,
        data_item_section_index: u16,
    },
    Unknown {
        candidate_type: u8,
        resource_value_type_index: u8,
        data: [u8; 6],
    },
}

impl BinaryParse for Candidate {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (candidate_type, r) = r.read::<u8>();
        let (resource_value_type_index, r) = r.read::<u8>();

        match candidate_type {
            0 => {
                let (embedded_data_length, r) = r.read::<U16>();
                let (embedded_data_offset, r) = r.read::<U32>();
                (
                    Self::Embedded {
                        resource_value_type_index,
                        embedded_data_length,
                        embedded_data_offset,
                    },
                    r,
                )
            }
            1 => {
                let (source_file, r) = r.read::<U16>();
                let (data_item_index, r) = r.read::<U16>();
                let (data_item_section_index, r) = r.read::<U16>();
                (
                    Self::Referenced {
                        resource_value_type_index,
                        source_file,
                        data_item_index,
                        data_item_section_index,
                    },
                    r,
                )
            }
            _ => {
                let (data, r) = r.read::<[u8; 6]>();
                (
                    Self::Unknown {
                        candidate_type,
                        resource_value_type_index,
                        data,
                    },
                    r,
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DataItemHeader {
    pub number_of_strings: u16,
    pub number_of_blobs: u16,
    pub total_data_length: u32,
}

impl BinaryParse for DataItemHeader {
    type Output = Self;
    type Size = typenum::U12;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        // uint32   unknown, zero
        let (_unknown, r) = r.read::<U32>();
        let (number_of_strings, r) = r.read::<U16>();
        let (number_of_blobs, r) = r.read::<U16>();
        let (total_data_length, r) = r.read::<U32>();

        (
            Self {
                number_of_strings,
                number_of_blobs,
                total_data_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct StringEntry {
    pub offset: u16,
    pub length: u16,
}

impl BinaryParse for StringEntry {
    type Output = Self;
    type Size = typenum::U4;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (offset, r) = r.read::<U16>();
        let (length, r) = r.read::<U16>();

        (Self { offset, length }, r)
    }
}

#[derive(Debug, Clone)]
pub struct BlobEntry {
    pub offset: u32,
    pub length: u32,
}

impl BinaryParse for BlobEntry {
    type Output = Self;
    type Size = typenum::U8;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (offset, r) = r.read::<U32>();
        let (length, r) = r.read::<U32>();

        (Self { offset, length }, r)
    }
}

#[derive(Debug, Clone)]
pub struct ReferencedFileHeader {
    pub number_of_roots: u16,
    pub number_of_folders: u16,
    pub number_of_files: u16,
    pub unicode_name_block_length: u32,
}

impl BinaryParse for ReferencedFileHeader {
    type Output = Self;
    type Size = typenum::U12;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (number_of_roots, r) = r.read::<U16>();
        let (number_of_folders, r) = r.read::<U16>();
        let (number_of_files, r) = r.read::<U16>();
        // uint16   unknown, zero
        let (_unknown, r) = r.read::<U16>();
        let (unicode_name_block_length, r) = r.read::<U32>();

        (
            Self {
                number_of_roots,
                number_of_folders,
                number_of_files,
                unicode_name_block_length,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct FolderEntry {
    pub parent_folder_index: u16,
    pub number_of_folders: u16,
    pub first_folder_index: u16,
    pub number_of_files: u16,
    pub first_file_index: u16,
    pub name_length: u16,
    pub full_path_length: u16,
    pub name_offset: u32,
}

impl BinaryParse for FolderEntry {
    type Output = Self;
    type Size = typenum::U20;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        // uint16   unknown, zero
        let (_unknown, r) = r.read::<U16>();
        let (parent_folder_index, r) = r.read::<U16>();
        let (number_of_folders, r) = r.read::<U16>();
        let (first_folder_index, r) = r.read::<U16>();
        let (number_of_files, r) = r.read::<U16>();
        let (first_file_index, r) = r.read::<U16>();
        let (name_length, r) = r.read::<U16>();
        let (full_path_length, r) = r.read::<U16>();
        let (name_offset, r) = r.read::<U32>();

        (
            Self {
                parent_folder_index,
                number_of_folders,
                first_folder_index,
                number_of_files,
                first_file_index,
                name_length,
                full_path_length,
                name_offset,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub parent_folder_index: u16,
    pub full_path_length: u16,
    pub name_length: u16,
    pub name_offset: u32,
}

impl BinaryParse for FileEntry {
    type Output = Self;
    type Size = typenum::U12;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        // uint16   unknown
        let (_unknown, r) = r.read::<U16>();
        let (parent_folder_index, r) = r.read::<U16>();
        let (full_path_length, r) = r.read::<U16>();
        let (name_length, r) = r.read::<U16>();
        let (name_offset, r) = r.read::<U32>();

        (
            Self {
                parent_folder_index,
                full_path_length,
                name_length,
                name_offset,
            },
            r,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ResourceFooter {
    pub magic: u32,
    pub total_file_size: u32,
    pub version_identifier: [u8; 8],
}

impl BinaryParse for ResourceFooter {
    type Output = Self;
    type Size = typenum::U16;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (magic, r) = r.read::<U32>();
        let (total_file_size, r) = r.read::<U32>();
        let (version_identifier, r) = r.read::<[u8; 8]>();

        (
            Self {
                magic,
                total_file_size,
                version_identifier,
            },
            r,
        )
    }
}
