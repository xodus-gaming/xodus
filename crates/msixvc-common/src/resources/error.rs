use thiserror::Error;

use crate::resources::structs::{QualifierType, ResourceValueType, SectionType};

#[derive(Debug, Error)]
pub enum PriParseError {
    #[error("Encountered an unsupported magic value, cannot proceed")]
    UnknownMagic,
    #[error("PRI Descriptor is missing from the index")]
    DescriptorMissing,
    #[error("Encountered an unknown qualifier type: {0}")]
    UnknownQualifierType(#[from] num_enum::TryFromPrimitiveError<QualifierType>),
    #[error("Encountered an unknown resource value type: {0}")]
    UnknownResourceValueType(#[from] num_enum::TryFromPrimitiveError<ResourceValueType>),
    #[error(
        "Section index {0} referenced elsewhere in the index does not exist in the table of contents"
    )]
    MissingSection(u16),
    #[error("Section at index {index} was expected to be a {expected} section, but is {found:?}")]
    UnexpectedSectionType {
        index: u16,
        expected: &'static str,
        found: SectionType,
    },
    #[error("Encountered an out-of-bounds offset or length while parsing {context}")]
    Truncated { context: &'static str },
    #[error("Encountered a candidate of unsupported type {0}, cannot resolve its value")]
    UnsupportedCandidateType(u8),
    #[error("Unexpected IO error {0:?}")]
    Io(#[from] std::io::Error),
}

impl PriParseError {
    #[inline]
    pub fn truncated(context: &'static str) -> Self {
        Self::Truncated { context }
    }
}
