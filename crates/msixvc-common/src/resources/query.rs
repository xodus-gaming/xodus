//! The runtime side of resource resolution: given a [`QualifierContext`], picks the
//! best-matching candidate for a resource path and decodes its value.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;

use crate::resources::error::PriParseError;
use crate::resources::index::PriIndex;
use crate::resources::index::decisions::{Decision, Qualifier, QualifierSet};
use crate::resources::index::resource_map::{CandidateValue, ResourceMap};
use crate::resources::structs::{QualifierType, ResourceValueType};

/// The runtime qualifier values a [`crate::resources::pri::Pri::resolve`] call is
/// evaluated against.
#[derive(Debug, Clone, Default)]
pub struct QualifierContext {
    /// BCP-47 language tags, in fallback order (most preferred first).
    pub language: Vec<Arc<str>>,
    pub scale: Option<u32>,
    pub target_size: Option<u32>,
    pub contrast: Option<Arc<str>>,
    pub theme: Option<Arc<str>>,
    pub home_region: Option<Arc<str>>,
    pub layout_direction: Option<Arc<str>>,
    pub device_family: Option<Arc<str>>,
    pub configuration: Option<Arc<str>>,
    pub alternate_form: Option<Arc<str>>,
    pub dx_feature_level: Option<Arc<str>>,
    /// Named qualifiers of type [`QualifierType::Custom`]. Currently unused: the
    /// file format doesn't expose which named qualifier a `Custom`-typed entry
    /// refers to (see [`evaluate_qualifier`]'s `Custom` arm), so there's nothing
    /// to look up by yet.
    pub custom: HashMap<Arc<str>, Arc<str>>,
}

/// The resolved value of a matched resource candidate.
#[derive(Debug, Clone)]
pub enum ResolvedValue {
    String(Arc<str>),
    Path(Arc<str>),
    Blob(Bytes),
    /// The candidate's data lives in a Data Item Section of another, externally
    /// referenced PRI file. Following that reference (loading the sibling file and
    /// resolving `data_item_index` within it) isn't implemented yet - the caller
    /// gets these raw indices back instead.
    External {
        referenced_file_index: u16,
        section_index: u16,
        data_item_index: u16,
    },
}

/// A resource's decision, alongside the candidate slice paired with its
/// qualifier sets.
type LocatedDecision<'a> = (&'a ResourceMap, &'a Decision, &'a [CandidateValue]);

/// Looks up `path`'s decision and the candidate slice paired with its qualifier
/// sets, shared by [`resolve`] and [`explain`]. `Ok(None)` means `path` doesn't
/// resolve to an item at all; a structurally invalid candidate range is a real
/// parse error, not a "not found", so that case is `Err` instead.
fn locate<'a>(
    index: &'a PriIndex,
    path: &str,
) -> Result<Option<LocatedDecision<'a>>, PriParseError> {
    let Some(resource_map) = index.primary_resource_map() else {
        return Ok(None);
    };
    let Some(schema) = index
        .hierarchical_schemas
        .get(&resource_map.hierarchical_schema_section_index)
    else {
        return Ok(None);
    };
    let Some(&index_property) = schema.paths.get(path) else {
        return Ok(None);
    };
    let Some(item) = resource_map.items.get(&index_property) else {
        return Ok(None);
    };
    let Some(decision_info) = index
        .decision_infos
        .get(&resource_map.decision_info_section_index)
    else {
        return Ok(None);
    };
    let Some(decision) = decision_info.decisions.get(item.decision_index as usize) else {
        return Ok(None);
    };

    let first_candidate = item.first_candidate_index as usize;
    let candidates = resource_map
        .candidates
        .get(first_candidate..first_candidate + decision.qualifier_sets.len())
        .ok_or(PriParseError::truncated("resource map candidate range"))?;

    Ok(Some((resource_map, decision, candidates)))
}

pub(crate) fn resolve(
    index: &PriIndex,
    path: &str,
    ctx: &QualifierContext,
) -> Result<Option<ResolvedValue>, PriParseError> {
    let Some((resource_map, decision, candidates)) = locate(index, path)? else {
        return Ok(None);
    };

    let best = decision
        .qualifier_sets
        .iter()
        .zip(candidates)
        .filter_map(|(set, candidate)| evaluate(set, ctx).map(|score| (score, candidate)))
        // Keep the first-seen candidate on ties: the file's own qualifier set order
        // already reflects preference among otherwise-equal matches.
        .fold(
            None,
            |best: Option<(u32, &CandidateValue)>, (score, candidate)| match best {
                Some((best_score, _)) if best_score >= score => best,
                _ => Some((score, candidate)),
            },
        );

    let Some((_, candidate)) = best else {
        return Ok(None);
    };

    resolve_candidate(index, resource_map, candidate).map(Some)
}

/// One of a resource's defined qualifier sets, alongside the score it received
/// against a [`QualifierContext`] (`None` if it didn't match at all) and the
/// candidate it's paired with - see
/// [`Pri::explain`](crate::resources::pri::Pri::explain).
#[derive(Debug, Clone)]
pub struct QualifierSetMatch {
    pub qualifiers: Vec<Qualifier>,
    pub score: Option<u32>,
    pub candidate: CandidateValue,
}

pub(crate) fn explain(
    index: &PriIndex,
    path: &str,
    ctx: &QualifierContext,
) -> Result<Option<Vec<QualifierSetMatch>>, PriParseError> {
    let Some((_, decision, candidates)) = locate(index, path)? else {
        return Ok(None);
    };

    Ok(Some(
        decision
            .qualifier_sets
            .iter()
            .zip(candidates)
            .map(|(set, candidate)| QualifierSetMatch {
                qualifiers: set.qualifiers.clone(),
                score: evaluate(set, ctx),
                candidate: candidate.clone(),
            })
            .collect(),
    ))
}

/// Returns `Some(score)` (higher is better) if every qualifier in `set` is
/// satisfied by `ctx`, or `None` if any of them isn't.
fn evaluate(set: &QualifierSet, ctx: &QualifierContext) -> Option<u32> {
    let mut score = 0u32;
    for qualifier in &set.qualifiers {
        let qualifier_score = evaluate_qualifier(qualifier.qualifier_type, &qualifier.value, ctx)?;
        score = score
            .saturating_add(qualifier_score)
            .saturating_add(qualifier.fallback_score as u32);
    }
    Some(score)
}

fn evaluate_qualifier(
    qualifier_type: QualifierType,
    value: &str,
    ctx: &QualifierContext,
) -> Option<u32> {
    match qualifier_type {
        QualifierType::Language => ctx
            .language
            .iter()
            .enumerate()
            .filter_map(|(position, preferred)| {
                let specificity = language_match_score(preferred, value)?;
                Some(specificity.saturating_add(1000u32.saturating_sub(position as u32)))
            })
            .max(),
        QualifierType::Scale => match_numeric(ctx.scale, value),
        QualifierType::TargetSize => match_numeric(ctx.target_size, value),
        QualifierType::Contrast => match_exact(ctx.contrast.as_deref(), value),
        QualifierType::Theme => match_exact(ctx.theme.as_deref(), value),
        QualifierType::HomeRegion => match_exact(ctx.home_region.as_deref(), value),
        QualifierType::LayoutDirection => match_exact(ctx.layout_direction.as_deref(), value),
        QualifierType::DeviceFamily => match_exact(ctx.device_family.as_deref(), value),
        QualifierType::Configuration => match_exact(ctx.configuration.as_deref(), value),
        QualifierType::AlternateForm => match_exact(ctx.alternate_form.as_deref(), value),
        QualifierType::DXFeatureLevel => match_exact(ctx.dx_feature_level.as_deref(), value),
        // The custom qualifier's name isn't recoverable from the file's documented
        // fields (see `QualifierContext::custom`), so it can't be looked up yet -
        // treat it as an always-satisfied, zero-weight qualifier rather than
        // blocking resolution entirely.
        QualifierType::Custom => Some(0),
    }
}

fn match_exact(current: Option<&str>, value: &str) -> Option<u32> {
    current
        .filter(|current| current.eq_ignore_ascii_case(value))
        .map(|_| 1000)
}

fn match_numeric(current: Option<u32>, value: &str) -> Option<u32> {
    let current = current?;
    let value: u32 = value.parse().ok()?;
    // A resource authored for a given qualifier value is an acceptable (if
    // imperfect) stand-in at any larger runtime value, but never at a smaller one -
    // prefer whichever qualifies is closest to (at or below) the runtime value.
    (value <= current).then(|| 1000u32.saturating_sub((current - value).min(1000)))
}

/// Scores how well a preferred language tag matches a candidate's qualifier
/// value: an exact tag match scores highest; sharing just the primary subtag (e.g.
/// requesting `pl` matches a candidate tagged `pl-PL`, and requesting `de-DE`
/// matches one tagged just `de`) scores lower but still matches - real-world PRI
/// files store region-specific tags like `PL-PL`, so a request for the bare
/// language needs to find them too, not just the reverse. Anything else doesn't
/// match at all.
fn language_match_score(preferred: &str, candidate: &str) -> Option<u32> {
    if preferred.eq_ignore_ascii_case(candidate) {
        Some(1000)
    } else if primary_subtag(preferred).eq_ignore_ascii_case(primary_subtag(candidate)) {
        Some(500)
    } else {
        None
    }
}

fn primary_subtag(tag: &str) -> &str {
    tag.split_once('-').map_or(tag, |(primary, _)| primary)
}

fn resolve_candidate(
    index: &PriIndex,
    resource_map: &ResourceMap,
    candidate: &CandidateValue,
) -> Result<ResolvedValue, PriParseError> {
    match candidate {
        CandidateValue::Embedded {
            resource_value_type_index,
            data,
        } => Ok(decode_value(
            data,
            resource_value_type(resource_map, *resource_value_type_index)?,
        )),
        CandidateValue::DataItem {
            resource_value_type_index,
            section_index,
            data_item_index,
        } => {
            let value_type = resource_value_type(resource_map, *resource_value_type_index)?;
            let data = index
                .data_item_sections
                .get(section_index)
                .ok_or(PriParseError::MissingSection(*section_index))?
                .get(*data_item_index)
                .ok_or(PriParseError::truncated("data item index"))?;
            Ok(decode_value(data, value_type))
        }
        CandidateValue::External {
            referenced_file_index,
            section_index,
            data_item_index,
            ..
        } => Ok(ResolvedValue::External {
            referenced_file_index: *referenced_file_index,
            section_index: *section_index,
            data_item_index: *data_item_index,
        }),
        CandidateValue::Unknown { candidate_type } => {
            Err(PriParseError::UnsupportedCandidateType(*candidate_type))
        }
    }
}

fn resource_value_type(
    resource_map: &ResourceMap,
    index: u8,
) -> Result<ResourceValueType, PriParseError> {
    resource_map
        .resource_value_types
        .get(index as usize)
        .copied()
        .ok_or(PriParseError::truncated("resource value type index"))
}

fn decode_value(bytes: &Bytes, value_type: ResourceValueType) -> ResolvedValue {
    match value_type {
        ResourceValueType::String => ResolvedValue::String(decode_text(bytes)),
        ResourceValueType::AsciiString => ResolvedValue::String(decode_ascii_text(bytes)),
        ResourceValueType::Utf8String => ResolvedValue::String(decode_utf8_text(bytes)),
        ResourceValueType::Path => ResolvedValue::Path(decode_text(bytes)),
        ResourceValueType::AsciiPath => ResolvedValue::Path(decode_ascii_text(bytes)),
        ResourceValueType::Utf8Path => ResolvedValue::Path(decode_utf8_text(bytes)),
        ResourceValueType::EmbeddedData => ResolvedValue::Blob(bytes.clone()),
    }
}

/// Stored text values are `NUL`-terminated (the entry's declared length includes
/// the terminator), so it's trimmed here rather than left in every resolved value.
fn trim_nul(s: String) -> Arc<str> {
    Arc::from(s.trim_end_matches('\0'))
}

fn decode_text(bytes: &[u8]) -> Arc<str> {
    trim_nul(String::from_utf16le_lossy(bytes))
}

fn decode_ascii_text(bytes: &[u8]) -> Arc<str> {
    trim_nul(bytes.iter().map(|&b| b as char).collect())
}

fn decode_utf8_text(bytes: &[u8]) -> Arc<str> {
    trim_nul(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_match_score_exact_and_primary_subtag_fallback() {
        // Exact match scores highest.
        let exact = language_match_score("en-US", "en-US").unwrap();
        // A specific request falls back to a neutral candidate...
        let specific_to_neutral = language_match_score("de-DE", "de").unwrap();
        // ...and a neutral request finds a region-specific candidate too, since
        // real-world PRI files store tags like `PL-PL` rather than bare `pl`.
        let neutral_to_specific = language_match_score("pl", "PL-PL").unwrap();

        assert!(exact > specific_to_neutral);
        assert!(exact > neutral_to_specific);
        assert!(language_match_score("en-US", "fr").is_none());
    }

    #[test]
    fn test_match_numeric_prefers_closest_at_or_below() {
        assert!(match_numeric(Some(200), "100").unwrap() > match_numeric(Some(200), "50").unwrap());
        assert_eq!(
            match_numeric(Some(200), "100"),
            match_numeric(Some(200), "100")
        );
        assert!(match_numeric(Some(100), "200").is_none());
        assert!(match_numeric(None, "100").is_none());
    }

    #[test]
    fn test_evaluate_requires_every_qualifier_to_match() {
        use crate::resources::index::decisions::Qualifier;

        let set = QualifierSet {
            qualifiers: vec![
                Qualifier {
                    qualifier_type: QualifierType::Language,
                    value: Arc::from("en-US"),
                    priority: 0,
                    fallback_score: 1000,
                },
                Qualifier {
                    qualifier_type: QualifierType::Theme,
                    value: Arc::from("dark"),
                    priority: 0,
                    fallback_score: 1000,
                },
            ],
        };

        let matching = QualifierContext {
            language: vec![Arc::from("en-US")],
            theme: Some(Arc::from("dark")),
            ..Default::default()
        };
        assert!(evaluate(&set, &matching).is_some());

        let partial = QualifierContext {
            language: vec![Arc::from("en-US")],
            theme: Some(Arc::from("light")),
            ..Default::default()
        };
        assert!(evaluate(&set, &partial).is_none());
    }
}
