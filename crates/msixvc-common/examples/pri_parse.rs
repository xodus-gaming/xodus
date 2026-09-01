//! Reads a PRI file and either lists its resource paths or resolves one against
//! a set of qualifiers - see `--help` for the full list of qualifier flags.
//!
//! ```sh
//! # List every resource path in the file
//! cargo run -p msixvc-common --example pri_parse -- Resources.pri
//!
//! # Resolve one, preferring Polish then German
//! cargo run -p msixvc-common --example pri_parse -- Resources.pri /resources/Feature_StW --lang pl-PL --lang de-DE
//!
//! # Show every qualifier set defined for a resource and which one wins
//! cargo run -p msixvc-common --example pri_parse -- Resources.pri /resources/Feature_StW --lang pl -v
//! ```

use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use msixvc_common::resources::pri::Pri;
use msixvc_common::resources::query::{QualifierContext, QualifierSetMatch};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Inspect and resolve resources in a Package Resource Index (PRI) file"
)]
struct Args {
    /// Path to the PRI file to read.
    file: PathBuf,

    /// Resource path to resolve, e.g. "/resources/AppDisplayName". Lists every
    /// known resource path instead if omitted.
    resource: Option<String>,

    /// Preferred language tag (BCP-47, e.g. de-DE). Repeatable, most preferred
    /// first.
    #[arg(long = "lang", value_name = "TAG")]
    language: Vec<String>,

    /// Display scale factor, e.g. 100, 150, 200.
    #[arg(long, value_name = "N")]
    scale: Option<u32>,

    /// Target size in pixels, for size-scalable resources like icons.
    #[arg(long, value_name = "N")]
    target_size: Option<u32>,

    /// Contrast qualifier value, e.g. "standard" or "high".
    #[arg(long, value_name = "VALUE")]
    contrast: Option<String>,

    /// Theme qualifier value, e.g. "light" or "dark".
    #[arg(long, value_name = "VALUE")]
    theme: Option<String>,

    /// Home region qualifier value, e.g. "US".
    #[arg(long, value_name = "VALUE")]
    home_region: Option<String>,

    /// Layout direction qualifier value, e.g. "LTR" or "RTL".
    #[arg(long, value_name = "VALUE")]
    layout_direction: Option<String>,

    /// Device family qualifier value, e.g. "Desktop" or "Mobile".
    #[arg(long, value_name = "VALUE")]
    device_family: Option<String>,

    /// Configuration qualifier value.
    #[arg(long, value_name = "VALUE")]
    configuration: Option<String>,

    /// Alternate form qualifier value.
    #[arg(long, value_name = "VALUE")]
    alternate_form: Option<String>,

    /// DirectX feature level qualifier value.
    #[arg(long, value_name = "VALUE")]
    dx_feature_level: Option<String>,

    /// Show every qualifier set defined for a resource's decision - its
    /// qualifiers, the score it got against the given context, and which
    /// candidate it selects - instead of just the final resolved value. Applies
    /// to every resource path when none is given.
    #[arg(short, long)]
    verbose: bool,
}

impl Args {
    fn qualifier_context(&self) -> QualifierContext {
        let arc = |s: &String| Arc::from(s.as_str());
        QualifierContext {
            language: self.language.iter().map(arc).collect(),
            scale: self.scale,
            target_size: self.target_size,
            contrast: self.contrast.as_ref().map(arc),
            theme: self.theme.as_ref().map(arc),
            home_region: self.home_region.as_ref().map(arc),
            layout_direction: self.layout_direction.as_ref().map(arc),
            device_family: self.device_family.as_ref().map(arc),
            configuration: self.configuration.as_ref().map(arc),
            alternate_form: self.alternate_form.as_ref().map(arc),
            dx_feature_level: self.dx_feature_level.as_ref().map(arc),
            custom: Default::default(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let ctx = args.qualifier_context();

    let file = tokio::fs::File::open(&args.file).await?;
    let pri = Pri::read(file).await?;

    match &args.resource {
        Some(resource) => resolve_one(&pri, resource, &ctx, args.verbose)?,
        None => list_paths(&pri, &ctx, args.verbose)?,
    }

    Ok(())
}

fn list_paths(pri: &Pri, ctx: &QualifierContext, verbose: bool) -> Result<(), Box<dyn Error>> {
    let mut paths: Vec<&str> = pri.resource_paths().collect();
    paths.sort_unstable();

    println!("{} resource path(s):", paths.len());
    for path in &paths {
        println!("  {path}");
    }

    if verbose {
        for path in &paths {
            println!();
            print_decisions(pri, path, ctx)?;
        }
    }

    Ok(())
}

fn resolve_one(
    pri: &Pri,
    resource: &str,
    ctx: &QualifierContext,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    if verbose {
        print_decisions(pri, resource, ctx)?;
        println!();
    }

    match pri.resolve(resource, ctx)? {
        Some(value) => println!("{resource} = {value:?}"),
        None => println!("{resource}: no candidate matched the given qualifiers"),
    }

    Ok(())
}

/// Prints every qualifier set defined for `resource`'s decision, marking
/// whichever one [`Pri::resolve`] would actually pick for `ctx`.
fn print_decisions(
    pri: &Pri,
    resource: &str,
    ctx: &QualifierContext,
) -> Result<(), Box<dyn Error>> {
    let Some(matches) = pri.explain(resource, ctx)? else {
        println!("{resource}: not found");
        return Ok(());
    };

    let best_score = matches.iter().filter_map(|m| m.score).max();

    println!("{resource}: {} qualifier set(s) defined", matches.len());
    for (
        index,
        QualifierSetMatch {
            qualifiers,
            score,
            candidate,
        },
    ) in matches.iter().enumerate()
    {
        let selected = *score == best_score && score.is_some();
        let marker = if selected { "=>" } else { "  " };

        let qualifiers = if qualifiers.is_empty() {
            "(neutral: no qualifiers)".to_string()
        } else {
            qualifiers
                .iter()
                .map(|q| {
                    format!(
                        "{:?}={} [fallback {}]",
                        q.qualifier_type, q.value, q.fallback_score
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        let score = score.map_or_else(|| "no match".to_string(), |s| format!("score {s}"));

        println!("  {marker} [{index}] {qualifiers}");
        println!("       {score} -> {candidate:?}");
    }

    Ok(())
}
