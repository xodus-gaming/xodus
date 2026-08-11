use std::process::ExitCode;

use serde::Deserialize;

/// Public, unauthenticated SIGL ("Store Item Generated List") ids for the
/// full current Game Pass catalogs. Documented at
/// https://www.reddit.com/r/XboxGamePass/comments/jt214y/ and used by real
/// clients (e.g. Greenlight) the same way.
const PC_SIGL_ID: &str = "fdd9e2a7-0fee-49f6-ad69-4354098401ff";

const PRODUCTS_BATCH_SIZE: usize = 100;

#[derive(Debug, Deserialize)]
struct SiglEntry {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProductsResponse {
    #[serde(rename = "Products", default)]
    products: std::collections::HashMap<String, ProductInfo>,
}

#[derive(Debug, Deserialize)]
struct ProductInfo {
    #[serde(rename = "ProductTitle")]
    product_title: String,
}

/// Lists the full current PC Game Pass catalog - every title Game Pass PC
/// currently offers, not just titles this account has played. Uses public,
/// unauthenticated Microsoft endpoints (catalog.gamepass.com), the same ones
/// real Xbox/Game Pass clients use to render their own "browse all" screens.
pub async fn run(client: &reqwest::Client, market: String, language: String) -> ExitCode {
    let store_ids = match fetch_catalog_ids(client, &market, &language).await {
        Ok(ids) => ids,
        Err(err) => {
            eprintln!("failed to fetch Game Pass catalog: {err}");
            return ExitCode::FAILURE;
        }
    };

    if store_ids.is_empty() {
        eprintln!("Game Pass catalog returned no titles");
        return ExitCode::FAILURE;
    }

    println!("{:<50} {}", "NAME", "STORE ID");
    for chunk in store_ids.chunks(PRODUCTS_BATCH_SIZE) {
        match resolve_titles(client, chunk, &market, &language).await {
            Ok(titles) => {
                for id in chunk {
                    let name = titles.get(id).map(String::as_str).unwrap_or("?");
                    println!("{:<50} {}", truncate(name, 50), id);
                }
            }
            Err(err) => {
                eprintln!("failed to resolve title names for a batch: {err}");
                for id in chunk {
                    println!("{:<50} {}", "?", id);
                }
            }
        }
    }

    ExitCode::SUCCESS
}

async fn fetch_catalog_ids(
    client: &reqwest::Client,
    market: &str,
    language: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let response = client
        .get(format!(
            "https://catalog.gamepass.com/sigls/v2?id={PC_SIGL_ID}&market={market}&language={language}"
        ))
        .send()
        .await?
        .error_for_status()?;
    let entries: Vec<SiglEntry> = response.json().await?;
    Ok(entries.into_iter().filter_map(|entry| entry.id).collect())
}

async fn resolve_titles(
    client: &reqwest::Client,
    ids: &[String],
    market: &str,
    language: &str,
) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
    let response = client
        .post(format!(
            "https://catalog.gamepass.com/v3/products?hydration=RemoteHighSapphire0&market={market}&language={language}"
        ))
        .header("ms-cv", "0.0")
        .header("calling-app-name", "xodus-cli")
        .header("calling-app-version", env!("CARGO_PKG_VERSION"))
        .json(&serde_json::json!({ "Products": ids }))
        .send()
        .await?
        .error_for_status()?;
    let data: ProductsResponse = response.json().await?;
    Ok(data
        .products
        .into_iter()
        .map(|(id, info)| (id, info.product_title))
        .collect())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigl_response_skips_the_header_entry() {
        // Trimmed from a real catalog.gamepass.com/sigls/v2 response: the
        // first element is metadata about the list itself (no "id"), the
        // rest are {"id": "<StoreId>"}.
        let json = r#"[
            {"siglId":"fdd9e2a7-0fee-49f6-ad69-4354098401ff","title":"All PC Games"},
            {"id":"9PK087LNGJC5"},
            {"id":"9NGLST31DG26"}
        ]"#;

        let entries: Vec<SiglEntry> = serde_json::from_str(json).expect("should parse");
        let ids: Vec<String> = entries.into_iter().filter_map(|e| e.id).collect();
        assert_eq!(
            ids,
            vec!["9PK087LNGJC5".to_string(), "9NGLST31DG26".to_string()]
        );
    }

    #[test]
    fn parses_real_products_response_shape() {
        // Trimmed from a real catalog.gamepass.com/v3/products response.
        let json = r#"{"Products":{"9PK087LNGJC5":{"ProductTitle":"Balatro","ProductDescription":"..."}}}"#;
        let data: ProductsResponse = serde_json::from_str(json).expect("should parse");
        assert_eq!(
            data.products
                .get("9PK087LNGJC5")
                .map(|p| p.product_title.as_str()),
            Some("Balatro")
        );
    }
}
