use std::collections::HashSet;
use std::fmt::Display;

use futures_util::future::join_all;
use inquire::Select;
use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::api::displaycatalog::find_products_by_id;
use xodus::models::displaycatalog::SkuLocalizedProperty;
use xodus::models::packagespc::{PackageDetails, PackageResponse};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

struct BundleCandidate {
    id: String,
    title: Option<String>,
}

impl Display for BundleCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.title {
            Some(title) => f.write_fmt(format_args!("{} ({})", title, self.id)),
            None => f.write_str(&self.id),
        }
    }
}

/// Picks the display title out of a SKU's localized properties. Split out from
/// `resolve_title` so this part of the extraction (as opposed to the network
/// call around it) can be unit tested directly.
fn extract_title(localized_properties: &[SkuLocalizedProperty]) -> Option<String> {
    localized_properties
        .first()
        .map(|prop| prop.sku_title.clone())
}

async fn resolve_title(
    client: &reqwest::Client,
    id: &str,
    market: Option<String>,
) -> Option<String> {
    let displaycatalog = find_products_by_id(
        client,
        id.to_owned(),
        market.unwrap_or("neutral".to_owned()),
        vec!["en".to_string(), "neutral".to_string()],
    )
    .await
    .inspect_err(|err| log::warn!("Failed to resolve title for bundle sub-product {id}: {err}"))
    .ok()?;

    let availability = displaycatalog.product.display_sku_availabilities.first()?;
    extract_title(&availability.sku.localized_properties)
}

pub async fn get_content_id(
    client: &reqwest::Client,
    product: String,
    market: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    get_content_id_impl(client, product, market, &mut HashSet::new()).await
}

/// `seen` tracks every product id already visited in this resolution chain. A
/// bundle's sub-products can include the bundle's own id (see #17/#129), and
/// without this guard selecting that entry would recurse into itself forever.
async fn get_content_id_impl(
    client: &reqwest::Client,
    product: String,
    market: Option<String>,
    seen: &mut HashSet<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if !seen.insert(product.clone()) {
        return Err(Box::new(std::io::Error::other(format!(
            "bundle resolution looped back to an already-visited product id ({product}); refusing to recurse forever"
        ))));
    }

    let displaycatalog = find_products_by_id(
        client,
        product,
        market.clone().unwrap_or("neutral".to_owned()),
        vec!["en".to_string(), "neutral".to_string()],
    )
    .await?;

    let product_details = displaycatalog.product;

    let mut found_package = None;
    let mut subprods: Vec<String> = vec![];
    'o: for availability in &product_details.display_sku_availabilities {
        for package in &availability.sku.properties.packages {
            if package
                .platform_dependencies
                .iter()
                .any(|dep| dep.platform_name == "Windows.Desktop")
            {
                found_package = Some(package);
                break 'o;
            }
        }
        for availability in &availability.availabilities {
            if let Some(licensing_data) = &availability.licensing_data {
                for satisfies in &licensing_data.satisfying_entitlement_keys {
                    for entitlement_key in &satisfies.entitlement_keys {
                        let key: Vec<&str> = entitlement_key.split(":").collect();
                        if key.len() == 3 && key[0] == "big" {
                            subprods.push(key[1].to_string());
                        }
                    }
                }
            }
        }
    }
    subprods.sort();
    subprods.dedup();
    // Drop anything already visited (e.g. the bundle's own id showing up in
    // its own sub-product list) before it's even offered as a choice.
    subprods.retain(|id| !seen.contains(id));

    let Some(package) = found_package else {
        if !subprods.is_empty() {
            let candidates = join_all(subprods.into_iter().map(|id| {
                let market = market.clone();
                async move {
                    let title = resolve_title(client, &id, market).await;
                    BundleCandidate { id, title }
                }
            }))
            .await;

            let Ok(item) = Select::new("Select files to download", candidates)
                .with_page_size(30)
                .prompt()
            else {
                return Err(Box::new(std::io::Error::other("Selection failed")));
            };
            return Box::pin(get_content_id_impl(client, item.id, market, seen)).await;
        }

        return Err(Box::new(std::io::Error::other(
            "Windows.Desktop package not found, if you believe this is an error, please report it",
        )));
    };

    let Some(content_id) = &package.content_id else {
        log::error!("ContentId not found, if you believe this is an error, please report it");
        return Err(Box::new(std::io::Error::other(
            "ContentId not found, if you believe this is an error, please report it",
        )));
    };
    Ok(content_id.to_owned())
}

pub async fn get_packages(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
) -> Result<PackageDetails, Box<dyn std::error::Error>> {
    let dev_token = tokens.get_device_sts_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        return Err(Box::new(std::io::Error::other("Invalid STS token")));
    };
    let user_token = tokens.get_user_sts_token().unwrap();
    let Token::Legacy(legacy) = user_token else {
        return Err(Box::new(std::io::Error::other("Unsupported user token")));
    };

    let xsts_token =
        xodus::api::xbox::run(client, dev_token, legacy, "http://update.xboxlive.com").await;

    let response = client
        .get(format!(
            "{XBOX_LIVE_PACKAGES_PC}/GetBasePackage/{content_id}"
        ))
        .header("x-xbl-contract-version", "3")
        .header(
            "Authorization",
            xodus::api::xbox::get_xsts_auth_header(xsts_token),
        )
        .send()
        .await
        .unwrap();

    let res: PackageResponse = response.json().await.expect("Failed to get data");

    let PackageResponse::Found(package) = res else {
        return Err(Box::new(std::io::Error::other(
            "Package was not found, is it owned by the user?",
        )));
    };
    Ok(package)
}

#[cfg(test)]
mod tests {
    use xodus::models::displaycatalog::LegalText;

    use super::*;

    fn sample_localized_property(title: &str) -> SkuLocalizedProperty {
        SkuLocalizedProperty {
            contributors: vec![],
            features: vec![],
            minimum_notes: String::new(),
            recommended_notes: String::new(),
            release_notes: String::new(),
            display_platform_properties: None,
            sku_description: String::new(),
            sku_title: title.to_string(),
            sku_button_title: String::new(),
            delivery_date_overlay: None,
            text_resources: None,
            legal_text: LegalText {
                additional_license_terms: String::new(),
                copyright: String::new(),
                copyright_uri: String::new(),
                privacy_policy: String::new(),
                privacy_policy_uri: String::new(),
                tou: String::new(),
                tou_uri: String::new(),
            },
            language: String::new(),
            markets: vec![],
        }
    }

    #[test]
    fn extract_title_returns_first_localized_title() {
        let properties = vec![sample_localized_property(
            "Minecraft: Java & Bedrock Edition",
        )];

        assert_eq!(
            extract_title(&properties),
            Some("Minecraft: Java & Bedrock Edition".to_string())
        );
    }

    #[test]
    fn extract_title_returns_none_when_no_localized_properties() {
        assert_eq!(extract_title(&[]), None);
    }

    #[test]
    fn bundle_candidate_displays_title_and_id_when_resolved() {
        let candidate = BundleCandidate {
            id: "9NBLGGH2JHXJ".to_string(),
            title: Some("Minecraft: Bedrock Edition".to_string()),
        };

        assert_eq!(
            candidate.to_string(),
            "Minecraft: Bedrock Edition (9NBLGGH2JHXJ)"
        );
    }

    #[test]
    fn bundle_candidate_displays_bare_id_when_title_unresolved() {
        let candidate = BundleCandidate {
            id: "9NBLGGH2JHXJ".to_string(),
            title: None,
        };

        assert_eq!(candidate.to_string(), "9NBLGGH2JHXJ");
    }

    #[tokio::test]
    async fn refuses_to_recurse_into_an_already_visited_product_id() {
        let client = reqwest::Client::new();
        let mut seen = HashSet::from(["9NXP44L49SHJ".to_string()]);

        let error = get_content_id_impl(&client, "9NXP44L49SHJ".to_string(), None, &mut seen)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("already-visited"));
    }
}
