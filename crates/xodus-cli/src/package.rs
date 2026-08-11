use inquire::Select;
use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::api::displaycatalog::find_products_by_id;
use xodus::models::packagespc::{PackageDetails, PackageResponse};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

pub async fn get_content_id(
    client: &reqwest::Client,
    product: String,
    market: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
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

    let Some(package) = found_package else {
        if !subprods.is_empty() {
            let Ok(item) = Select::new("Select files to download", subprods)
                .with_page_size(30)
                .prompt()
            else {
                return Err(Box::new(std::io::Error::other("Selection failed")));
            };
            return Box::pin(get_content_id(client, item, market)).await;
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
    let user_token = tokens.get_user_sts_token().map_err(|_| {
        Box::new(std::io::Error::other(
            "Not logged in - run `xodus-cli login` first",
        )) as Box<dyn std::error::Error>
    })?;
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
    use super::*;
    use xodus::models::secrets::LegacyToken;
    use xodus::models::soap::Timestamp;
    use xodus::tokens::PASSPORT_STS;

    fn dummy_legacy_token() -> Token {
        Token::Legacy(LegacyToken {
            key_name: None,
            token: "dummy".to_string(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp {
                id: None,
                created: "2026-01-01T00:00:00Z".to_string(),
                expires: "2099-01-01T00:00:00Z".to_string(),
            },
        })
    }

    #[tokio::test]
    async fn get_packages_gives_a_clean_error_when_not_logged_in() {
        let tokens = TokenManager::with_memory();
        // A device token is always present in real usage (ensure_device_credentials
        // runs at binary startup), but deliberately no user token here - this
        // simulates a session that has never run `xodus-cli login`.
        tokens
            .save_device_token(PASSPORT_STS.to_string(), dummy_legacy_token())
            .unwrap();

        let client = reqwest::Client::new();
        let result = get_packages(&client, &tokens, "unused-content-id".to_string()).await;

        let err = result.expect_err("expected a clean error, not a panic, when not logged in");
        assert!(
            err.to_string().contains("run `xodus-cli login` first"),
            "unexpected error message: {err}"
        );
    }
}
