use std::process::ExitCode;

use serde::Deserialize;
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TitleHistoryResponse {
    titles: Vec<TitleEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TitleEntry {
    title_id: String,
    name: String,
    pfn: Option<String>,
    #[serde(default)]
    devices: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CatalogLookupResponse {
    #[serde(rename = "BigIds", default)]
    big_ids: Vec<String>,
}

/// Lists titles from the account's real Xbox Live title history (recently
/// played), resolving each one's Microsoft Store product id where possible.
/// Meant to answer "what product id do I even pass to `download`/`streaming`"
/// without guessing store ids from search engines - only titles this account
/// has actually played show up here.
pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    market: Option<String>,
    max_items: usize,
) -> ExitCode {
    let dev_token = tokens.get_device_sts_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        eprintln!("Invalid device STS token");
        return ExitCode::FAILURE;
    };
    let user_token = match tokens.get_user_sts_token() {
        Ok(token) => token,
        Err(_) => {
            eprintln!("Not logged in - run `xodus-cli login` first");
            return ExitCode::FAILURE;
        }
    };
    let Token::Legacy(legacy) = user_token else {
        eprintln!("Invalid user STS token");
        return ExitCode::FAILURE;
    };

    let xsts = xodus::api::xbox::run(client, dev_token, legacy, "http://xboxlive.com").await;
    let Some(xid) = xsts.xid().map(|xid| xid.to_string()) else {
        eprintln!("Could not determine xuid from token");
        return ExitCode::FAILURE;
    };
    let auth = xodus::api::xbox::get_xsts_auth_header(xsts);

    let response = client
        .get(format!(
            "https://titlehub.xboxlive.com/users/xuid({xid})/titles/titlehistory/decoration/scid?maxItems={max_items}"
        ))
        .header("Authorization", auth)
        .header("x-xbl-contract-version", "2")
        .header("Accept-Language", "en-US")
        .send()
        .await;

    let response = match response {
        Ok(response) => response,
        Err(err) => {
            eprintln!("titlehub request failed: {err}");
            return ExitCode::FAILURE;
        }
    };

    if !response.status().is_success() {
        eprintln!("titlehub request failed: HTTP {}", response.status());
        return ExitCode::FAILURE;
    }

    let history: TitleHistoryResponse = match response.json().await {
        Ok(history) => history,
        Err(err) => {
            eprintln!("failed to parse titlehub response: {err}");
            return ExitCode::FAILURE;
        }
    };

    let market = market.unwrap_or_else(|| "US".to_string());

    // Store id lookups are independent per title, so run them concurrently
    // rather than awaiting one at a time - with the default max_items=30
    // this is the difference between one round-trip's latency and thirty.
    let store_ids = futures_util::future::join_all(history.titles.iter().map(|title| {
        let market = &market;
        async move {
            match &title.pfn {
                Some(pfn) => lookup_store_id(client, pfn, market).await,
                None => None,
            }
        }
    }))
    .await;

    println!(
        "{:<45} {:<25} {:<12} {}",
        "NAME", "DEVICES", "TITLE ID", "STORE ID"
    );
    for (title, store_id) in history.titles.iter().zip(store_ids) {
        println!(
            "{:<45} {:<25} {:<12} {}",
            truncate(&title.name, 45),
            title.devices.join(","),
            title.title_id,
            store_id.unwrap_or_else(|| "?".to_string())
        );
    }

    ExitCode::SUCCESS
}

async fn lookup_store_id(client: &reqwest::Client, pfn: &str, market: &str) -> Option<String> {
    let response = client
        .get(format!(
            "https://displaycatalog.mp.microsoft.com/v7.0/products/lookup?alternateId=PackageFamilyName&value={pfn}&market={market}&languages=en-US"
        ))
        .send()
        .await
        .ok()?;
    let data: CatalogLookupResponse = response.json().await.ok()?;
    data.big_ids.into_iter().next()
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
    async fn gives_a_clean_error_when_not_logged_in() {
        let tokens = TokenManager::with_memory();
        // A device token is always present in real usage (ensure_device_credentials
        // runs at binary startup), but deliberately no user token here -
        // this simulates a session that has never run `xodus-cli login`.
        tokens
            .save_device_token(PASSPORT_STS.to_string(), dummy_legacy_token())
            .unwrap();

        let client = reqwest::Client::new();
        let result = run(&client, &tokens, None, 10).await;

        assert_eq!(
            result,
            ExitCode::FAILURE,
            "expected a clean failure, not a panic, when not logged in"
        );
    }

    #[test]
    fn truncate_keeps_short_strings_unchanged() {
        assert_eq!(truncate("Balatro", 45), "Balatro");
    }

    #[test]
    fn truncate_shortens_long_strings_with_ellipsis() {
        let truncated = truncate("A very long title that exceeds the column width", 20);
        assert_eq!(truncated.chars().count(), 20);
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn parses_real_titlehub_response_shape() {
        // Trimmed from a real titlehub.xboxlive.com titlehistory response.
        let json = r#"{"xuid":"2535425365223098","titles":[
            {"titleId":"1792830437","pfn":"PlayStack.Balatro_3wcqaesafpzfy","name":"Balatro","type":"Game","devices":["PC","XboxOne","XboxSeries"]},
            {"titleId":"1414793202","pfn":null,"name":"GTA IV","type":"Game","devices":["Xbox360","XboxOne","XboxSeries"]}
        ]}"#;

        let history: TitleHistoryResponse = serde_json::from_str(json).expect("should parse");
        assert_eq!(history.titles.len(), 2);
        assert_eq!(history.titles[0].name, "Balatro");
        assert_eq!(
            history.titles[0].pfn.as_deref(),
            Some("PlayStack.Balatro_3wcqaesafpzfy")
        );
        assert_eq!(history.titles[1].pfn, None);
    }

    #[test]
    fn parses_real_catalog_lookup_response_shape() {
        // Trimmed from a real displaycatalog.mp.microsoft.com lookup response.
        let json = r#"{"BigIds":["9PK087LNGJC5"],"HasMorePages":false,"Products":[]}"#;
        let data: CatalogLookupResponse = serde_json::from_str(json).expect("should parse");
        assert_eq!(data.big_ids, vec!["9PK087LNGJC5".to_string()]);
    }
}
