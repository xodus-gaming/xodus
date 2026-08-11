use xodus::licensing::splicense::{DeviceKey, SPLicense};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::tokens::TokenManager;

pub async fn get_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
) -> std::result::Result<(DeviceKey, SPLicense), String> {
    let dev_token = tokens.get_device_sts_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        return Err("Invalid STS token".to_string());
    };
    let user = tokens
        .get_user()
        .map_err(|_| "Not logged in - run `xodus-cli login` first".to_string())?;
    let user_token = tokens
        .get_user_sts_token()
        .map_err(|_| "Not logged in - run `xodus-cli login` first".to_string())?;
    let Token::Legacy(legacy) = user_token else {
        return Err("Unspported user token".to_string());
    };

    let ms_device_token = xodus::api::live::exchange_device_token(
        client,
        dev_token.clone(),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .unwrap();

    let user_token = xodus::api::live::exchange_user_token(
        client,
        legacy,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let ms_device_token: Token = ms_device_token.into();
    let Token::Compact(ms_device_token) = ms_device_token else {
        return Err("Unsupported token".to_string());
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err("Failed to get exchange MS token".to_string());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => unreachable!("Only responses are handled"),
    };
    let Token::Compact(user_token) = user_token else {
        return Err("Unsupported token".to_string());
    };

    let (_response, game_license) = xodus::licensing::content::get_license_content(
        client,
        ms_device_token,
        user_token,
        user.puid,
        content_id,
        market,
    )
    .await
    .expect("failed to get license");

    let game_splicense = SPLicense::parse_base64(&game_license.splicense_block)
        .expect("could not parse base64 game SPLicense");

    let dev_license = tokens.get_device_license().unwrap();
    let device_license = SPLicense::parse_base64(&dev_license.splicense)
        .expect("could not parse base64 device SPLicense");
    let key = device_license
        .encrypted_device_key
        .unwrap()
        .derive_device_key();
    Ok((key, game_splicense))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xodus::models::secrets::LegacyToken;
    use xodus::tokens::PASSPORT_STS;

    fn dummy_legacy_token() -> Token {
        Token::Legacy(LegacyToken {
            key_name: None,
            token: "dummy".to_string(),
            binary_secret: None,
            tpm_key: None,
            lifetime: soap::Timestamp {
                id: None,
                created: "2026-01-01T00:00:00Z".to_string(),
                expires: "2099-01-01T00:00:00Z".to_string(),
            },
        })
    }

    #[tokio::test]
    async fn get_license_gives_a_clean_error_when_not_logged_in() {
        let tokens = TokenManager::with_memory();
        // A device token is always present in real usage (ensure_device_credentials
        // runs at binary startup), but deliberately no user/user-token here -
        // this simulates a session that has never run `xodus-cli login`.
        tokens
            .save_device_token(PASSPORT_STS.to_string(), dummy_legacy_token())
            .unwrap();

        let client = reqwest::Client::new();
        let result = get_license(
            &client,
            &tokens,
            "unused-content-id".to_string(),
            "US".to_string(),
        )
        .await;

        let Err(err) = result else {
            panic!("expected a clean error, not a panic, when not logged in");
        };
        assert!(
            err.contains("run `xodus-cli login` first"),
            "unexpected error message: {err}"
        );
    }
}
