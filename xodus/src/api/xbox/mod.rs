use crate::models::{
    live::ExchangeUserTokenOutcome,
    secrets::{LegacyToken, Token},
    soap,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct UserAuthRequest {
    relying_party: String,
    token_type: String,
    properties: UserAuthProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct UserAuthProperties {
    auth_method: String,
    site_name: String,
    rps_ticket: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsResponse {
    token: String,
    display_claims: DisplayClaims,
}

#[derive(Debug, Deserialize)]
struct DisplayClaims {
    xui: Vec<XuiClaim>,
}

#[derive(Debug, Deserialize)]
struct XuiClaim {
    uhs: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct XstsPropertyBag {
    #[serde(skip_serializing_if = "Option::is_none")]
    service_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    user_tokens: Option<Vec<String>>,

    #[serde(rename = "SandboxId", skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    delegation_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct XstsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    relying_party: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,

    properties: XstsPropertyBag,
}

pub async fn authenticate_xbox_user(
    client: &reqwest::Client,
    rps_ticket: String,
) -> reqwest::Result<XstsResponse> {
    let body = UserAuthRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: UserAuthProperties {
            auth_method: "RPS".to_string(),
            site_name: "user.auth.xboxlive.com".to_string(),
            rps_ticket,
        },
    };

    let resp = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .header("User-Agent", "xal-go/0.0.0")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    resp.json().await
}

pub async fn request_xsts_token(
    client: &reqwest::Client,
    token: String,
    relying_party: &str,
) -> reqwest::Result<XstsResponse> {
    let body = XstsRequest {
        relying_party: Some(relying_party.to_string()),
        token_type: Some("JWT".to_string()),
        properties: XstsPropertyBag {
            user_tokens: Some(vec![token]),
            sandbox_id: Some("RETAIL".to_string()),
            delegation_token: None,
            service_token: None,
        },
    };

    let rbody = serde_json::to_vec(&body).unwrap();

    let resp = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .header("User-Agent", "xal-go/0.0.0")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .body(rbody)
        .send()
        .await?
        .error_for_status()?;

    let text = resp.text().await?;

    let parsed = serde_json::from_str::<XstsResponse>(&text).unwrap();
    Ok(parsed)
}

pub fn get_xsts_auth_header(xsts: XstsResponse) -> String {
    let uhs = xsts
        .display_claims
        .xui
        .first()
        .map(|claim| claim.uhs.as_str())
        .expect("XSTS response missing xui claim");
    format!("XBL3.0 x={uhs};{}", xsts.token)
}

pub async fn run(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
) -> XstsResponse {
    let secret = dev_token.binary_secret.unwrap();

    let user_token = crate::api::live::exchange_user_token(
        client,
        legacy.token,
        "USERNAME".to_string(),
        dev_token.token,
        secret,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "user.auth.xboxlive.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            eprintln!("Failed to get exchange MS token");
            panic!("TODO");
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => token.into(),
        _ => unreachable!("Only responses are handled"),
    };
    let Token::Compact(user_token) = user_token else {
        eprintln!("Unsupported token");
        panic!("TODO");
    };
    let resp = authenticate_xbox_user(client, user_token)
        .await
        .expect("Failed to authenticate Xbox user");

    let resp = request_xsts_token(client, resp.token, relying_party)
        .await
        .expect("Failed to authenticate Xbox user");
    resp
}
