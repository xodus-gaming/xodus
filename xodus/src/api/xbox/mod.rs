use crate::models::{
    live::ExchangeUserTokenOutcome,
    secrets::{LegacyToken, Token},
    soap,
};
use base64::Engine;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::rand_core::OsRng,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsResponse {
    issue_instant: String,
    not_after: String,
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

    #[serde(skip_serializing_if = "Option::is_none")]
    proof_key: Option<Vec<u8>>,
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
            rps_ticket: format!("{rps_ticket}"),
        },
    };

    let resp = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .header("User-Agent", "xal-go/0.0.0")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(&body)
        .send()
        .await?;

    let code = resp.status();
    println!("code {code}");
    // resp.text().await
    resp.json().await
}

fn to_windows_file_time(now: SystemTime) -> u64 {
    const WINDOWS_TICK: u64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH_FROM_WINDOWS: u64 = 11_644_473_600;

    let duration = now.duration_since(UNIX_EPOCH).unwrap();
    (duration.as_secs() + SEC_TO_UNIX_EPOCH_FROM_WINDOWS) * WINDOWS_TICK
        + (duration.subsec_nanos() as u64 / 100)
}

fn ecdsa_public_key_to_jwk(key: &SigningKey) -> Vec<u8> {
    let verifying = key.verifying_key();
    let point = verifying.to_encoded_point(false);
    let x = point.x().unwrap();
    let y = point.y().unwrap();

    serde_json::to_vec(&serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
        "alg": "ES256",
        "use": "sig",
    }))
    .unwrap()
}

pub async fn request_xsts_token(
    client: &reqwest::Client,
    key: &SigningKey,
    token: String,
    relying_party: &str,
) -> reqwest::Result<XstsResponse> {
    let file_time = to_windows_file_time(SystemTime::now());

    let body = XstsRequest {
        relying_party: Some(relying_party.to_string()),
        token_type: Some("JWT".to_string()),
        properties: XstsPropertyBag {
            user_tokens: Some(vec![token]),
            sandbox_id: Some("RETAIL".to_string()),
            delegation_token: None,
            service_token: None,
        },
        proof_key: Some(ecdsa_public_key_to_jwk(key)),
    };

    let rbody = serde_json::to_vec(&body).unwrap();

    let mut rsig = Vec::new();
    rsig.extend_from_slice(&1u32.to_be_bytes());
    rsig.push(0);
    rsig.extend_from_slice(&file_time.to_be_bytes());
    rsig.push(0);
    rsig.extend_from_slice(b"GET");
    rsig.push(0);
    rsig.extend_from_slice(b"/xsts/authorize");
    rsig.push(0);
    rsig.extend_from_slice(&rbody);
    rsig.push(0);

    let digest = Sha256::digest(&rsig);
    let signature: Signature = key.sign(&digest);

    let mut bsig = Vec::new();
    bsig.extend_from_slice(&1u32.to_be_bytes());
    bsig.extend_from_slice(&file_time.to_be_bytes());
    bsig.extend_from_slice(&signature.to_bytes());

    let sig = base64::engine::general_purpose::STANDARD.encode(bsig);

    let resp = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .header("User-Agent", "xal-go/0.0.0")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .header("Signature", sig)
        .body(rbody)
        .send()
        .await?;

    let text = resp.text().await?;
    println!("{text}");

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
        "minecraft".to_string(),
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
            // Refresh token
            let token2: Token = collection.security_tokens.remove(0).into();
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
    let signing_key = SigningKey::random(&mut OsRng);

    let resp = request_xsts_token(client, &signing_key, resp.token, relying_party)
        .await
        .expect("Failed to authenticate Xbox user");
    resp
}
