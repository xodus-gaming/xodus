//! Xbox device authentication.
//!
//! Not to be confused with `tokens::device`, which provisions an *MSA* device
//! credential against login.live.com. This is the Xbox Live side: a token that
//! says "this device holds the private half of that ProofKey", and it is the
//! prerequisite for asking sisu or title.auth for a title token.

use serde::Serialize;

use crate::api::xbox::signature::{ProofKey, ProofKeyJwk};
use crate::models::xbox::AuthTokenResponse;

const DEVICE_AUTH_URL: &str = "https://device.auth.xboxlive.com/device/authenticate";

/// Device authentication with an MSA device RPS ticket.
///
/// The ProofOfPossession form below proves only that the caller holds a key it
/// generated itself, which title.auth will not accept as a title-capable device
/// (403). This form additionally presents the device's own MSA credential --
/// the one `tokens::device` provisions against login.live.com -- so the
/// resulting device token stands for a registered device.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DeviceRpsProperties {
    auth_method: String,
    site_name: String,
    rps_ticket: String,
    id: String,
    device_type: String,
    version: String,
    proof_key: ProofKeyJwk,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DeviceRpsRequest {
    relying_party: String,
    token_type: String,
    properties: DeviceRpsProperties,
}

pub async fn authenticate_device_rps(
    client: &reqwest::Client,
    proof_key: &ProofKey,
    device_id: &str,
    device_type: &str,
    device_rps: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let body = DeviceRpsRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: DeviceRpsProperties {
            auth_method: "RPS".to_string(),
            site_name: "user.auth.xboxlive.com".to_string(),
            rps_ticket: device_rps.to_string(),
            id: format!("{{{device_id}}}"),
            device_type: device_type.to_string(),
            version: "10.0.22631".to_string(),
            proof_key: proof_key.jwk(),
        },
    };

    let body = serde_json::to_vec(&body)?;
    let signature = proof_key.sign_request("POST", "/device/authenticate", "", &body);

    let resp = client
        .post(DEVICE_AUTH_URL)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .header("Signature", signature)
        .body(body)
        .send()
        .await?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(crate::api::xbox::signature::describe_failure(
            "device RPS authentication",
            status,
            &headers,
            &text,
        )
        .into());
    }

    Ok(serde_json::from_str::<AuthTokenResponse>(&text)?.token)
}
