use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenRequest {
    pub client_id: String,
    #[serde(default)]
    pub allow_ui: bool,
    #[serde(default, alias = "MSAFullTrust")]
    pub msa_full_trust: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenResponse {
    pub token: String,
    pub expiry: i64,
    pub device_rps: String,
    pub device_expiry: i64,
}

/// Failure reply: same root element as `MSATokenResponse`, carrying only an `Error` HRESULT.
#[derive(Serialize)]
#[serde(rename = "MSATokenResponse", rename_all = "PascalCase")]
pub struct MSATokenErrorResponse {
    pub error: String,
}
