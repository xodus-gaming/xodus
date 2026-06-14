use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XSTSTokenRequest {
    pub url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XSTSTokenResponse {
    pub token: String,
    pub expiry: i64,
    pub relying_party: String,
    pub signature_policy: TitleSignaturePolicy,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TitleSignaturePolicy {
    pub algorithms: TitleSignatureAlgorithms,
    pub max_body_bytes: u64,
    pub signature_types: TitleSignatureTypes,
}

#[derive(Serialize)]
pub struct TitleSignatureAlgorithms {
    pub algorithm: Vec<String>,
}

#[derive(Serialize)]
pub struct TitleSignatureTypes {
    pub signature: Vec<String>,
}
