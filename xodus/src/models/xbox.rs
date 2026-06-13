use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserAuthRequest {
    pub relying_party: String,
    pub token_type: String,
    pub properties: UserAuthProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserAuthProperties {
    pub auth_method: String,
    pub site_name: String,
    pub rps_ticket: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsResponse {
    pub token: String,
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

impl XstsResponse {
    pub fn user_hash(&self) -> Option<&str> {
        self.display_claims.xui.first().map(|claim| claim.uhs.as_str())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsPropertyBag {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_tokens: Option<Vec<String>>,

    #[serde(rename = "SandboxId", skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relying_party: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    pub properties: XstsPropertyBag,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtResponse {
    pub end_points: Vec<TitleMgtEndPoint>,
    pub signature_policies: Vec<TitleMgtSignaturePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtEndPoint {
    pub protocol: String,
    pub host: String,
    #[serde(default)]
    pub host_type: Option<String>,
    #[serde(default)]
    pub relying_party: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub signature_policy_index: Option<u8>
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtSignaturePolicy {
    pub version: u16,
    pub supported_algorithms: Vec<String>,
    pub max_body_bytes: u64,
    pub supported_signature_types: Vec<String>
}