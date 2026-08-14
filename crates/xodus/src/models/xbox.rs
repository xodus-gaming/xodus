pub mod subscriptions;

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

/// Device and title tokens.
///
/// They come back in the same envelope as an XSTS token but with a different
/// claim shape -- a title token's `DisplayClaims.xti` is an object, not the
/// array `XstsResponse` expects -- and nothing here needs the claims anyway.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthTokenResponse {
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct XstsResponse {
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub token: String,
    display_claims: DisplayClaims,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DisplayClaims {
    #[serde(default)]
    xui: Vec<XuiClaim>,
    #[serde(default)]
    xti: Vec<XtiClaim>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct XuiClaim {
    uhs: String,
    gtg: Option<String>,
    xid: Option<String>,
    mgt: Option<String>,
    agg: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct XtiClaim {
    tid: Option<String>,
}

impl XstsResponse {
    pub fn user_hash(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .map(|claim| claim.uhs.as_str())
    }

    pub fn xuid(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .and_then(|claim| claim.xid.as_deref())
    }

    pub fn gamertag(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .and_then(|claim| claim.gtg.as_deref())
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

    /// Attaching these two is what puts the `xti` title claim on the result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_token: Option<String>,
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

#[derive(Debug, Deserialize, Clone)]
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
    pub signature_policy_index: Option<u8>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtSignaturePolicy {
    pub version: u16,
    pub supported_algorithms: Vec<String>,
    pub max_body_bytes: u64,
    pub supported_signature_types: Vec<String>,
}
