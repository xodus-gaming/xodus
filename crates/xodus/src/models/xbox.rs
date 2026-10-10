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

/// Identity claims of one user in an XSTS token (`DisplayClaims.xui[n]`), as XSTS names them.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct XuiClaim {
    /// User hash: the `x=` part of the `XBL3.0` Authorization value.
    pub uhs: String,
    /// Classic gamertag.
    pub gtg: Option<String>,
    /// Xuid, decimal.
    pub xid: Option<String>,
    /// Modern gamertag.
    pub mgt: Option<String>,
    /// Age group: `Adult`, `Teen` or `Child`.
    pub agg: Option<String>,
    /// Modern gamertag suffix (empty when the modern gamertag is unique by itself).
    #[serde(default)]
    pub mgs: Option<String>,
    /// Unique modern gamertag (modern gamertag plus `#suffix`).
    #[serde(default)]
    pub umg: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct XtiClaim {
    tid: Option<String>,
}

impl XstsResponse {
    pub fn user_hash(&self) -> Option<&str> {
        self.xui().map(|claim| claim.uhs.as_str())
    }

    /// Claims of the user the token was issued for (`xui[0]`).
    pub fn xui(&self) -> Option<&XuiClaim> {
        self.display_claims.xui.first()
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

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtEndPoint {
    pub protocol: String,
    pub host: String,
    #[serde(default)]
    pub host_type: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub relying_party: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub signature_policy_index: Option<u8>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtSignaturePolicy {
    pub version: u16,
    pub supported_algorithms: Vec<String>,
    pub max_body_bytes: u64,
    pub supported_signature_types: Vec<String>,
}
