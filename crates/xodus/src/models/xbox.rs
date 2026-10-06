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

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PagingInfo {
    pub continuation_token: Option<String>,
    pub total_items: i64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContainerBlob {
    #[serde(default)]
    pub client_file_time: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    pub etag: String,
    pub file_name: String,
    pub size: i64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContainerResponse {
    pub blobs: Vec<ContainerBlob>,
    pub paging_info: PagingInfo,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Atom {
    pub atom: String,
    pub name: String,
    pub size: i64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Atoms {
    pub atoms: Vec<Atom>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    #[serde(rename = "@msa")]
    pub msa: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Title {
    #[serde(rename = "@scid")]
    pub scid: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ContextDescription {
    pub account: Account,
    pub title: Title,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Blob {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "$text")]
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Blobs {
    #[serde(default)]
    pub blob: Vec<Blob>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Container {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(default, rename = "@clientFileTime")]
    pub client_file_time: Option<String>,
    #[serde(default, rename = "@displayName")]
    pub display_name: Option<String>,
    #[serde(default, rename = "@etag")]
    pub etag: Option<String>,
    pub blobs: Blobs,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Containers {
    #[serde(default)]
    pub container: Vec<Container>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Data {
    pub containers: Containers,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct XbConnectedStorageSpace {
    pub context_description: ContextDescription,
    pub data: Data,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobCreationRequest {
    pub size: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobCreationResponse {
    pub blob_uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobSubmitRequest {
    pub block_ids: Vec<String>,
    pub size: i64,
}
