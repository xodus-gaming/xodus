use serde::{Deserialize, Serialize};

use crate::models::soap::StringStorage;

use super::base::{AppliesTo, PolicyReference, Timestamp};
use super::crypto::EncryptedData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityToken {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "wst:RequestType", alias = "RequestType")]
    pub request_type: String,
    #[serde(rename = "wsp:AppliesTo", alias = "AppliesTo")]
    pub applies_to: AppliesTo,
    #[serde(
        rename = "wsp:PolicyReference",
        alias = "PolicyReference",
        skip_serializing_if = "Option::is_none"
    )]
    pub policy_reference: Option<PolicyReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityTokenResponse<Str: StringStorage> {
    #[serde(rename = "wst:TokenType", alias = "TokenType")]
    pub token_type: String,
    #[serde(rename = "wsp:AppliesTo", alias = "AppliesTo")]
    pub applies_to: AppliesTo,
    #[serde(rename = "wst:Lifetime", alias = "Lifetime")]
    pub lifetime: Timestamp,
    #[serde(
        rename = "wst:RequestedSecurityToken",
        alias = "RequestedSecurityToken"
    )]
    pub requested_security_token: RequestedSecurityToken<Str>,
    #[serde(rename = "wst:RequestedProofToken", alias = "RequestedProofToken")]
    pub requested_proof_token: Option<RequestedProofToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestedSecurityToken<Str: StringStorage> {
    #[serde(rename = "EncryptedData")]
    pub encrypted_data: Option<EncryptedData<Str>>,
    #[serde(rename = "wsse:BinarySecurityToken", alias = "BinarySecurityToken")]
    pub binary_security_token: Option<BinarySecurityTokenRes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BinarySecurityTokenRes {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "$value")]
    pub value: String,
    #[serde(rename = "@ValueType", skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BinarySecurityTokenReq {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@ValueType")]
    pub value_type: String,
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedProofToken {
    #[serde(rename = "wst:BinarySecret", alias = "BinarySecret")]
    pub binary_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMultipleSecurityTokens {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@xmlns:ps")]
    pub ps: String,
    #[serde(rename = "wst:RequestSecurityToken")]
    pub security_tokens: Vec<RequestSecurityToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityTokenResponseCollection<Str: StringStorage> {
    #[serde(
        rename = "wst:RequestSecurityTokenResponse",
        alias = "RequestSecurityTokenResponse"
    )]
    pub security_tokens: Vec<RequestSecurityTokenResponse<Str>>,
}
