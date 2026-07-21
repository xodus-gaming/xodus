use serde::{Deserialize, Serialize};

use crate::models::soap::StringStorage;

use super::base::{RequestedTokenReference, Timestamp};
use super::crypto::{EncryptedData, SecurityTokenReference, Signature};
use super::tokens::BinarySecurityTokenReq;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthInfo {
    #[serde(rename = "@xmlns:ps")]
    pub ps: String,
    #[serde(rename = "@Id")]
    pub id: String,

    #[serde(rename = "ps:SSOFlags")]
    pub sso_flags: String,
    #[serde(rename = "ps:HostingApp")]
    pub hosting_app: String,
    #[serde(rename = "ps:BinaryVersion")]
    pub binary_version: String,
    #[serde(rename = "ps:UIVersion")]
    pub ui_version: String,
    #[serde(rename = "ps:InlineUX")]
    pub inline_ux: String,
    #[serde(rename = "ps:IsAdmin")]
    pub is_admin: String,
    #[serde(rename = "ps:Cookies")]
    pub cookies: Option<String>,
    #[serde(rename = "ps:RequestParams")]
    pub request_params: String,
    #[serde(rename = "ps:WindowsClientString")]
    pub windows_client_string: String,
    #[serde(
        rename = "ps:LicenseSignatureKeyVersion",
        skip_serializing_if = "Option::is_none"
    )]
    pub license_signature_key_version: Option<String>,
    #[serde(rename = "ps:ClientCapabilities")]
    pub client_capabilities: String,
    #[serde(rename = "ps:IsConnected", skip_serializing_if = "Option::is_none")]
    pub is_connected: Option<String>,
    #[serde(rename = "ps:InlineFT", skip_serializing_if = "Option::is_none")]
    pub inline_ft: Option<String>,
}

impl Default for AuthInfo {
    fn default() -> Self {
        Self {
            sso_flags: "".to_string(),
            ps: "http://schemas.microsoft.com/Passport/SoapServices/PPCRL".to_owned(),
            id: "PPAuthInfo".to_owned(),
            hosting_app: "{DF60E2DF-88AD-4526-AE21-83D130EF0F68}".to_owned(),
            binary_version: "55".to_owned(),
            ui_version: "1".to_owned(),
            is_connected: None,
            inline_ux: "TokenBroker".to_owned(),
            is_admin: "1".to_owned(),
            cookies: None,
            request_params: "AQAAAAIAAABsYwQAAAAxMDMz".to_owned(),
            windows_client_string: "b4d/QB7Zy5pjUAY9ByQ1echTyTITx6ZCErOEztuIVtw=".to_owned(),
            license_signature_key_version: Some("2".to_owned()),
            client_capabilities: "1".to_owned(),
            inline_ft: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security<Str: StringStorage> {
    #[serde(
        rename = "wsse:UsernameToken",
        alias = "UsernameToken",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub username_token: Option<UsernameToken>,
    #[serde(
        rename = "EncryptedData",
        alias = "EncryptedData",
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_data: Option<EncryptedData<Str>>,
    #[serde(
        rename = "wsse:BinarySecurityToken",
        alias = "BinarySecurityToken",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub binary_security_token: Vec<BinarySecurityTokenReq>,
    #[serde(
        rename = "wssc:DerivedKeyToken",
        alias = "DerivedKeyToken",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub derived_key_tokens: Vec<DerivedKeyToken>,
    #[serde(rename = "wsu:Timestamp", alias = "Timestamp")]
    pub timestamp: Timestamp,
    #[serde(rename = "Signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature<Str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameToken {
    #[serde(rename = "@wsu:Id", alias = "@Id")]
    pub id: String,
    #[serde(
        rename = "wsse:Username",
        alias = "Username",
        skip_serializing_if = "Option::is_none"
    )]
    pub username: Option<String>,
    #[serde(
        rename = "wsse:Password",
        alias = "Password",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<String>,
    #[serde(
        rename = "wsse:UsernameHint",
        alias = "UsernameHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub username_hint: Option<String>,
    #[serde(
        rename = "wsse:LoginOption",
        alias = "LoginOption",
        skip_serializing_if = "Option::is_none"
    )]
    pub login_option: Option<String>,
}

impl UsernameToken {
    pub fn devicetoken(username: String) -> Self {
        Self {
            id: "devicesoftware".to_string(),
            username: Some(username),
            password: None,
            username_hint: None,
            login_option: None,
        }
    }

    pub fn user_hint(username: String) -> Self {
        Self {
            id: "user".to_string(),
            username_hint: Some(username),
            login_option: Some("1".to_string()),
            username: None,
            password: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedKeyToken {
    #[serde(rename = "@wsu:Id", alias = "@Id")]
    pub id: String,
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
    #[serde(
        rename = "wsse:RequestedTokenReference",
        alias = "RequestedTokenReference"
    )]
    pub requested_token_reference: Option<RequestedTokenReference>,
    #[serde(
        rename = "wsse:SecurityTokenReference",
        alias = "SecurityTokenReference",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_reference: Option<SecurityTokenReference>,
    #[serde(rename = "wssc:Nonce", alias = "Nonce")]
    pub nonce: String,
}

impl DerivedKeyToken {
    pub fn sign_key(nonce: String) -> Self {
        Self {
            id: "SignKey".to_string(),
            algorithm: "urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED".to_string(),
            requested_token_reference: Some(RequestedTokenReference::default()),
            token_reference: None,
            nonce,
        }
    }
}
