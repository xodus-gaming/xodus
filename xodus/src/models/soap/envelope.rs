use serde::{Deserialize, Serialize};

use super::base::{Fault, MustUnderstandValue, PP};
use super::crypto::{EncryptedData, EncryptedPP};
use super::security::{AuthInfo, Security};
use super::tokens::{
    RequestMultipleSecurityTokens, RequestSecurityToken, RequestSecurityTokenResponse,
    RequestSecurityTokenResponseCollection,
};

pub trait StringStorage<'t>: AsRef<str> + Clone + From<&'t str> {}

impl StringStorage<'_> for String {}
impl<'a> StringStorage<'a> for &'a str {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "s:Envelope")]
pub struct Envelope<'t, Str : StringStorage<'t>> {
    #[serde(rename = "@xmlns:s")]
    pub s: Option<Str>,
    #[serde(rename = "@xmlns:ps")]
    pub ps: Option<Str>,
    #[serde(rename = "@xmlns:wsse")]
    pub wsse: Option<Str>,
    #[serde(rename = "@xmlns:saml")]
    pub saml: Option<Str>,
    #[serde(rename = "@xmlns:wsp")]
    pub wsp: Option<Str>,
    #[serde(rename = "@xmlns:wsu")]
    pub wsu: Option<Str>,
    #[serde(rename = "@xmlns:wsa")]
    pub wsa: Option<Str>,
    #[serde(rename = "@xmlns:wssc")]
    pub wssc: Option<Str>,
    #[serde(rename = "@xmlns:wst")]
    pub wst: Option<Str>,

    #[serde(rename = "s:Header", alias = "Header")]
    pub header: Header<'t, Str>,
    #[serde(rename = "s:Body", alias = "Body")]
    pub body: Body,
}

impl<'t, Str : StringStorage<'t>> Envelope<'t, Str> {
    pub fn new(header: Header<'t>, body: Body) -> Self {
        Self {
            s: Some(Str::from("http://www.w3.org/2003/05/soap-envelope")),
            ps: Some("http://schemas.microsoft.com/Passport/SoapServices/PPCRL".to_owned()),
            wsse:
                Some("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                    .to_owned()),
            saml: Some("urn:oasis:names:tc:SAML:1.0:assertion".to_owned()),
            wsp: Some("http://schemas.xmlsoap.org/ws/2004/09/policy".to_owned()),
            wsu:
                Some("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
                    .to_owned()),
            wsa: Some("http://www.w3.org/2005/08/addressing".to_owned()),
            wssc: Some("http://schemas.xmlsoap.org/ws/2005/02/sc".to_owned()),
            wst: Some("http://schemas.xmlsoap.org/ws/2005/02/trust".to_owned()),
            header,
            body,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header<'t, Str : StringStorage<'t>> {
    #[serde(rename = "wsa:Action", alias = "Action")]
    pub action: MustUnderstandValue,
    #[serde(rename = "wsa:To", alias = "To")]
    pub to: MustUnderstandValue,
    #[serde(rename = "wsa:MessageID")]
    pub message_id: Option<String>,
    #[serde(rename = "ps:AuthInfo")]
    pub auth_info: Option<AuthInfo>,
    #[serde(rename = "wsse:Security", alias = "Security")]
    pub security: Security<Str>,
    #[serde(
        rename = "psf:EncryptedPP",
        alias = "EncryptedPP",
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_pp: Option<EncryptedPP>,
    #[serde(
        rename = "psf:pp",
        alias = "pp",
        skip_serializing_if = "Option::is_none"
    )]
    pub pp: Option<PP>,
}

impl<'t> Header<'t> {
    pub fn new() -> Self {
        let now = chrono::Utc::now();
        Self {
            action: MustUnderstandValue {
                must_understand: Some("1".to_owned()),
                value: "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue".to_owned(),
            },
            to: MustUnderstandValue {
                must_understand: Some("1".to_owned()),
                value: "https://login.live.com:443/RST2.srf".to_owned(),
            },
            message_id: Some(now.timestamp().to_string()),
            auth_info: Some(AuthInfo::default()),
            security: Security {
                username_token: None,
                encrypted_data: None,
                derived_key_tokens: vec![],
                binary_security_token: vec![],
                timestamp: super::base::Timestamp {
                    id: Some("Timestamp".to_owned()),
                    created: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    expires: (now + std::time::Duration::from_mins(5))
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                },
                signature: None,
            },
            encrypted_pp: None,
            pp: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    #[serde(rename = "$value")]
    pub body: BodyContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BodyContent {
    #[serde(rename = "wst:RequestSecurityToken")]
    RequestSecurityToken(RequestSecurityToken),
    #[serde(rename = "ps:RequestMultipleSecurityTokens")]
    RequestMultipleSecurityTokens(RequestMultipleSecurityTokens),

    RequestSecurityTokenResponseCollection(RequestSecurityTokenResponseCollection),
    RequestSecurityTokenResponse(RequestSecurityTokenResponse),
    EncryptedData(EncryptedData),
    Fault(Fault),
}
