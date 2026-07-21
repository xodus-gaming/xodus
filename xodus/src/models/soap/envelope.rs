use serde::{Deserialize, Serialize};

use super::base::{Fault, MustUnderstandValue, PP};
use super::crypto::{EncryptedData, EncryptedPP};
use super::security::{AuthInfo, Security};
use super::tokens::{
    RequestMultipleSecurityTokens, RequestSecurityToken, RequestSecurityTokenResponse,
    RequestSecurityTokenResponseCollection,
};

pub trait StringStorage: AsRef<str> + Clone + Serialize {}

pub trait FromStrRef<'src>: StringStorage {
    fn st<'p: 'src>(s: &'p str) -> Self;
}

impl StringStorage for String {}
impl<'a> StringStorage for &'a str {}

impl<'a, 't: 'a> FromStrRef<'t> for &'a str {
    fn st<'p: 't>(s: &'p str) -> Self {
        s
    }
}

impl<'t> FromStrRef<'t> for String {
    fn st<'p: 't>(s: &'p str) -> Self {
        s.to_owned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "s:Envelope")]
pub struct Envelope<Str: StringStorage> {
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
    pub header: Header<Str>,
    #[serde(rename = "s:Body", alias = "Body")]
    pub body: Body<Str>,
}

impl<Str: StringStorage> Envelope<Str> {
    pub fn new(header: Header<Str>, body: Body<Str>) -> Self
    where
        Str: FromStrRef<'static>,
    {
        Self {
            s: Some(Str::st("http://www.w3.org/2003/05/soap-envelope")),
            ps: Some(Str::st(
                "http://schemas.microsoft.com/Passport/SoapServices/PPCRL",
            )),
            wsse: Some(Str::st(
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            )),
            saml: Some(Str::st("urn:oasis:names:tc:SAML:1.0:assertion")),
            wsp: Some(Str::st("http://schemas.xmlsoap.org/ws/2004/09/policy")),
            wsu: Some(Str::st(
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            )),
            wsa: Some(Str::st("http://www.w3.org/2005/08/addressing")),
            wssc: Some(Str::st("http://schemas.xmlsoap.org/ws/2005/02/sc")),
            wst: Some(Str::st("http://schemas.xmlsoap.org/ws/2005/02/trust")),
            header,
            body,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header<Str: StringStorage> {
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
    pub encrypted_pp: Option<EncryptedPP<Str>>,
    #[serde(
        rename = "psf:pp",
        alias = "pp",
        skip_serializing_if = "Option::is_none"
    )]
    pub pp: Option<PP>,
}

impl<Str: StringStorage> Header<Str> {
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
pub struct Body<Str: StringStorage> {
    #[serde(rename = "$value")]
    pub body: BodyContent<Str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BodyContent<Str: StringStorage> {
    #[serde(rename = "wst:RequestSecurityToken", alias = "RequestSecurityToken")]
    RequestSecurityToken(RequestSecurityToken),
    #[serde(
        rename = "ps:RequestMultipleSecurityTokens",
        alias = "RequestMultipleSecurityTokens"
    )]
    RequestMultipleSecurityTokens(RequestMultipleSecurityTokens),

    RequestSecurityTokenResponseCollection(RequestSecurityTokenResponseCollection<Str>),
    RequestSecurityTokenResponse(RequestSecurityTokenResponse<Str>),
    EncryptedData(EncryptedData<Str>),
    Fault(Fault),
}
