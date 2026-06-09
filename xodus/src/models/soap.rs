use std::vec;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "s:Envelope")]
pub struct Envelope {
    #[serde(rename = "@xmlns:s")]
    pub s: Option<String>,
    #[serde(rename = "@xmlns:ps")]
    pub ps: Option<String>,
    #[serde(rename = "@xmlns:wsse")]
    pub wsse: Option<String>,
    #[serde(rename = "@xmlns:saml")]
    pub saml: Option<String>,
    #[serde(rename = "@xmlns:wsp")]
    pub wsp: Option<String>,
    #[serde(rename = "@xmlns:wsu")]
    pub wsu: Option<String>,
    #[serde(rename = "@xmlns:wsa")]
    pub wsa: Option<String>,
    #[serde(rename = "@xmlns:wssc")]
    pub wssc: Option<String>,
    #[serde(rename = "@xmlns:wst")]
    pub wst: Option<String>,

    #[serde(rename = "s:Header", alias = "Header")]
    pub header: Header,
    #[serde(rename = "s:Body", alias = "Body")]
    pub body: Body,
}

impl Envelope {
    pub fn new(header: Header, body: Body) -> Self {
        Self {
            s: Some("http://www.w3.org/2003/05/soap-envelope".to_owned()),
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
            header: header,
            body: body,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    #[serde(rename = "wsa:Action", alias = "Action")]
    pub action: MustUnderstandValue,
    #[serde(rename = "wsa:To", alias = "To")]
    pub to: MustUnderstandValue,
    #[serde(rename = "wsa:MessageID")]
    pub message_id: Option<String>,
    #[serde(rename = "ps:AuthInfo")]
    pub auth_info: Option<AuthInfo>,
    #[serde(rename = "wsse:Security", alias = "Security")]
    pub security: Security,
    #[serde(
        rename = "psf:EncryptedPP",
        alias = "EncryptedPP",
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_pp: Option<EncryptedPP>,
}

impl Header {
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
                derived_key_token: vec![],
                binary_security_token: vec![],
                timestamp: Timestamp {
                    id: Some("Timestamp".to_owned()),
                    created: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    expires: (now + std::time::Duration::from_mins(5))
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                },
                signature: None,
            },
            encrypted_pp: None,
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

    #[serde(
        rename = "wst:RequestSecurityTokenResponse",
        alias = "RequestSecurityTokenResponse"
    )]
    RequestSecurityTokenResponse(RequestSecurityTokenResponse),
    EncryptedData(EncryptedData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MustUnderstandValue {
    #[serde(rename = "@s:mustUnderstand")]
    pub must_understand: Option<String>,
    #[serde(rename = "$value")]
    pub value: String,
}

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
    #[serde(rename = "ps:LicenseSignatureKeyVersion", skip_serializing_if = "String::is_empty")]
    pub license_signature_key_version: String,
    #[serde(rename = "ps:ClientCapabilities")]
    pub client_capabilities: String,
    #[serde(rename = "ps:IsConnected", skip_serializing_if = "String::is_empty")]
    pub is_connected: String,
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
            inline_ux: "TokenBroker".to_owned(),
            is_admin: "1".to_owned(),
            cookies: None,
            request_params: "AQAAAAIAAABsYwQAAAAxMDMz".to_owned(),
            windows_client_string: "b4d/QB7Zy5pjUAY9ByQ1echTyTITx6ZCErOEztuIVtw=".to_owned(),
            license_signature_key_version: "2".to_owned(),
            client_capabilities: "1".to_owned(),
            is_connected: "".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    #[serde(rename = "wsse:UsernameToken", skip_serializing_if = "Option::is_none")]
    pub username_token: Option<UsernameToken>,
    #[serde(
        rename = "EncryptedData",
        alias = "EncryptedData",
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_data: Option<EncryptedData>,
    #[serde(
        rename = "wsse:BinarySecurityToken",
        alias = "BinarySecurityToken",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub binary_security_token: Vec<BinarySecurityToken>,
    #[serde(
        rename = "wssc:DerivedKeyToken",
        alias = "DerivedKeyToken",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub derived_key_token: Vec<DerivedKeyToken>,
    #[serde(rename = "wsu:Timestamp", alias = "Timestamp")]
    pub timestamp: Timestamp,
    #[serde(rename = "Signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameToken {
    #[serde(rename = "@wsu:Id", alias = "@Id")]
    pub id: String,
    #[serde(rename = "wsse:Username", skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(rename = "wsse:Password", skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(rename = "wsse:UsernameHint", skip_serializing_if = "String::is_empty")]
    pub username_hint: String,
    #[serde(rename = "wsse:LoginOption", skip_serializing_if = "String::is_empty")]
    pub login_option: String,
}

impl UsernameToken {
    pub fn new(username: String, password: String) -> Self {
        Self {
            id: "devicesoftware".to_string(),
            username,
            password,
            login_option: "".to_string(),
            username_hint: "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptedData {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "@Type")]
    pub el_type: String,

    pub encryption_method: EncryptionMethod,
    #[serde(rename = "ds:KeyInfo", alias = "KeyInfo")]
    pub key_info: KeyInfoWrap,
    pub cipher_data: CipherData,
}

impl EncryptedData {
    pub fn devicesoftware(key: String) -> Self {
        Self {
            id: "devicesoftware".to_string(),
            xmlns: "http://www.w3.org/2001/04/xmlenc#".to_string(),
            el_type: "http://www.w3.org/2001/04/xmlenc#Element".to_string(),

            encryption_method: EncryptionMethod::default(),
            key_info: KeyInfoWrap::sts(),
            cipher_data: CipherData::new(key),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptedPP {
    pub encrypted_data: EncryptedData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfoWrap {
    #[serde(
        rename = "@xmlns:ds",
        alias = "@xmlns",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds: Option<String>,
    #[serde(
        rename = "ds:KeyName",
        alias = "KeyName",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_name: Option<String>,
    #[serde(
        rename = "wsse:SecurityTokenReference",
        alias = "SecurityTokenReference",
        skip_serializing_if = "Option::is_none"
    )]
    pub security_token_reference: Option<SecurityTokenReference>,
}

impl KeyInfoWrap {
    pub fn sts() -> Self {
        Self {
            ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
            key_name: Some("http://Passport.NET/STS".to_string()),
            security_token_reference: None,
        }
    }

    pub fn as_signature(self) -> SignatureKeyInfo {
        let Self {
            security_token_reference: Some(reference),
            ..
        } = self
        else {
            panic!("Key is not named");
        };

        SignatureKeyInfo {
            security_token_reference: reference,
        }
    }

    pub fn as_named(self) -> NamedKeyInfo {
        let Self {
            ds,
            key_name,
            security_token_reference: _,
        } = self;

        NamedKeyInfo {
            ds: ds.unwrap_or_else(|| "http://www.w3.org/2000/09/xmldsig#".to_string()),
            key_name: key_name.expect("Key is not named"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    #[serde(rename = "@wsu:Id", alias = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "wsu:Created", alias = "Created")]
    pub created: String,
    #[serde(rename = "wsu:Expires", alias = "Expires")]
    pub expires: String,
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
        alias = "SecurityTokenReference"
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedTokenReference {
    #[serde(rename = "wsse:KeyIdentifier")]
    pub key_identifier: KeyIdentifier,
    #[serde(rename = "wsse:Reference")]
    pub reference: ReferenceUri,
}

impl Default for RequestedTokenReference {
    fn default() -> Self {
        Self {
            key_identifier: KeyIdentifier {
                value_type: "http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".to_string(),
                value: None,
            },
            reference: ReferenceUri {
                uri: String::new(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyIdentifier {
    #[serde(rename = "@ValueType")]
    pub value_type: String,
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceUri {
    #[serde(rename = "@URI")]
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "SignatureValue")]
    pub signature_value: String,
    #[serde(rename = "KeyInfo", skip_serializing_if = "Option::is_none")]
    pub key_info: Option<SignatureKeyInfo>,
}

impl Signature {
    pub fn empty_hmac() -> Self {
        Self {
            xmlns: "http://www.w3.org/2000/09/xmldsig#".to_string(),
            signed_info: SignedInfo::default(),
            signature_value: String::new(),
            key_info: Some(SignatureKeyInfo::sign_key()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInfo {
    #[serde(rename = "CanonicalizationMethod")]
    pub canonicalization_method: AlgorithmNode,
    #[serde(rename = "SignatureMethod")]
    pub signature_method: AlgorithmNode,
    #[serde(rename = "Reference")]
    pub reference: Vec<SignatureReference>,
}

impl Default for SignedInfo {
    fn default() -> Self {
        Self {
            canonicalization_method: AlgorithmNode {
                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
            },
            signature_method: AlgorithmNode {
                algorithm: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256".to_string(),
            },
            reference: vec![
                SignatureReference::exclusive("#RST0"),
                SignatureReference::exclusive("#Timestamp"),
                SignatureReference::exclusive("#PPAuthInfo"),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmNode {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureReference {
    #[serde(rename = "@URI")]
    pub uri: String,
    #[serde(rename = "Transforms")]
    pub transforms: SignatureTransforms,
    #[serde(rename = "DigestMethod")]
    pub digest_method: AlgorithmNode,
    #[serde(rename = "DigestValue")]
    pub digest_value: String,
}

impl SignatureReference {
    pub fn exclusive(uri: &str) -> Self {
        Self {
            uri: uri.to_string(),
            transforms: SignatureTransforms {
                transform: vec![AlgorithmNode {
                    algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                }],
            },
            digest_method: AlgorithmNode {
                algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            },
            digest_value: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureTransforms {
    #[serde(rename = "Transform")]
    pub transform: Vec<AlgorithmNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureKeyInfo {
    #[serde(
        rename = "wsse:SecurityTokenReference",
        alias = "SecurityTokenReference"
    )]
    pub security_token_reference: SecurityTokenReference,
}

impl SignatureKeyInfo {
    pub fn sign_key() -> Self {
        Self {
            security_token_reference: SecurityTokenReference {
                reference: ReferenceUri {
                    uri: "#SignKey".to_string(),
                },
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTokenReference {
    #[serde(rename = "wsse:Reference", alias = "Reference")]
    pub reference: ReferenceUri,
}

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
pub struct RequestSecurityTokenResponse {
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
    pub requested_security_token: RequestedSecurityToken,
    #[serde(rename = "wst:RequestedProofToken", alias = "RequestedProofToken")]
    pub requested_proof_token: Option<RequestedProofToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestedSecurityToken {
    #[serde(rename = "EncryptedData")]
    pub encrypted_data: Option<EncryptedData>,
    #[serde(rename = "wsse:BinarySecurityToken", alias = "BinarySecurityToken")]
    pub binary_security_token: Option<BinarySecurityToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BinarySecurityToken {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "$value")]
    pub value: String,
    #[serde(rename = "@ValueType", skip_serializing_if = "String::is_empty")]
    pub value_type: String,
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

    #[serde(rename = "wst:RequestSecurityToken")]
    pub security_tokens: Vec<RequestSecurityToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliesTo {
    #[serde(rename = "wsa:EndpointReference", alias = "EndpointReference")]
    pub endpoint_reference: EndpointReference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReference {
    #[serde(rename = "wsa:Address", alias = "Address")]
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReference {
    #[serde(rename = "@URI")]
    pub uri: String,
    #[serde(rename = "$value")]
    pub val: String,
}

impl PolicyReference {
    pub fn token_broker() -> Self {
        Self {
            uri: "TOKEN_BROKER".to_string(),
            val: String::default(),
        }
    }

    pub fn mbi_ssl() -> Self {
        Self {
            uri: "mbi_ssl".to_string(),
            val: String::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
    #[serde(rename = "$value")]
    pub val: Option<String>,
}

impl Default for EncryptionMethod {
    fn default() -> Self {
        Self {
            algorithm: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc".to_string(),
            val: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedKeyInfo {
    #[serde(rename = "@xmlns:ds")]
    pub ds: String,
    #[serde(rename = "ds:KeyName", alias = "KeyName")]
    pub key_name: String,
}

impl NamedKeyInfo {
    pub fn sts() -> Self {
        Self {
            ds: "http://www.w3.org/2000/09/xmldsig#".to_string(),
            key_name: "http://Passport.NET/STS".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CipherData {
    pub cipher_value: String,
}

impl CipherData {
    pub fn new(key: String) -> Self {
        Self { cipher_value: key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_info_wrap_deserializes_ds_key_info_key_name() {
        let xml = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:KeyName>http://Passport.NET/STS</ds:KeyName>
                    </ds:KeyInfo>"#;

        let key_info: KeyInfoWrap =
            quick_xml::de::from_str(xml).expect("failed to deserialize key info");

        let named = key_info.as_named();
        assert_eq!(named.ds, "http://www.w3.org/2000/09/xmldsig#");
        assert_eq!(named.key_name, "http://Passport.NET/STS");
    }

    #[test]
    fn key_info_wrap_deserializes_wsse_security_token_reference() {
        let xml = r##"<KeyInfo xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                        <wsse:SecurityTokenReference>
                            <wsse:Reference URI="#SignKey"></wsse:Reference>
                        </wsse:SecurityTokenReference>
                    </KeyInfo>"##;

        let key_info: KeyInfoWrap =
            quick_xml::de::from_str(xml).expect("failed to deserialize key info");

        let signature = key_info.as_signature();
        assert_eq!(signature.security_token_reference.reference.uri, "#SignKey");
    }
}
