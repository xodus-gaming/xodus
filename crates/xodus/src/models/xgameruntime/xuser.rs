use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenRequest {
    pub client_id: String,
    #[serde(default)]
    pub allow_ui: bool,
    #[serde(default, alias = "MSAFullTrust")]
    pub msa_full_trust: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenResponse {
    pub token: String,
    pub expiry: i64,
    pub device_rps: String,
    pub device_expiry: i64,
}

/// `XUserGetTokenAndSignatureAsync` forwarded by the runtime: get an XSTS token (and the
/// Xbox Live request signature) for one HTTP request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenAndSignatureRequest {
    /// MSA app id of the title (`MSAAppId` in MicrosoftGame.config). Optional: without it
    /// and `TitleId` the service falls back to an unsigned, user-only XSTS token.
    #[serde(default, alias = "clientId")]
    pub client_id: Option<String>,
    /// Numeric title id (`TitleId` in MicrosoftGame.config, decimal here).
    #[serde(default)]
    pub title_id: Option<u32>,
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: Option<TokenRequestHeaders>,
    /// Request body, base64 encoded.
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub force_refresh: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenRequestHeaders {
    #[serde(default)]
    pub header: Vec<TokenRequestHeader>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenRequestHeader {
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// Response to [`TokenAndSignatureRequest`]. Either `Token` (+ `Signature`, `Expiry`) or
/// `Error` (HRESULT as `0x........`) + `Message` is present.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenAndSignatureResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Base64 `Signature` header value; empty when the endpoint has no signature policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Unix timestamp (seconds) after which the token must not be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl TokenAndSignatureResponse {
    pub fn error(hresult: u32, message: impl Into<String>) -> Self {
        Self {
            error: Some(format!("0x{hresult:08X}")),
            message: Some(message.into()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// The request as WineGDK's libxml builder formats it (indented, with text nodes).
    #[test]
    fn token_and_signature_request_xml() {
        let xml = r#"<?xml version="1.0"?>
<TokenAndSignatureRequest>
  <ClientId>0000000049075E37</ClientId>
  <TitleId>1792830437</TitleId>
  <Url>https://achievements.xboxlive.com/users/xuid(1)/achievements?titleId=1792830437</Url>
  <Method>GET</Method>
  <Headers>
    <Header>
      <Name>x-xbl-contract-version</Name>
      <Value>2</Value>
    </Header>
    <Header>
      <Name>Accept</Name>
      <Value>application/json</Value>
    </Header>
  </Headers>
  <Body>eyJhIjoxfQ==</Body>
  <ForceRefresh>true</ForceRefresh>
</TokenAndSignatureRequest>
"#;
        let req: TokenAndSignatureRequest = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(req.client_id.as_deref(), Some("0000000049075E37"));
        assert_eq!(req.title_id, Some(1792830437));
        assert_eq!(req.method.as_deref(), Some("GET"));
        let headers = req.headers.unwrap().header;
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].name, "Accept");
        assert_eq!(headers[1].value, "application/json");
        assert_eq!(req.body.as_deref(), Some("eyJhIjoxfQ=="));
        assert!(req.force_refresh);

        // minimal request: only Url is required
        let req: TokenAndSignatureRequest =
            quick_xml::de::from_str("<TokenAndSignatureRequest><Url>https://x.xboxlive.com/</Url></TokenAndSignatureRequest>")
                .unwrap();
        assert!(req.client_id.is_none() && req.title_id.is_none() && req.headers.is_none());
        assert!(!req.force_refresh);
    }

    #[test]
    fn token_and_signature_response_xml() {
        let ok = TokenAndSignatureResponse {
            token: Some("XBL3.0 x=123;eyJ".to_string()),
            signature: Some("AAAAAQ==".to_string()),
            expiry: Some(1_760_000_000),
            ..Default::default()
        };
        assert_eq!(
            quick_xml::se::to_string(&ok).unwrap(),
            "<TokenAndSignatureResponse><Token>XBL3.0 x=123;eyJ</Token><Signature>AAAAAQ==</Signature><Expiry>1760000000</Expiry></TokenAndSignatureResponse>"
        );
        let err = TokenAndSignatureResponse::error(0x89245101, "no user is signed in");
        assert_eq!(
            quick_xml::se::to_string(&err).unwrap(),
            "<TokenAndSignatureResponse><Error>0x89245101</Error><Message>no user is signed in</Message></TokenAndSignatureResponse>"
        );
    }
}
