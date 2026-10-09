use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::models::xbox::XuiClaim;

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

/// `XUserAgeGroup` of the signed-in user, from the XSTS `agg` display claim.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgeGroup {
    #[default]
    Unknown,
    Child,
    Teen,
    Adult,
}

impl AgeGroup {
    /// Map the `agg` claim (`Adult`, `Teen` or `Child`, case-insensitive); anything else,
    /// including an empty claim, is `Unknown`.
    pub fn from_claim(agg: &str) -> Self {
        match agg.trim().to_ascii_lowercase().as_str() {
            "child" => Self::Child,
            "teen" => Self::Teen,
            "adult" => Self::Adult,
            _ => Self::Unknown,
        }
    }

    /// Name on the wire (`<AgeGroup>` element content).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Child => "Child",
            Self::Teen => "Teen",
            Self::Adult => "Adult",
        }
    }
}

/// Identity of the signed-in user as the XSTS token's `DisplayClaims.xui[0]` carries it:
/// what `XUserGetId`, `XUserGetGamertag` and `XUserGetAgeGroup` report to the game. Every
/// field is optional because XSTS only includes the claims the relying party is entitled to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserIdentity {
    /// `xid`, decimal.
    pub xuid: Option<String>,
    /// `gtg`: classic gamertag.
    pub gamertag: Option<String>,
    /// `mgt`: modern gamertag.
    pub modern_gamertag: Option<String>,
    /// `mgs`: modern gamertag suffix (empty when the modern gamertag is unique by itself).
    pub modern_gamertag_suffix: Option<String>,
    /// `umg`: unique modern gamertag (modern gamertag plus `#suffix`).
    pub unique_modern_gamertag: Option<String>,
    /// `agg`.
    pub age_group: Option<AgeGroup>,
    /// `uhs`: user hash, the `x=` part of the `XBL3.0` Authorization value.
    pub uhs: Option<String>,
}

impl UserIdentity {
    /// From a raw `xui` claim map as XSTS returns it.
    pub fn from_claims(claims: &HashMap<String, String>) -> Self {
        let claim = |key: &str| claims.get(key).cloned();
        Self {
            xuid: claim("xid"),
            gamertag: claim("gtg"),
            modern_gamertag: claim("mgt"),
            modern_gamertag_suffix: claim("mgs"),
            unique_modern_gamertag: claim("umg"),
            age_group: claims.get("agg").map(|agg| AgeGroup::from_claim(agg)),
            uhs: claim("uhs"),
        }
    }

    /// From a title-bound XSTS token; `None` when it carries no display claims.
    pub fn from_xsts(token: &xal::response::XSTSToken) -> Option<Self> {
        token
            .display_claims
            .as_ref()?
            .xui
            .first()
            .map(Self::from_claims)
    }
}

/// From the claims of a user-only XSTS token.
impl From<&XuiClaim> for UserIdentity {
    fn from(claim: &XuiClaim) -> Self {
        Self {
            xuid: claim.xid.clone(),
            gamertag: claim.gtg.clone(),
            modern_gamertag: claim.mgt.clone(),
            modern_gamertag_suffix: claim.mgs.clone(),
            unique_modern_gamertag: claim.umg.clone(),
            age_group: claim.agg.as_deref().map(AgeGroup::from_claim),
            uhs: Some(claim.uhs.clone()),
        }
    }
}

fn hresult_string(hresult: u32) -> String {
    format!("0x{hresult:08X}")
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

/// Response to [`TokenAndSignatureRequest`]. Either `Token` (+ `Signature`, `Expiry` and the
/// identity claims of the user the token was issued for) or `Error` (HRESULT as
/// `0x........`) + `Message` is present.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub xuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gamertag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modern_gamertag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modern_gamertag_suffix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_modern_gamertag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_group: Option<AgeGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uhs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl TokenAndSignatureResponse {
    pub fn error(hresult: u32, message: impl Into<String>) -> Self {
        Self {
            error: Some(hresult_string(hresult)),
            message: Some(message.into()),
            ..Default::default()
        }
    }

    /// Attach the identity claims of the user the token was issued for.
    pub fn with_identity(mut self, identity: UserIdentity) -> Self {
        self.xuid = identity.xuid;
        self.gamertag = identity.gamertag;
        self.modern_gamertag = identity.modern_gamertag;
        self.modern_gamertag_suffix = identity.modern_gamertag_suffix;
        self.unique_modern_gamertag = identity.unique_modern_gamertag;
        self.age_group = identity.age_group;
        self.uhs = identity.uhs;
        self
    }
}

/// `XUserAddAsync` forwarded by the runtime: who is signed in to xodus, so the game's single
/// user can carry the real xuid, gamertags and age group.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserInfoRequest {
    /// MSA app id of the title (`MSAAppId` in MicrosoftGame.config). Optional: without it
    /// and `TitleId` the claims come from a user-only XSTS token.
    #[serde(default, alias = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Numeric title id (`TitleId` in MicrosoftGame.config, decimal here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_id: Option<u32>,
    /// Request a fresh XSTS token instead of the cached one.
    #[serde(default)]
    pub force_refresh: bool,
}

/// Response to [`UserInfoRequest`]: `SignedIn` true plus the identity claims, `SignedIn`
/// false when nobody is signed in to xodus, or `Error` (HRESULT as `0x........`) + `Message`
/// when the signed-in user's identity could not be established.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserInfoResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_in: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gamertag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modern_gamertag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modern_gamertag_suffix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_modern_gamertag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_group: Option<AgeGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uhs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl UserInfoResponse {
    pub fn signed_in(identity: UserIdentity) -> Self {
        Self {
            signed_in: Some(true),
            xuid: identity.xuid,
            gamertag: identity.gamertag,
            modern_gamertag: identity.modern_gamertag,
            modern_gamertag_suffix: identity.modern_gamertag_suffix,
            unique_modern_gamertag: identity.unique_modern_gamertag,
            age_group: identity.age_group,
            uhs: identity.uhs,
            ..Default::default()
        }
    }

    pub fn signed_out() -> Self {
        Self {
            signed_in: Some(false),
            ..Default::default()
        }
    }

    pub fn error(hresult: u32, message: impl Into<String>) -> Self {
        Self {
            error: Some(hresult_string(hresult)),
            message: Some(message.into()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    use xal::response::{XSTSDisplayClaims, XSTSToken};

    use super::*;

    /// `xui[0]` of an XSTS token for http://xboxlive.com (values made up).
    fn claims() -> HashMap<String, String> {
        [
            ("xid", "2535405123456789"),
            ("gtg", "Gamer Tag"),
            ("mgt", "GamerTag"),
            ("mgs", "1234"),
            ("umg", "GamerTag#1234"),
            ("agg", "Adult"),
            ("uhs", "1234567890123456"),
            ("prv", "184 185 186"),
            ("usr", "234"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn identity() -> UserIdentity {
        UserIdentity {
            xuid: Some("2535405123456789".to_string()),
            gamertag: Some("Gamer Tag".to_string()),
            modern_gamertag: Some("GamerTag".to_string()),
            modern_gamertag_suffix: Some("1234".to_string()),
            unique_modern_gamertag: Some("GamerTag#1234".to_string()),
            age_group: Some(AgeGroup::Adult),
            uhs: Some("1234567890123456".to_string()),
        }
    }

    const IDENTITY_XML: &str = "<Xuid>2535405123456789</Xuid><Gamertag>Gamer Tag</Gamertag><ModernGamertag>GamerTag</ModernGamertag><ModernGamertagSuffix>1234</ModernGamertagSuffix><UniqueModernGamertag>GamerTag#1234</UniqueModernGamertag><AgeGroup>Adult</AgeGroup><Uhs>1234567890123456</Uhs>";

    #[test]
    fn age_group_from_claim() {
        assert_eq!(AgeGroup::from_claim("Adult"), AgeGroup::Adult);
        assert_eq!(AgeGroup::from_claim("Teen"), AgeGroup::Teen);
        assert_eq!(AgeGroup::from_claim("Child"), AgeGroup::Child);
        // case and whitespace do not matter
        assert_eq!(AgeGroup::from_claim("adult"), AgeGroup::Adult);
        assert_eq!(AgeGroup::from_claim(" TEEN "), AgeGroup::Teen);
        // anything else is Unknown
        assert_eq!(AgeGroup::from_claim("Unknown"), AgeGroup::Unknown);
        assert_eq!(AgeGroup::from_claim("Senior"), AgeGroup::Unknown);
        assert_eq!(AgeGroup::from_claim(""), AgeGroup::Unknown);
        assert_eq!(AgeGroup::default(), AgeGroup::Unknown);
        // the wire names round-trip through the mapping
        for group in [
            AgeGroup::Unknown,
            AgeGroup::Child,
            AgeGroup::Teen,
            AgeGroup::Adult,
        ] {
            assert_eq!(AgeGroup::from_claim(group.as_str()), group);
        }
    }

    #[test]
    fn user_identity_from_claims() {
        assert_eq!(UserIdentity::from_claims(&claims()), identity());

        // a token for another relying party may carry nothing but the user hash
        let uhs_only = HashMap::from([("uhs".to_string(), "42".to_string())]);
        let partial = UserIdentity::from_claims(&uhs_only);
        assert_eq!(partial.uhs.as_deref(), Some("42"));
        assert!(partial.xuid.is_none() && partial.gamertag.is_none());
        assert!(partial.age_group.is_none());

        // an unrecognised age group claim is reported as Unknown, not dropped
        let odd_agg = HashMap::from([("agg".to_string(), "Senior".to_string())]);
        assert_eq!(
            UserIdentity::from_claims(&odd_agg).age_group,
            Some(AgeGroup::Unknown)
        );

        // title-bound token: None without display claims, else xui[0]
        let token: XSTSToken = "eyJ".into();
        assert!(token.display_claims.is_none());
        assert!(UserIdentity::from_xsts(&token).is_none());
        let token = XSTSToken {
            display_claims: Some(XSTSDisplayClaims { xui: vec![] }),
            ..token
        };
        assert!(UserIdentity::from_xsts(&token).is_none());
        let token = XSTSToken {
            display_claims: Some(XSTSDisplayClaims {
                xui: vec![claims()],
            }),
            ..token
        };
        assert_eq!(UserIdentity::from_xsts(&token), Some(identity()));

        // user-only token: claims as xodus's own XSTS model carries them
        let claim: XuiClaim = serde_json::from_str(
            r#"{"uhs":"1234567890123456","gtg":"Gamer Tag","xid":"2535405123456789","mgt":"GamerTag","agg":"Adult","mgs":"1234","umg":"GamerTag#1234"}"#,
        )
        .unwrap();
        assert_eq!(UserIdentity::from(&claim), identity());
        // ... and the fields a cached pre-mgs/umg claim lacks are simply absent
        let claim: XuiClaim = serde_json::from_str(r#"{"uhs":"42"}"#).unwrap();
        let from_old_cache = UserIdentity::from(&claim);
        assert_eq!(from_old_cache.uhs.as_deref(), Some("42"));
        assert!(from_old_cache.modern_gamertag_suffix.is_none());
        assert!(from_old_cache.unique_modern_gamertag.is_none());
    }

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

    /// Success replies carry the claims of the user the token was issued for; an unsigned
    /// token has an empty `Signature`.
    #[test]
    fn token_and_signature_response_identity_xml() {
        let ok = TokenAndSignatureResponse {
            token: Some("XBL3.0 x=1234567890123456;eyJ".to_string()),
            signature: Some(String::new()),
            expiry: Some(1_760_000_000),
            ..Default::default()
        }
        .with_identity(identity());
        let xml = quick_xml::se::to_string(&ok).unwrap();
        assert_eq!(
            xml,
            format!(
                "<TokenAndSignatureResponse><Token>XBL3.0 x=1234567890123456;eyJ</Token><Signature/><Expiry>1760000000</Expiry>{IDENTITY_XML}</TokenAndSignatureResponse>"
            )
        );
        let parsed: TokenAndSignatureResponse = quick_xml::de::from_str(&xml).unwrap();
        assert_eq!(parsed, ok);

        // claims are optional: a token for a relying party that only gets the user hash
        let partial = TokenAndSignatureResponse {
            token: Some("XBL3.0 x=42;eyJ".to_string()),
            signature: Some("AAAAAQ==".to_string()),
            expiry: Some(1_760_000_000),
            ..Default::default()
        }
        .with_identity(UserIdentity {
            uhs: Some("42".to_string()),
            ..Default::default()
        });
        assert_eq!(
            quick_xml::se::to_string(&partial).unwrap(),
            "<TokenAndSignatureResponse><Token>XBL3.0 x=42;eyJ</Token><Signature>AAAAAQ==</Signature><Expiry>1760000000</Expiry><Uhs>42</Uhs></TokenAndSignatureResponse>"
        );
    }

    /// The request as WineGDK's libxml builder formats it, plus the minimal forms.
    #[test]
    fn user_info_request_xml() {
        let xml = r#"<?xml version="1.0"?>
<UserInfoRequest>
  <ClientId>0000000049075E37</ClientId>
  <TitleId>1792830437</TitleId>
  <ForceRefresh>true</ForceRefresh>
</UserInfoRequest>
"#;
        let req: UserInfoRequest = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(req.client_id.as_deref(), Some("0000000049075E37"));
        assert_eq!(req.title_id, Some(1792830437));
        assert!(req.force_refresh);

        // nothing is required: stored user token, default relying party, cached token
        for xml in ["<UserInfoRequest/>", "<UserInfoRequest></UserInfoRequest>"] {
            let req: UserInfoRequest = quick_xml::de::from_str(xml).unwrap();
            assert_eq!(req, UserInfoRequest::default());
        }

        // what a Rust client sends
        let req = UserInfoRequest {
            client_id: Some("0000000049075E37".to_string()),
            title_id: Some(1792830437),
            force_refresh: false,
        };
        let xml = quick_xml::se::to_string(&req).unwrap();
        assert_eq!(
            xml,
            "<UserInfoRequest><ClientId>0000000049075E37</ClientId><TitleId>1792830437</TitleId><ForceRefresh>false</ForceRefresh></UserInfoRequest>"
        );
        assert_eq!(
            quick_xml::de::from_str::<UserInfoRequest>(&xml).unwrap(),
            req
        );
        assert_eq!(
            quick_xml::se::to_string(&UserInfoRequest::default()).unwrap(),
            "<UserInfoRequest><ForceRefresh>false</ForceRefresh></UserInfoRequest>"
        );
    }

    #[test]
    fn user_info_response_xml() {
        let signed_in = UserInfoResponse::signed_in(identity());
        let xml = quick_xml::se::to_string(&signed_in).unwrap();
        assert_eq!(
            xml,
            format!("<UserInfoResponse><SignedIn>true</SignedIn>{IDENTITY_XML}</UserInfoResponse>")
        );
        let parsed: UserInfoResponse = quick_xml::de::from_str(&xml).unwrap();
        assert_eq!(parsed, signed_in);

        let signed_out = UserInfoResponse::signed_out();
        let xml = quick_xml::se::to_string(&signed_out).unwrap();
        assert_eq!(
            xml,
            "<UserInfoResponse><SignedIn>false</SignedIn></UserInfoResponse>"
        );
        let parsed: UserInfoResponse = quick_xml::de::from_str(&xml).unwrap();
        assert_eq!(parsed, signed_out);
        assert_eq!(parsed.signed_in, Some(false));

        let err = UserInfoResponse::error(0x89245102, "Xbox Live sign-in failed: 401");
        let xml = quick_xml::se::to_string(&err).unwrap();
        assert_eq!(
            xml,
            "<UserInfoResponse><Error>0x89245102</Error><Message>Xbox Live sign-in failed: 401</Message></UserInfoResponse>"
        );
        let parsed: UserInfoResponse = quick_xml::de::from_str(&xml).unwrap();
        assert_eq!(parsed, err);
        assert!(parsed.signed_in.is_none());
    }
}
