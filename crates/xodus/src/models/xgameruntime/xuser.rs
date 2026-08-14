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

/// XUserGetTokenAndSignature, relayed from the Wine side. The relying party is
/// derived from the request URL: Minecraft asks for
/// `https://b980a380.minecraft.playfabapi.com/`, the well-known Bedrock PlayFab
/// party.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsTokenRequest {
    pub relying_party: String,
    /// XUserGetTokenAndSignatureOptions::ForceRefresh - bypass the cache.
    #[serde(default)]
    pub force_refresh: bool,
    /// The title's `<MSAAppId>` from MicrosoftGame.Config. When present the
    /// token is minted through sisu so it carries the title claim; without it
    /// the user-token-only chain is used and PlayFab-style services refuse the
    /// result.
    #[serde(default)]
    pub app_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsTokenResponse {
    /// Ready to use as an Authorization header: `XBL3.0 x=<uhs>;<jwt>`.
    pub token: String,
    pub expiry: i64,
    /// Empty. Only xboxlive.com endpoints check a proof-of-possession
    /// signature, and reaching those needs a device key we do not have yet.
    #[serde(default)]
    pub signature: String,
    /// Real identity from the XSTS xui claim, so XUserGetId/XUserGetGamertag
    /// can agree with the token the title is about to send.
    pub xuid: String,
    pub gamertag: String,
}
