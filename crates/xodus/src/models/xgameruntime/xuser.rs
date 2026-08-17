use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenRequest {
    pub client_id: String,
    #[serde(default)]
    pub allow_ui: bool,
    #[serde(default, alias = "MSAFullTrust")]
    pub msa_full_trust: bool,
    /// Xbox Live relying party the caller needs a token for. Defaults to
    /// "http://xboxlive.com" when the caller does not care.
    #[serde(default)]
    pub relying_party: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenResponse {
    pub token: String,
    pub expiry: i64,
    pub device_rps: String,
    pub device_expiry: i64,
    /// Xbox Live identity for the signed-in user. Empty when the XSTS exchange
    /// could not be completed - the MSA token is still usable without it.
    #[serde(default)]
    pub xuid: String,
    #[serde(default)]
    pub gamertag: String,
    /// Ready-to-use Authorization header ("XBL3.0 x=<uhs>;<token>").
    #[serde(default)]
    pub xsts_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XSTSTokenRequest {
    /// Service the caller wants a token for, e.g. "https://merged-nms-auth.nomanssky.com".
    pub relying_party: String,
    /// Same MSA app id the title uses for its token requests.
    pub client_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XSTSTokenResponse {
    /// Ready-to-use Authorization header value ("XBL3.0 x=<uhs>;<token>").
    pub token: String,
    #[serde(default)]
    pub xuid: String,
    #[serde(default)]
    pub gamertag: String,
    pub expiry: i64,
}
