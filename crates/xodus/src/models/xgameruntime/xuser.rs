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
    /// JWK of the caller's ECDSA P-256 public key, as JSON. Xbox binds the issued
    /// token to it so the caller can sign requests with the matching private key;
    /// titles that verify signatures reject tokens issued without one.
    #[serde(default)]
    pub proof_key: Option<String>,
    /// Title the caller runs as, in hex, from its MicrosoftGame.Config. Needed to
    /// look up the endpoint document that names the title's own relying parties.
    #[serde(default)]
    pub title_id: Option<String>,
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
    /// JWK of the caller's ECDSA P-256 public key, as JSON. See MSATokenRequest.
    #[serde(default)]
    pub proof_key: Option<String>,
    /// Title the caller runs as, in hex, from its MicrosoftGame.Config. Needed to
    /// look up the endpoint document that names the title's own relying parties.
    #[serde(default)]
    pub title_id: Option<String>,
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
