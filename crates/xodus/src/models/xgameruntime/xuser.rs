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

/// Request an XSTS token that carries a TITLE claim, for one relying party.
///
/// The caller supplies its own identity because only it knows them: the GDK
/// reads MSAAppId and TitleId out of MicrosoftGame.config.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsTokenRequest {
    pub relying_party: String,
    pub client_id: String,
    /// Decimal. MicrosoftGame.config stores TitleId in hex, so the caller
    /// converts; keeping it a string avoids a second XML integer convention.
    pub title_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsTokenResponse {
    pub token: String,
    /// The `x=` half of `XBL3.0 x=<uhs>;<token>`; it is per-token, so returning
    /// it here saves the caller parsing display claims it cannot see.
    pub user_hash: String,
    /// The XUID from the same display claims. The caller sets its user id from
    /// this: the local XSTS path reads `xid` out of the response itself, so a
    /// token minted here must hand it back or the user id silently stays 0 -
    /// which shows up as requests for `users/xuid(0)/...` being refused 403.
    pub xuid: String,
    pub expiry: i64,
}
