// Temporary context, full service design will be much more extensive

use std::collections::HashMap;
use std::sync::Arc;

use xodus::auth::{TitleSession, XstsToken};
use xodus::models::secrets::LegacyToken;
use xodus::models::xbox::TitleMgtResponse;
use xodus::tokens::TokenManager;

/// State shared by every connection: title-bound Xbox Live sessions and their XSTS tokens
/// (a game may reconnect, and several processes of one title must share one session).
#[derive(Default)]
pub struct SharedState {
    /// Keyed by `"<msa app id>:<title id>"`.
    pub sessions: tokio::sync::Mutex<HashMap<String, TitleSession>>,
    /// Keyed by `"<msa app id>:<title id>:<relying party>"`.
    pub xsts: tokio::sync::Mutex<HashMap<String, XstsToken>>,
    /// Endpoint -> relying party / signature policy table from title.mgt.xboxlive.com.
    pub endpoints: tokio::sync::Mutex<Option<TitleMgtResponse>>,
}

pub struct SimpleContext {
    pub client: reqwest::Client,
    pub device_token: Option<LegacyToken>,
    pub shared: Arc<SharedState>,
    tokens: Arc<TokenManager>,
}

impl SimpleContext {
    pub fn new(
        device_token: LegacyToken,
        tokens: Arc<TokenManager>,
        shared: Arc<SharedState>,
    ) -> Self {
        let client = reqwest::ClientBuilder::new()
            .user_agent(format!("xodus-service/{}", env!("CARGO_PKG_VERSION")))
            .connection_verbose(true)
            .build()
            .unwrap();

        Self {
            client,
            device_token: Some(device_token),
            shared,
            tokens,
        }
    }

    pub fn tokens(&self) -> &Arc<TokenManager> {
        &self.tokens
    }
}
