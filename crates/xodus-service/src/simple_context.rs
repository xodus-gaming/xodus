// Temporary context, full service design will be much more extensive

use std::sync::Arc;

use xodus::models::secrets::LegacyToken;
use xodus::api::xbox::title::TitleSession;
use xodus::models::xbox::TitleMgtResponse;
use xodus::tokens::TokenManager;

pub struct SimpleContext {
    pub client: reqwest::Client,
    pub device_token: Option<LegacyToken>,
    tokens: Arc<TokenManager>,
    /// Endpoint documents that map a service URL to the relying party Xbox issues
    /// tokens for. Fetched once each, since neither changes within a session. The
    /// title-scoped one is where a publisher's own back ends live.
    endpoints: Option<TitleMgtResponse>,
    title_endpoints: Option<TitleMgtResponse>,
    /// SISU is expensive, so the flow runs once and every relying party after the
    /// first costs only an XSTS exchange.
    title_session: Option<TitleSession>,
}

impl SimpleContext {
    pub fn new(device_token: LegacyToken, tokens: Arc<TokenManager>) -> Self {
        let client = reqwest::ClientBuilder::new()
            .user_agent(format!("xodus-service/{}", env!("CARGO_PKG_VERSION")))
            .connection_verbose(true)
            .build()
            .unwrap();

        Self {
            client,
            device_token: Some(device_token),
            tokens,
            endpoints: None,
            title_endpoints: None,
            title_session: None,
        }
    }

    /// Opens the title's SISU session on first use and hands it back afterwards.
    pub async fn title_session(
        &mut self,
        client_id: &str,
        title_id: u32,
    ) -> Option<&mut TitleSession> {
        if self.title_session.is_none() {
            match TitleSession::open(&self.client, &self.tokens, client_id, title_id).await {
                Ok(session) => self.title_session = Some(session),
                Err(err) => {
                    log::warn!("Title session unavailable: {err}");
                    return None;
                }
            }
        }
        self.title_session.as_mut()
    }

    /// Relying party to ask XSTS for when a caller names `url`. The title's own
    /// document wins over the platform-wide one, because that is where a publisher
    /// registers its back end. Anything neither document knows travels unchanged,
    /// which is what callers that already hold a relying party rely on.
    pub async fn relying_party_for(
        &mut self,
        url: &str,
        client_id: &str,
        title_id: Option<u32>,
    ) -> (String, bool) {
        if let Some(title_id) = title_id
            && self.title_endpoints.is_none()
        {
            // reqwest::Client is a handle around shared state, so cloning it here
            // just sidesteps holding two borrows of self at once.
            let client = self.client.clone();
            let fetched = match self.title_session(client_id, title_id).await {
                Some(session) => {
                    xodus::api::xbox::title::get_title_endpoints(&client, session).await
                }
                None => Err("no title session".into()),
            };
            match fetched {
                Ok(response) => {
                    log::debug!("Title {title_id:#x} publishes {} endpoints", response.end_points.len());
                    self.title_endpoints = Some(response);
                }
                Err(err) => log::warn!("Title endpoint document unavailable: {err}"),
            }
        }

        if self.endpoints.is_none() {
            match xodus::api::xbox::title::get_title_management(&self.client).await {
                Ok(response) => self.endpoints = Some(response),
                Err(err) => log::warn!("Endpoint document unavailable: {err}"),
            }
        }

        for (from_title, document) in [
            (true, self.title_endpoints.as_ref()),
            (false, self.endpoints.as_ref()),
        ]
        .into_iter()
        .filter_map(|(from_title, doc)| doc.map(|doc| (from_title, doc)))
        {
            let Some(endpoint) = xodus::api::xbox::title::get_endpoint(url, document) else {
                continue;
            };
            // A listed host without a relying party needs no token of its own, so
            // there is nothing better to say than what the caller asked for.
            if let Some(party) = endpoint.relying_party.as_deref() {
                log::debug!("{url} resolves to relying party {party}");
                return (party.to_string(), from_title);
            }
        }

        log::debug!("{url} is in no endpoint document, using it as-is");
        (url.to_string(), false)
    }

    pub fn tokens(&self) -> &Arc<TokenManager> {
        &self.tokens
    }
}
