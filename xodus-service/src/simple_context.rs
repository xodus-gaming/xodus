// Temporary context, full service design will be much more extensive

use std::collections::HashMap;

use xodus::models::{
    live::ExchangeUserTokenOutcome,
    secrets::{LegacyToken, Token},
    soap,
    xbox::{TitleMgtEndPoint, TitleMgtSignaturePolicy, XstsResponse},
};

#[derive(Debug)]
pub struct SimpleContext {
    pub client: reqwest::Client,
    pub device_token: Option<LegacyToken>,
    user_token: Option<XstsResponse>,
    cached_endpoints: Option<xodus::models::xbox::TitleMgtResponse>,
    user_token_cache: HashMap<String, XstsResponse>,
}

impl SimpleContext {
    pub fn new(device_token: LegacyToken) -> Self {
        let client = reqwest::ClientBuilder::new()
            .user_agent(format!("xodus-service/{}", env!("CARGO_PKG_VERSION")))
            .connection_verbose(true)
            .build()
            .unwrap();

        Self {
            client,
            device_token: Some(device_token),
            user_token: None,
            cached_endpoints: None,
            user_token_cache: HashMap::default(),
        }
    }

    pub async fn get_title_config(
        &mut self,
        url: &str,
    ) -> Option<(TitleMgtEndPoint, TitleMgtSignaturePolicy)> {
        if let Some(endpoints) = &self.cached_endpoints {
            let endpoint = xodus::api::xbox::title::get_endpoint(url, endpoints)?;
            let policy = endpoints
                .signature_policies
                .get(endpoint.signature_policy_index.unwrap_or_default() as usize)?;
            return Some((endpoint.clone(), policy.clone()));
        }

        let title_management = xodus::api::xbox::title::get_title_management(&self.client)
            .await
            .ok()?;
        let endpoint = xodus::api::xbox::title::get_endpoint(url, &title_management).cloned();
        let policies = title_management.signature_policies.clone();
        self.cached_endpoints = Some(title_management);

        let endpoint = endpoint?;
        let policy = policies
            .get(endpoint.signature_policy_index.unwrap_or_default() as usize)
            .cloned()?;

        Some((endpoint, policy))
    }

    pub async fn get_token<'a>(&'a mut self, relying_party: &str) -> Option<XstsResponse> {
        if let Some(token) = self.user_token_cache.get(relying_party)
            && token.not_after > chrono::Utc::now()
        {
            return Some(token.clone());
        }

        let user_token = match self.user_token.clone() {
            Some(t) => t,
            None => self.get_user_token().await?,
        };

        let token = xodus::api::xbox::request_xsts_token(
            &self.client,
            user_token.token.clone(),
            relying_party,
        )
        .await
        .ok()?;
        self.user_token_cache
            .insert(relying_party.to_string(), token.clone());
        Some(token)
    }

    async fn get_user_token<'a>(&'a mut self) -> Option<XstsResponse> {
        let Token::Legacy(token) = crate::user::get_token("http://Passport.NET/STS")? else {
            return None;
        };
        let device_token = self.device_token.as_ref().unwrap();
        let user_token = xodus::api::live::exchange_user_token(
            &self.client,
            token.token,
            "USERNAME".to_string(),
            device_token.token.clone(),
            device_token.binary_secret.clone().unwrap(),
            None,
            Some("Silent".to_string()),
            "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
            &[(
                "user.auth.xboxlive.com".to_owned(),
                Some(soap::PolicyReference::mbi_ssl()),
            )],
        )
        .await
        .ok()?;

        let user_token: Token = match user_token {
            ExchangeUserTokenOutcome::Fault(_) => {
                eprintln!("Failed to get exchange MS token");
                panic!("TODO");
            }
            ExchangeUserTokenOutcome::Issued(
                soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
            ) => {
                let token = collection.security_tokens.remove(0);
                token.into()
            }
            ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
                token,
            )) => token.into(),
            _ => unreachable!("Only responses are handled"),
        };
        let Token::Compact(user_token) = user_token else {
            return None;
        };

        let resp = xodus::api::xbox::authenticate_xbox_user(&self.client, user_token)
            .await
            .ok()?;
        self.user_token = Some(resp.clone());
        Some(resp)
    }
}
