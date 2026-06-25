use std::collections::HashMap;
use chrono::{DateTime, Utc};
use xal::response::XSTSToken;
use crate::device;
use crate::models::live::{DAProperty, ExchangeUserTokenOutcome};
use crate::models::{secrets, soap};
use crate::models::secrets::Token;

const CLIENT_ID: &str = "000000004424da1f";
const LOGIN_MARKET: &str = "en-US";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0";

pub fn get_users() -> Vec<User> {
    Vec::new()
}

pub fn get_user(puid: String) -> Option<User> {
    None
}

pub struct User {
    puid: String,
    username: String,
    da_login: Option<DAProperty>,
    tokens: HashMap<String, Token>,
    xbl_token: Option<XSTSToken>,
    xsts_token: Option<XSTSToken>,
}

impl User {

    pub async fn new(client: &reqwest::Client, da_login: DAProperty) -> Self {

        let device_token = device::get_device_token()
            .expect("Failed to get device credentials");
        let Token::Legacy(device_token) = device_token else {
            Err("Invalid device credentials").unwrap()
        };

        let exchange = exchange_user_token(client, da_login.clone(), device_token)
            .expect("Failed to exchange user token");
        let ExchangeUserTokenOutcome::Issued(exchange) = exchange else {
            Err("Failed to exchange user token").unwrap()
        };

        let soap = match exchange {
            soap::BodyContent::RequestSecurityTokenResponseCollection(collection) => {
                collection.security_tokens
            }
            soap::BodyContent::RequestSecurityTokenResponse(token) => vec![token],
            _ => unreachable!(),
        };

        let mut tokens = HashMap::new();
        for token in soap {
            let address = token.applies_to.endpoint_reference.address.clone();
            let token = token.into();
            let address = if let Token::Legacy(legacy) = &token {
                legacy.key_name.clone().unwrap_or(address)
            } else {
                address
            };
            tokens.insert(address, token);
        }

        Self {
            puid: da_login.puid.clone(),
            username: da_login.username.clone(),
            da_login: Some(da_login),
            tokens,
            xbl_token: None,
            xsts_token: None
        }
    }

    pub fn puid(&self) -> &String {
        &self.puid
    }

    pub fn username(&self) -> &String {
        &self.username
    }

    pub fn da_login(&self) -> &DAProperty {
        // Return token if it exists else run flow to get a new one
        if (self.da_login.is_none()) {
            // Login flow
            todo!()
        } else {
            let da_login = self.da_login.as_ref().unwrap();

            let expires: DateTime<Utc> = da_login.da_expires.clone().parse().unwrap();
            if expires < Utc::now() {
                // Login flow
                todo!()
            }

            da_login
        }
    }

    pub fn get_token(&self, address: String) -> Option<Token> {
        if let Some(token) = self.tokens.get(&address) {

            if let Token::Legacy(token) = &token {
                let expires: DateTime<Utc> = token.lifetime.expires.copy().parse().unwrap();

                if expires < Utc::now() {
                    // Login flow
                    // Will differ per-token probably
                    todo!()
                }
            }

            Some(token.clone())
        } else {
            None
        }
    }

    pub fn xbl_token(&self) -> XSTSToken {
        if let Some(token) = &self.xbl_token {
            let expires: DateTime<Utc> = token.not_after.to_utc();
            if expires < Utc::now() {
                // Login flow
                todo!()
            }
            token.clone()
        } else {
            // Login flow
            todo!()
        }
    }

    pub fn xsts_token(&self) -> XSTSToken {
        if let Some(token) = &self.xsts_token {
            let expires: DateTime<Utc> = token.not_after.to_utc();
            if expires < Utc::now() {
                // Login flow
                todo!()
            }
            token.clone()
        } else {
            // Login flow
            todo!()
        }
    }

}

fn exchange_user_token(client: &reqwest::Client, prop: DAProperty, device: secrets::LegacyToken) -> reqwest::Result<ExchangeUserTokenOutcome> {
    let device_token = device.token.clone();
    let binary_secret = device.binary_secret.clone();
    let client_id = CLIENT_ID.to_string();

    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async move {
            let scopes = vec![(
                USER_AUTH_SCOPE.to_string(),
                Some(soap::PolicyReference::token_broker()),
            )];

            crate::api::live::exchange_user_token(
                &client,
                prop.da_token,
                prop.username,
                device_token,
                binary_secret.unwrap(),
                Some(prop.sts_inline_flow_token),
                None,
                client_id,
                &scopes,
            )
                .await
        })
    })
}