use std::process::ExitCode;

use xodus::api::live::ExchangeTokenResponseOutcome;
use xodus::api::live::rst::RSTError;
use xodus::models::live::DAProperty;
use xodus::models::{secrets, soap};
use xodus::tokens::TokenManager;

use crate::webview;

const CLIENT_ID: &str = "000000004424da1f";
const LOGIN_MARKET: &str = "en-US";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0";

pub async fn run(client: &reqwest::Client, tokens: &TokenManager) -> ExitCode {
    let token = tokens.get_device_sts_token().unwrap();
    let secrets::Token::Legacy(token) = token else {
        eprintln!("Invalid STS token");
        return ExitCode::FAILURE;
    };
    let handler = LoginHandler::new(client.clone(), token, tokens.clone());
    let output = webview::run_sessions(handler)
        .expect("failed to login")
        .flatten();
    match output {
        Some(resp) => resp.refresh_user(tokens).expect("user tokens to be saved"),
        None => {
            eprintln!("Didn't log in");
            return ExitCode::FAILURE;
        }
    };

    ExitCode::SUCCESS
}

struct LoginHandler {
    client: reqwest::Client,
    device: xodus::models::secrets::LegacyToken,
    client_id: String,
    finish: bool,
    tokens: TokenManager,
}

impl LoginHandler {
    fn new(
        client: reqwest::Client,
        device: xodus::models::secrets::LegacyToken,
        tokens: TokenManager,
    ) -> Self {
        Self {
            client,
            device,
            client_id: CLIENT_ID.to_string(),
            finish: false,
            tokens,
        }
    }

    fn exchange_user_token(
        &self,
        prop: DAProperty,
    ) -> Result<soap::RequestSecurityTokenResponseCollection, RSTError> {
        let client = self.client.clone();
        let device_token = self.device.clone();
        let client_id = self.client_id.clone();
        let username = prop.username;
        let inline_ft = prop.sts_inline_flow_token;
        let user_token = xodus::models::secrets::LegacyToken {
            key_name: None,
            token: prop.da_token,
            binary_secret: None,
            tpm_key: None,
            lifetime: soap::Timestamp {
                id: None,
                created: prop.da_start_time,
                expires: prop.da_expires,
            },
        };

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let mut scopes = vec![(
                    USER_AUTH_SCOPE.to_string(),
                    Some(soap::PolicyReference::token_broker()),
                )];

                if self.finish {
                    scopes.push(("http://Passport.NET/tb".to_string(), None));
                }

                xodus::api::live::exchange_user_token(
                    &client,
                    user_token,
                    username,
                    device_token,
                    Some(inline_ft),
                    None,
                    client_id,
                    &scopes,
                )
                .await
            })
        })
    }
}

impl webview::SessionHandler for LoginHandler {
    type Output = Option<soap::RequestSecurityTokenResponseCollection>;

    fn bootstrap(
        &mut self,
        runtime: &mut webview::RuntimeCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        runtime.open_session(webview::login_request(
            self.client_id.clone(),
            LOGIN_MARKET.to_string(),
        ));
        Ok(())
    }

    fn on_token(
        &mut self,
        session_id: webview::SessionId,
        data: DAProperty,
        runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        match self.exchange_user_token(data.clone()) {
            Err(RSTError::TokenFault(pp)) => {
                if let Some(pp) = pp
                    && let Some(auth_url) = pp.inline_auth_url
                {
                    runtime.close_session(session_id);
                    self.finish = true;
                    runtime.open_session(webview::finalize_request(auth_url));
                    return Ok(webview::HandlerControl::Continue);
                }

                println!("User token exchange returned a fault without inline auth");
                runtime.close_session(session_id);
                Ok(webview::HandlerControl::Complete(None))
            }
            Ok(exchanged) => {
                runtime.close_session(session_id);
                self.tokens
                    .save_user(&xodus::models::secrets::User {
                        puid: data.puid,
                        username: data.username,
                    })
                    .unwrap();
                Ok(webview::HandlerControl::Complete(Some(exchanged)))
            }
            Err(e) => Err(Box::new(e)),
        }
    }

    fn on_closed(
        &mut self,
        _session_id: webview::SessionId,
        _runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        Ok(webview::HandlerControl::Complete(None))
    }
}
