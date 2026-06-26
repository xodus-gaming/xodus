use crate::webview;
use xodus::models::live::{DAProperty, ExchangeUserTokenOutcome};
use xodus::models::{secrets, soap};
use xodus::tokens::TokenManager;

const CLIENT_ID: &str = "000000004424da1f";
const LOGIN_MARKET: &str = "en-US";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0";

pub async fn run(client: &reqwest::Client, tokens: &TokenManager) {
    let token = tokens.get_device_sts_token().unwrap();
    let secrets::Token::Legacy(token) = token else {
        eprintln!("Invalid STS token");
        return;
    };
    let handler = LoginHandler::new(client.clone(), token, tokens.clone());
    let output = webview::run_sessions(handler)
        .expect("failed to login")
        .flatten();
    let issued_tokens = match output {
        Some(soap::BodyContent::RequestSecurityTokenResponseCollection(collection)) => {
            collection.security_tokens
        }
        Some(soap::BodyContent::RequestSecurityTokenResponse(token)) => vec![token],
        None => {
            eprintln!("Didn't log in");
            vec![]
        }
        _ => unreachable!(),
    };

    for token in issued_tokens {
        let address = token.applies_to.endpoint_reference.address.clone();
        let token = token.into();
        let address = if let secrets::Token::Legacy(legacy) = &token {
            legacy.key_name.clone().unwrap_or(address)
        } else {
            address
        };
        tokens.save_user_token(address, token).unwrap();
    }
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

    fn exchange_user_token(&self, prop: DAProperty) -> reqwest::Result<ExchangeUserTokenOutcome> {
        let client = self.client.clone();
        let device_token = self.device.token.clone();
        let binary_secret = self.device.binary_secret.clone();
        let client_id = self.client_id.clone();

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
}

impl webview::SessionHandler for LoginHandler {
    type Output = Option<soap::BodyContent>;

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
        let exchanged = self.exchange_user_token(data.clone())?;

        match exchanged {
            ExchangeUserTokenOutcome::Fault(pp) => {
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
            ExchangeUserTokenOutcome::Issued(da) => {
                runtime.close_session(session_id);
                self.tokens
                    .save_user(&xodus::models::secrets::User {
                        puid: data.puid,
                        username: data.username,
                    })
                    .unwrap();
                Ok(webview::HandlerControl::Complete(Some(da)))
            }
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
