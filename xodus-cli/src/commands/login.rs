use crate::{device, webview};
use xodus::models::live::{DAProperty, ExchangeUserTokenOutcome};
use xodus::models::soap::PolicyReference;

const CLIENT_ID: &str = "000000004424da1f";
const LOGIN_MARKET: &str = "pl-PL";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&amp;api-version=2.0";

pub async fn run(client: &reqwest::Client) {
    let handler = LoginHandler::new(client.clone(), device::get_device_token().unwrap());
    webview::run_sessions(handler).expect("failed to login");
}

struct LoginHandler {
    client: reqwest::Client,
    device: xodus::models::secrets::Token,
    client_id: String,
    finish: bool
}

impl LoginHandler {
    fn new(client: reqwest::Client, device: xodus::models::secrets::Token) -> Self {
        Self {
            client,
            device,
            client_id: CLIENT_ID.to_string(),
            finish: false
        }
    }

    fn exchange_user_token(&self, prop: DAProperty) -> reqwest::Result<ExchangeUserTokenOutcome> {
        let client = self.client.clone();
        let cipher_value = self.device.cipher_value.clone();
        let binary_secret = self.device.binary_secret.clone();
        let client_id = self.client_id.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let mut scopes = vec![(
                    USER_AUTH_SCOPE.to_string(),
                    Some(PolicyReference::token_broker()),
                )];

                if self.finish {
                    scopes.push(("http://Passport.NET/tb".to_string(), None));
                }

                xodus::api::live::exchange_user_token(
                    &client,
                    prop.da_token,
                    prop.username,
                    cipher_value,
                    binary_secret,
                    Some(prop.sts_inline_flow_token),
                    client_id,
                    &scopes,
                )
                .await
            })
        })
    }
}

impl webview::SessionHandler for LoginHandler {
    type Output = ();

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
        let exchanged = self.exchange_user_token(data)?;

        match exchanged {
            ExchangeUserTokenOutcome::Fault(pp) => {
                if let Some(pp) = pp {
                    if let Some(auth_url) = pp.inline_auth_url {
                        runtime.close_session(session_id);
                        self.finish = true;
                        runtime.open_session(webview::finalize_request(auth_url));
                        return Ok(webview::HandlerControl::Continue);
                    }
                }

                println!("User token exchange returned a fault without inline auth");
                runtime.close_session(session_id);
                Ok(webview::HandlerControl::Complete(()))
            }
            ExchangeUserTokenOutcome::Issued(da) => {
                println!("{da:?}");
                runtime.close_session(session_id);
                Ok(webview::HandlerControl::Complete(()))
            }
        }
    }

    fn on_closed(
        &mut self,
        _session_id: webview::SessionId,
        _runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        Ok(webview::HandlerControl::Complete(()))
    }
}
