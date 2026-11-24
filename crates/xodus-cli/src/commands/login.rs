use std::process::ExitCode;

use xodus::models::live::{DAProperty, ExchangeUserTokenOutcome};
use xodus::models::{secrets, soap};
use xodus::tokens::TokenManager;

use crate::webview;

const CLIENT_ID: &str = "000000004424da1f";
const LOGIN_MARKET: &str = "en-US";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0";
/// Exit status when no token was obtained (window closed); xodus-service maps it to E_ABORT.
const LOGIN_CANCELLED_EXIT: u8 = 2;
/// Exit status when sign-in failed with an error (e.g. an RST2 Fault); distinct from cancel.
const LOGIN_FAILED_EXIT: u8 = 3;
const FAULT_WITHOUT_INLINE_AUTH: &str = "User token exchange returned a fault without inline auth";

/// Maps the sign-in session outcome to (exit status, stderr text).
fn login_exit<T, E: std::fmt::Display>(outcome: Result<Option<T>, E>) -> (u8, Option<String>) {
    match outcome {
        Ok(Some(_)) => (0, None),
        Ok(None) => (LOGIN_CANCELLED_EXIT, None),
        Err(e) => (LOGIN_FAILED_EXIT, Some(format!("failed to login: {e}"))),
    }
}

/// A user-token Fault is only recoverable when its PP carries an inline auth URL.
fn user_token_fault(pp: Option<soap::PP>) -> Result<soap::PP, String> {
    match pp {
        Some(pp) if pp.inline_auth_url.is_some() => Ok(pp),
        _ => Err(FAULT_WITHOUT_INLINE_AUTH.to_string()),
    }
}

pub async fn run(client: &reqwest::Client, tokens: &TokenManager) -> ExitCode {
    let token = tokens.get_device_sts_token().unwrap();
    let secrets::Token::Legacy(token) = token else {
        eprintln!("Invalid STS token");
        return ExitCode::FAILURE;
    };
    let handler = LoginHandler::new(client.clone(), token, tokens.clone());
    let outcome = webview::run_sessions(handler).map(Option::flatten);
    let (status, message) = login_exit(outcome.as_ref().map(Option::as_ref));
    if let Some(message) = message {
        eprintln!("{message}");
    }
    let Ok(Some(output)) = outcome else {
        return ExitCode::from(status);
    };
    let issued_tokens = match output {
        soap::BodyContent::RequestSecurityTokenResponseCollection(collection) => {
            collection.security_tokens
        }
        soap::BodyContent::RequestSecurityTokenResponse(token) => vec![*token],
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
    ) -> Result<ExchangeUserTokenOutcome, Box<dyn std::error::Error>> {
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
                    None,
                )
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
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
                runtime.close_session(session_id);
                // user_token_fault guarantees inline_auth_url is Some.
                let auth_url = user_token_fault(pp)?.inline_auth_url.unwrap_or_default();
                self.finish = true;
                runtime.open_session(webview::finalize_request(auth_url));
                Ok(webview::HandlerControl::Continue)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pp(inline_auth_url: Option<&str>) -> soap::PP {
        soap::PP {
            xmlns_psf: None,
            server_version: None,
            req_status: None,
            inline_auth_url: inline_auth_url.map(String::from),
            inline_end_auth_url: None,
            auth_state_internal: None,
            user_session_key: None,
        }
    }

    #[test]
    fn login_exit_no_token_is_cancel() {
        assert_eq!(login_exit::<u8, &str>(Ok(None)), (2, None));
    }

    #[test]
    fn login_exit_err_is_failure() {
        assert_eq!(
            login_exit::<u8, &str>(Err("boom")),
            (3, Some("failed to login: boom".to_string()))
        );
    }

    #[test]
    fn login_exit_token_is_success() {
        assert_eq!(login_exit::<u8, &str>(Ok(Some(1))), (0, None));
    }

    #[test]
    fn login_exit_fault_without_inline_auth_is_failure() {
        for p in [None, Some(pp(None))] {
            let e = user_token_fault(p).unwrap_err();
            assert_eq!(e, FAULT_WITHOUT_INLINE_AUTH);
            assert_eq!(login_exit::<u8, _>(Err(e)).0, 3);
        }
        let ok = user_token_fault(Some(pp(Some("https://login.live.com/x")))).unwrap();
        assert_eq!(ok.inline_auth_url.as_deref(), Some("https://login.live.com/x"));
    }
}
