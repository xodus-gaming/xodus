use crate::{device, user};
use xodus::models::secrets::Token;
use xodus::api;
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::soap;

pub async fn run(client: &reqwest::Client) {

    let dev_token = device::get_device_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        eprintln!("Invalid STS token");
        return;
    };
    let user = user::get_user().unwrap();
    let user_token = user::get_token("http://Passport.NET/STS".to_string()).unwrap();
    let Token::Legacy(legacy) = user_token else {
        eprintln!("Unspported user token");
        return;
    };

    let secret = dev_token.binary_secret.unwrap();

    let user_token = api::live::exchange_user_token(
        client,
        legacy.token,
        user.username,
        dev_token.token,
        secret,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
        .await
        .expect("Failed to get ms user token");

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            eprintln!("Failed to get exchange MS token");
            return;
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
        eprintln!("Unspported token");
        return;
    };

    let token = user::get_token("scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_string()).unwrap();
    let Token::Compact(token) = token else {
        eprintln!("Unspported user token");
        return;
    };

    let xbltoken = api::xbox::authenticate_xbox_user(client, token).await.unwrap();

    let xsts = api::xbox::request_xsts_token(client, xbltoken.token, "http://mp.microsoft.com/").await;
    if xsts.is_err() {
        eprintln!("Failed to authenticate Xbox user");
        return;
    }
    let xsts_header = api::xbox::get_xsts_auth_header(xsts.unwrap());

    let games = api::xbox::services::get_library(client, user_token, xsts_header).await;

    println!("{:?}", games);
}