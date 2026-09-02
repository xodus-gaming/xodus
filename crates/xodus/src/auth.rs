use reqwest::Client;
use xal::client_params::CLIENT_WINDOWS;
use xal::oauth2::basic::BasicTokenType;
use xal::oauth2::{EmptyExtraTokenFields, RedirectUrl, Scope, StandardTokenResponse};
use xal::response::{
    XADDisplayClaims, XATDisplayClaims, XAUDisplayClaims, XSTSDisplayClaims, XTokenResponse,
};
use xal::{
    AuthPromptCallback, Constants, DeviceType, Flows, TokenStore, XalAppParameters,
    XalAuthenticator,
};

use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::Token;
use crate::models::soap;
use crate::tokens::TokenManager;

fn get_app_params() -> XalAppParameters {
    XalAppParameters {
        client_id: "000000004424da1f".to_string(),
        title_id: Some("704208617".into()),
        auth_scopes: vec![Scope::new(
            xal::Constants::SCOPE_SERVICE_USER_AUTH.to_owned(),
        )],
        redirect_uri: Some(
            RedirectUrl::new(xal::Constants::OAUTH20_DESKTOP_REDIRECT_URL.into()).unwrap(),
        ),
        client_secret: None,
    }
}

pub async fn start_new_session(
    cb: impl AuthPromptCallback,
) -> Result<TokenStore, Box<dyn std::error::Error>> {
    let app_params = get_app_params();
    let mut authenticator = XalAuthenticator::new(app_params, CLIENT_WINDOWS(), "RETAIL".into());
    let ts = Flows::ms_authorization_flow(&mut authenticator, cb, true).await?;
    let ts = Flows::xbox_live_authorization_traditional_flow(
        &mut authenticator,
        ts.live_token,
        Constants::RELYING_PARTY_XBOXLIVE.to_string(),
        xal::AccessTokenPrefix::None,
        false,
    )
    .await?;
    Ok(ts)
}

pub async fn get_xsts_token(
    device_token: Option<&XTokenResponse<XADDisplayClaims>>,
    title_token: Option<&XTokenResponse<XATDisplayClaims>>,
    user_token: Option<&XTokenResponse<XAUDisplayClaims>>,
    relying_party: &str,
) -> Result<XTokenResponse<XSTSDisplayClaims>, xal::Error> {
    let app_params = get_app_params();
    let mut authenticator = XalAuthenticator::new(app_params, CLIENT_WINDOWS(), "RETAIL".into());
    authenticator
        .get_xsts_token(device_token, title_token, user_token, relying_party)
        .await
}

pub async fn refresh_tokens(
    authenticator: &mut XalAuthenticator,
    live_token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
) -> Result<TokenStore, Box<dyn std::error::Error>> {
    let ts = Flows::xbox_live_sisu_authorization_flow(authenticator, live_token).await?;
    Ok(ts)
}

pub async fn do_sisu(
    client: &Client,
    manager: &TokenManager,
    client_id: &str,
    title_id: i64,
) -> Result<
    (
        XalAuthenticator,
        xal::response::SisuRPSAuthorizationResponse,
        xal::response::DeviceToken,
    ),
    Box<dyn std::error::Error>,
> {
    let Token::Legacy(token) = manager.get_user_sts_token()? else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };
    let scope = "xboxlive.signin";
    let Token::Legacy(device_token) = manager.get_device_sts_token()? else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };
    let device_token_resp: soap::RequestSecurityTokenResponse =
        crate::api::live::exchange_device_token(
            client,
            device_token.clone(),
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await?;

    let Token::Compact(ms_device_token) = device_token_resp.into() else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    let user_token = crate::api::live::exchange_user_token(
        client,
        token,
        "USERNAME".to_string(),
        device_token,
        None,
        Some("Silent".to_string()),
        client_id.to_string(),
        &[
            (
                format!("scope={scope}&api-version=2.0&clientid={client_id}"),
                Some(soap::PolicyReference::token_broker()),
            ),
            ("http://Passport.NET/tb".to_string(), None),
        ],
    )
    .await?;

    let ExchangeUserTokenOutcome::Issued(
        soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
    ) = user_token
    else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    if let Some(sts) = collection.security_tokens.pop() {
        let address = sts.applies_to.endpoint_reference.address.clone();
        let sts: Token = sts.into();
        let address = if let Token::Legacy(legacy) = &sts {
            legacy.key_name.clone().unwrap_or(address)
        } else {
            address
        };
        if let Err(err) = manager.save_user_token(address, sts) {
            tracing::warn!("Failed to persist refreshed STS token: {err}");
        }
    }
    let token: soap::RequestSecurityTokenResponse = collection.security_tokens.remove(0);
    let token: Token = token.into();
    let Token::Compact(user_token) = token else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    let mut auth = XalAuthenticator::new(
        XalAppParameters {
            client_id: client_id.to_owned(),
            title_id: Some(title_id.to_string()),
            auth_scopes: vec![],
            redirect_uri: None,
            client_secret: None,
        },
        xal::XalClientParameters {
            user_agent: "XAL GRTS 2025.11.20251105.000".to_string(),
            device_type: DeviceType::WIN32,
            client_version: "10.0.22621".to_string(),
            query_display: String::new(),
        },
        "RETAIL".to_owned(),
    );

    let data = auth
        .get_device_token_rps(ms_device_token.to_owned())
        .await?;
    let resp = auth
        .sisu_authorize_rps(&user_token, &data.token, None)
        .await
        .expect("ok");
    Ok((auth, resp, data))
}

#[ignore]
#[tokio::test]
async fn test_minecraft_win_auth() {
    let client = reqwest::Client::new();
    crate::secrets::init_secrets().expect("Unable to initialize credentials");
    let tokens = TokenManager::with_keychain_and_memory();

    let (_, resp, _) = do_sisu(&client, &tokens, "0000000040159362", 896928775)
        .await
        .expect("ok");

    println!("title {}", resp.title_token.token);
    println!("user {}", resp.user_token.token);
    println!("webpage {}", resp.web_page);
}
