use xal::{
    AuthPromptCallback, Constants, Flows, TokenStore, XalAppParameters, XalAuthenticator,
    client_params::CLIENT_WINDOWS,
    oauth2::{
        EmptyExtraTokenFields, RedirectUrl, Scope, StandardTokenResponse, basic::BasicTokenType,
    },
    response::{
        XADDisplayClaims, XATDisplayClaims, XAUDisplayClaims, XSTSDisplayClaims, XTokenResponse,
    },
};

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
