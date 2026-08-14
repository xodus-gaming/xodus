use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;
use crate::models::xbox::XstsResponse;

pub mod auth;
pub mod device;
pub mod signature;
pub mod title;
pub use auth::{authenticate_xbox_user, get_xsts_auth_header, request_xsts_token};
pub use signature::ProofKey;

/// MSA user token -> Xbox user token -> XSTS token for `relying_party`.
///
/// The relying party is whatever the caller needs a token for:
/// `http://xboxlive.com` for Xbox Live services,
/// `https://b980a380.minecraft.playfabapi.com/` for Minecraft Bedrock's PlayFab
/// title, and so on. No device or title token is attached; the parties reached
/// this way accept a plain user token.
pub async fn run(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
) -> Result<XstsResponse, Box<dyn std::error::Error + Send + Sync>> {
    let user_token = crate::api::live::exchange_user_token(
        client,
        legacy,
        "USERNAME".to_string(),
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "user.auth.xboxlive.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await?;

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(fault) => {
            return Err(format!("MSA rejected the user token exchange: {fault:?}").into());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            if collection.security_tokens.is_empty() {
                return Err("MSA returned no security tokens".into());
            }
            collection.security_tokens.remove(0).into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => return Err("Unexpected SOAP body in the user token exchange".into()),
    };
    let Token::Compact(user_token) = user_token else {
        return Err("MSA returned a legacy token where a compact one was expected".into());
    };

    let resp = authenticate_xbox_user(client, user_token).await?;

    Ok(request_xsts_token(client, resp.token, relying_party).await?)
}

/// Pull the compact token out of whatever shape MSA answered with.
fn compact_token(outcome: ExchangeUserTokenOutcome) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let token: Token = match outcome {
        ExchangeUserTokenOutcome::Fault(fault) => {
            return Err(format!("MSA rejected the token exchange: {fault:?}").into());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            if collection.security_tokens.is_empty() {
                return Err("MSA returned no security tokens".into());
            }
            for token in &collection.security_tokens {
                log::debug!(
                    "MSA issued a token for {}",
                    token.applies_to.endpoint_reference.address
                );
            }
            collection.security_tokens.remove(0).into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(token)) => {
            log::debug!(
                "MSA issued a token for {}",
                token.applies_to.endpoint_reference.address
            );
            (*token).into()
        }
        _ => return Err("Unexpected SOAP body in the token exchange".into()),
    };

    match token {
        Token::Compact(token) => Ok(token),
        Token::Legacy(_) => Err("MSA returned a legacy token where a compact one was expected".into()),
    }
}

/// An RPS ticket for `user.auth.xboxlive.com`, issued to one title's own MSA
/// app id rather than to a generic client.
///
/// Same shape and policy as the ticket `run()` already uses successfully -- only
/// the hosting app differs, and that is what carries the title's identity into
/// the token chain.
async fn rps_ticket_for_app(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    app_id: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // The token-broker form, with the app id in the scope. title.auth only
    // accepts this one: a plain user.auth ticket for the same hosting app is
    // issued happily by MSA and then rejected with 400.
    //
    // MSA will not always issue it, though: Asphalt Legends' 00000000441DF337
    // comes back with reqstatus 0x8004882c / errorstatus 0x80045c30 and no
    // token at all, while Minecraft's is fine. Asking without the "Silent"
    // constraint returns the identical pair, so it is the app-and-scope
    // combination being refused rather than the interaction mode -- which also
    // means no amount of consent UI would change it. Try the narrower
    // xboxlive.signin scope before giving up on a title claim.
    let attempts = [
        format!("scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0&clientid={app_id}"),
        format!("scope=xboxlive.signin&api-version=2.0&clientid={app_id}"),
    ];

    let mut last_err = None;
    for scope in attempts {
        let policies = [
            (scope.clone(), Some(soap::PolicyReference::token_broker())),
            ("http://Passport.NET/tb".to_string(), None),
        ];

        match crate::api::live::exchange_user_token(
            client,
            legacy.clone(),
            "USERNAME".to_string(),
            dev_token.clone(),
            None,
            Some("Silent".to_string()),
            app_id.to_string(),
            &policies,
        )
        .await
        {
            Ok(outcome) => return compact_token(outcome),
            Err(err) => {
                log::warn!("MSA refused {scope}: {err}");
                last_err = Some(err);
            }
        }
    }

    Err(last_err
        .map(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)
        .unwrap_or_else(|| "no scope was attempted".into()))
}

/// The full chain, including the title claim.
///
/// `app_id` is the title's `<MSAAppId>` from MicrosoftGame.Config (Minecraft
/// Bedrock: 0000000040159362). Without it the resulting token has only a `xui`
/// claim and services that key off the title -- PlayFab, the in-game
/// marketplace -- refuse it.
pub async fn run_with_title(
    client: &reqwest::Client,
    proof_key: &ProofKey,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
    app_id: &str,
    device_id: &str,
) -> Result<XstsResponse, Box<dyn std::error::Error + Send + Sync>> {
    let rps_ticket = rps_ticket_for_app(client, dev_token.clone(), legacy, app_id).await?;

    // The device's own MSA credential, exchanged for a ticket user.auth accepts.
    // This is what makes the device token count as a registered device: a
    // ProofOfPossession token, which proves only that we hold a key we made up
    // ourselves, gets a 403 out of title.auth.
    let device_rps = crate::api::live::exchange_device_token(
        client,
        dev_token,
        "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
        "scope=service::user.auth.xboxlive.com::MBI_SSL".to_owned(),
        Some(soap::PolicyReference::token_broker()),
    )
    .await?;
    let Token::Compact(device_rps) = Token::from(device_rps) else {
        return Err("MSA returned a legacy device token".into());
    };

    let device_token =
        device::authenticate_device_rps(client, proof_key, device_id, "Win32", &device_rps).await?;

    // One ticket, two tokens: user.auth says who is signed in, title.auth says
    // which title they are signed in through.
    log::debug!("RPS ticket starts {:?}", &rps_ticket[..rps_ticket.len().min(8)]);
    let title_token = title::authenticate_title(client, proof_key, &rps_ticket, &device_token).await?;
    let user_token = authenticate_xbox_user(client, rps_ticket).await?.token;

    Ok(auth::request_xsts_token_for_title(
        client,
        user_token,
        device_token,
        title_token,
        relying_party,
    )
    .await?)
}
