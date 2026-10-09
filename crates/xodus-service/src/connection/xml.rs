use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::api::xbox::signing;
use xodus::api::xbox::title::{self, ResolvedEndpoint};
use xodus::auth::TitleSession;
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::models::xgameruntime::xuser::{
    MSATokenRequest, MSATokenResponse, TokenAndSignatureRequest, TokenAndSignatureResponse,
};
use xodus::proto::xodus::XodusMessageType;

use crate::XML_MAGIC;
use crate::simple_context::SimpleContext;

pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    tracing::debug!("Parsing XML");
    let message_type = socket.read_u16_le().await?;
    let message_size = socket.read_u16_le().await?;
    let mut buffer = vec![0; message_size as usize];
    tracing::debug!("Reading buffer {message_size}");
    socket.read_exact(&mut buffer).await?;
    tracing::debug!("Read buffer");
    let message_type = XodusMessageType::try_from(message_type as i32).unwrap_or_default();

    let out_buf = match parse_message(context, message_type, buffer).await {
        Ok(buf) => buf,
        Err(err) => {
            tracing::error!("Failed parsing message: {err}");
            vec![]
        }
    };

    let data = super::encode_message(XML_MAGIC, message_type as u16 + 1, out_buf);
    socket.write_all(&data).await
}

pub async fn parse_message(
    context: &mut SimpleContext,
    message_type: XodusMessageType,
    buffer: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match message_type {
        XodusMessageType::Ping => Ok(buffer),
        XodusMessageType::MsaTokenRequest => {
            tracing::debug!("Raw buffer: {buffer:?}");
            let string_buf = std::str::from_utf8(&buffer)?;
            tracing::debug!("String buffer: {string_buf:?}");
            let req = quick_xml::de::from_str::<MSATokenRequest>(string_buf)?;
            let Token::Legacy(token) = context.tokens().get_user_sts_token()? else {
                return Ok(vec![]);
            };
            let scope = if req.msa_full_trust {
                "service::user.auth.xboxlive.com::MBI_SSL"
            } else {
                "xboxlive.signin"
            };
            let device_token = context.device_token.as_ref().unwrap();
            let device_token_resp = xodus::api::live::exchange_device_token(
                &context.client,
                device_token.clone(),
                "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
                "scope=service::user.auth.xboxlive.com::MBI_SSL".to_owned(),
                Some(soap::PolicyReference::token_broker()),
            )
            .await;

            let ms_device_rps_token = if let Some((Token::Compact(ms_device_token), Ok(lifetime))) =
                device_token_resp.ok().map(|t| {
                    let expiry = chrono::DateTime::parse_from_rfc3339(&t.lifetime.expires);
                    (t.into(), expiry)
                }) {
                Some((ms_device_token, lifetime.timestamp()))
            } else {
                None
            };

            let user_token = xodus::api::live::exchange_user_token(
                &context.client,
                token,
                "USERNAME".to_string(),
                device_token.clone(),
                None,
                Some("Silent".to_string()),
                req.client_id.clone(),
                &[
                    (
                        format!("scope={scope}&api-version=2.0&clientid={}", req.client_id),
                        Some(soap::PolicyReference::token_broker()),
                    ),
                    ("http://Passport.NET/tb".to_string(), None),
                ],
            )
            .await?;

            match user_token {
                ExchangeUserTokenOutcome::Issued(
                    soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
                ) => {
                    if let Some(sts) = collection.security_tokens.pop() {
                        let address = sts.applies_to.endpoint_reference.address.clone();
                        let sts: Token = sts.into();
                        let address = if let Token::Legacy(legacy) = &sts {
                            legacy.key_name.clone().unwrap_or(address)
                        } else {
                            address
                        };
                        if let Err(err) = context.tokens().save_user_token(address, sts) {
                            tracing::warn!("Failed to persist refreshed STS token: {err}");
                        }
                    }
                    let token = collection.security_tokens.remove(0);
                    let expiry = chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)?;
                    let token: Token = token.into();
                    let Token::Compact(user_token) = token else {
                        return Ok(vec![]);
                    };
                    let payload = MSATokenResponse {
                        token: user_token,
                        expiry: expiry.timestamp(),
                        device_expiry: ms_device_rps_token.as_ref().map(|(_, r)| *r).unwrap_or(0),
                        device_rps: ms_device_rps_token
                            .map(|(t, _)| t)
                            .unwrap_or_else(String::new),
                    };
                    let payload = quick_xml::se::to_string(&payload)?;
                    Ok(payload.as_bytes().to_vec())
                }
                _ => todo!("Error handling sill sucks"),
            }
        }
        XodusMessageType::TokenAndSignatureRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let response = match quick_xml::de::from_str::<TokenAndSignatureRequest>(string_buf) {
                Ok(req) => token_and_signature(context, req).await,
                Err(err) => TokenAndSignatureResponse::error(
                    E_INVALIDARG,
                    format!("malformed TokenAndSignatureRequest: {err}"),
                ),
            };
            Ok(quick_xml::se::to_string(&response)?.into_bytes())
        }
        _ => Err("Unimplemented".into()),
    }
}

const E_INVALIDARG: u32 = 0x8007_0057;
const E_FAIL: u32 = 0x8000_4005;
/// No user is signed in to xodus.
const E_GAMEUSER_SIGNED_OUT: u32 = 0x8924_5101;
/// Xbox Live refused the sign-in (consent, ban, missing Game Pass, ...): user action needed.
const E_GAMEUSER_RESOLVE_USER_ISSUE_REQUIRED: u32 = 0x8924_5102;

/// `XUserGetTokenAndSignatureAsync`: XSTS token for the request's relying party plus the
/// request signature. With `ClientId` + `TitleId` the token is title-bound (sisu flow) and
/// signed with that session's proof key; without them only an unsigned user token is possible.
async fn token_and_signature(
    context: &mut SimpleContext,
    req: TokenAndSignatureRequest,
) -> TokenAndSignatureResponse {
    let Ok(url) = reqwest::Url::parse(&req.url) else {
        return TokenAndSignatureResponse::error(E_INVALIDARG, "Url is not a valid URL");
    };
    let method = req
        .method
        .as_deref()
        .unwrap_or("GET")
        .trim()
        .to_ascii_uppercase();
    let body = match req.body.as_deref() {
        Some(b) if !b.trim().is_empty() => {
            match base64::engine::general_purpose::STANDARD.decode(b.trim()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return TokenAndSignatureResponse::error(
                        E_INVALIDARG,
                        "Body is not valid base64",
                    );
                }
            }
        }
        _ => Vec::new(),
    };

    if context.tokens().get_user_sts_token().is_err() {
        return TokenAndSignatureResponse::error(E_GAMEUSER_SIGNED_OUT, "no user is signed in");
    }

    let resolved = resolve_endpoint(context, url.as_str())
        .await
        .unwrap_or(ResolvedEndpoint {
            relying_party: title::DEFAULT_RELYING_PARTY.to_string(),
            signature_policy: None,
        });
    tracing::debug!(
        "token request for {} -> relying party {}, signed: {}",
        url,
        resolved.relying_party,
        resolved.signature_policy.is_some()
    );

    match (req.client_id.as_deref(), req.title_id) {
        (Some(client_id), Some(title_id)) if !client_id.trim().is_empty() => {
            title_bound_token(
                context,
                client_id.trim(),
                title_id,
                &resolved,
                &url,
                &method,
                &body,
                req.force_refresh,
            )
            .await
        }
        _ => user_only_token(context, &resolved, req.force_refresh).await,
    }
}

/// Relying party and signature policy for a URL from the (cached) title endpoint table.
async fn resolve_endpoint(context: &SimpleContext, url: &str) -> Option<ResolvedEndpoint> {
    let mut table = context.shared.endpoints.lock().await;
    if table.is_none() {
        match title::get_title_management(&context.client).await {
            Ok(t) => *table = Some(t),
            Err(err) => tracing::warn!("could not fetch the title endpoint table: {err}"),
        }
    }
    table
        .as_ref()
        .and_then(|t| title::resolve_relying_party(url, t))
}

#[allow(clippy::too_many_arguments)]
async fn title_bound_token(
    context: &mut SimpleContext,
    client_id: &str,
    title_id: u32,
    resolved: &ResolvedEndpoint,
    url: &reqwest::Url,
    method: &str,
    body: &[u8],
    force_refresh: bool,
) -> TokenAndSignatureResponse {
    let session_key = format!("{client_id}:{title_id}");
    let xsts_key = format!("{session_key}:{}", resolved.relying_party);

    let mut sessions = context.shared.sessions.lock().await;
    if !sessions
        .get(&session_key)
        .is_some_and(TitleSession::is_valid)
    {
        tracing::info!("establishing Xbox Live session for title {title_id}");
        let session = TitleSession::establish(
            &context.client,
            context.tokens(),
            client_id,
            i64::from(title_id),
        )
        .await
        .map_err(|err| err.to_string());
        match session {
            Ok(s) => {
                sessions.insert(session_key.clone(), s);
            }
            Err(err) => {
                tracing::warn!("Xbox Live sign-in for title {title_id} failed: {err}");
                return TokenAndSignatureResponse::error(
                    E_GAMEUSER_RESOLVE_USER_ISSUE_REQUIRED,
                    format!("Xbox Live sign-in failed: {err}"),
                );
            }
        }
    }
    let session = sessions
        .get_mut(&session_key)
        .expect("session inserted above");

    let mut cache = context.shared.xsts.lock().await;
    let cached = if force_refresh {
        None
    } else {
        cache
            .get(&xsts_key)
            .filter(|t| t.check_validity().is_ok())
            .cloned()
    };
    let xsts = match cached {
        Some(t) => t,
        None => match session.get_xsts_token(&resolved.relying_party).await {
            Ok(t) => {
                cache.insert(xsts_key, t.clone());
                t
            }
            Err(err) => {
                tracing::warn!("XSTS request for {} failed: {err}", resolved.relying_party);
                return TokenAndSignatureResponse::error(
                    E_FAIL,
                    format!("XSTS token request failed: {err}"),
                );
            }
        },
    };
    if xsts.display_claims.is_none() {
        return TokenAndSignatureResponse::error(E_FAIL, "XSTS token without display claims");
    }
    let authorization = xsts.authorization_header_value();

    let signature = match &resolved.signature_policy {
        Some(policy) => match signing::sign_request(
            &session.proof_key(),
            i32::from(policy.version),
            policy.max_body_bytes as usize,
            chrono::Utc::now(),
            method,
            &signing::path_and_query(url),
            &authorization,
            body,
        ) {
            Ok(s) => s,
            Err(err) => {
                return TokenAndSignatureResponse::error(
                    E_FAIL,
                    format!("request signing failed: {err}"),
                );
            }
        },
        None => String::new(),
    };

    TokenAndSignatureResponse {
        token: Some(authorization),
        signature: Some(signature),
        expiry: Some(xsts.not_after.timestamp()),
        ..Default::default()
    }
}

/// Fallback without title identity: user-only XSTS token, never signed.
async fn user_only_token(
    context: &mut SimpleContext,
    resolved: &ResolvedEndpoint,
    force_refresh: bool,
) -> TokenAndSignatureResponse {
    let relying_party = resolved.relying_party.as_str();
    let cached = if force_refresh {
        None
    } else {
        context
            .tokens()
            .get_cached_xsts(relying_party)
            .filter(|t| t.not_after > chrono::Utc::now())
    };
    let xsts = match cached {
        Some(t) => t,
        None => {
            let (Some(device_token), Ok(Token::Legacy(user_token))) = (
                context.device_token.clone(),
                context.tokens().get_user_sts_token(),
            ) else {
                return TokenAndSignatureResponse::error(
                    E_GAMEUSER_SIGNED_OUT,
                    "no usable MSA tokens",
                );
            };
            match xodus::api::xbox::xsts_user_only(
                &context.client,
                device_token,
                user_token,
                relying_party,
            )
            .await
            {
                Ok(t) => {
                    context.tokens().cache_xsts(relying_party, &t);
                    t
                }
                Err(err) => {
                    tracing::warn!("user-only XSTS request for {relying_party} failed: {err}");
                    return TokenAndSignatureResponse::error(
                        E_GAMEUSER_RESOLVE_USER_ISSUE_REQUIRED,
                        format!("XSTS token request failed: {err}"),
                    );
                }
            }
        }
    };
    let Some(uhs) = xsts.user_hash().map(str::to_owned) else {
        return TokenAndSignatureResponse::error(E_FAIL, "XSTS token without user hash");
    };

    TokenAndSignatureResponse {
        token: Some(format!("XBL3.0 x={uhs};{}", xsts.token)),
        signature: Some(String::new()),
        expiry: Some(xsts.not_after.timestamp()),
        message: Some("unsigned: no ClientId/TitleId in request".to_string()),
        ..Default::default()
    }
}
