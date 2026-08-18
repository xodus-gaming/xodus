use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::models::xgameruntime::xuser::{
    MSATokenRequest, MSATokenResponse, XSTSTokenRequest, XSTSTokenResponse,
};
use xodus::proto::xodus::XodusMessageType;

use crate::XML_MAGIC;
use crate::simple_context::SimpleContext;

pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    log::debug!("Parsing XML");
    let message_type = socket.read_u16_le().await?;
    let message_size = socket.read_u16_le().await?;
    let mut buffer = vec![0; message_size as usize];
    log::debug!("Reading buffer {message_size}");
    socket.read_exact(&mut buffer).await?;
    log::debug!("Read buffer");
    let Ok(message_type) = XodusMessageType::try_from(message_type as i32) else {
        // Answering `UNKNOWN + 1` would hand the client a PONG for a message we
        // never understood, so reply as UNKNOWN instead and let it decide.
        log::error!("Unknown message type {message_type}");
        let data = super::encode_message(XML_MAGIC, XodusMessageType::Unknown as u16, vec![]);
        return socket.write_all(&data).await;
    };

    let out_buf = match parse_message(context, message_type, buffer).await {
        Ok(buf) => buf,
        Err(err) => {
            log::error!("Failed parsing message: {err}");
            vec![]
        }
    };

    let data = super::encode_message(XML_MAGIC, message_type as u16 + 1, out_buf);
    socket.write_all(&data).await
}

/// Trades the stored user credentials for an Xbox Live XSTS token. Returns the
/// ready-made Authorization header together with the identity it carries.
/// The proof key arrives as JSON text in the request; a malformed one is treated as
/// absent so the exchange still yields an unsigned token rather than failing outright.
fn parse_proof_key(raw: Option<&str>) -> Option<serde_json::Value> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    match serde_json::from_str(raw) {
        Ok(value) => Some(value),
        Err(err) => {
            log::warn!("Ignoring malformed ProofKey: {err}");
            None
        }
    }
}

async fn fetch_xbox_identity(
    context: &mut SimpleContext,
    client_id: &str,
    relying_party: &str,
    proof_key: Option<serde_json::Value>,
) -> Result<Option<(String, String, String, i64)>, Box<dyn std::error::Error + Send + Sync>> {
    let Token::Legacy(token) = context.tokens().get_user_sts_token()? else {
        return Ok(None);
    };
    let Some(device_token) = context.device_token.clone() else {
        return Ok(None);
    };

    let user_token = xodus::api::live::exchange_user_token(
        &context.client,
        token,
        "USERNAME".to_string(),
        device_token,
        None,
        Some("Silent".to_string()),
        client_id.to_string(),
        &[
            (
                // MBI_SSL is rejected for these stored credentials; the signin scope
                // yields a "d=" compact token, which is the RPS ticket form that
                // user.auth.xboxlive.com accepts.
                format!("scope=xboxlive.signin&api-version=2.0&clientid={client_id}"),
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
        log::error!("No token collection for the Xbox user authentication");
        return Ok(None);
    };

    // The collection carries the DA token last and the usable compact ticket first.
    if let Some(da) = collection.security_tokens.pop() {
        let address = da.applies_to.endpoint_reference.address.clone();
        let da: Token = da.into();
        let address = if let Token::Legacy(legacy) = &da {
            legacy.key_name.clone().unwrap_or(address)
        } else {
            address
        };
        if let Err(err) = context.tokens().save_user_token(address, da) {
            log::warn!("Failed to persist refreshed STS token: {err}");
        }
    }

    if collection.security_tokens.is_empty() {
        log::error!("Token collection held no usable ticket");
        return Ok(None);
    }
    let token: Token = collection.security_tokens.remove(0).into();
    let Token::Compact(rps_ticket) = token else {
        log::error!("Expected a compact RPS ticket, got {token:?}");
        return Ok(None);
    };

    let xbox_user =
        xodus::api::xbox::auth::authenticate_xbox_user(&context.client, rps_ticket, proof_key)
            .await?;
    let xsts = xodus::api::xbox::auth::request_xsts_token(
        &context.client,
        xbox_user.token.clone(),
        relying_party,
    )
    .await?;

    let expiry = xsts.not_after.timestamp();
    let xuid = xsts.xuid().unwrap_or_default().to_string();
    let gamertag = xsts.gamertag().unwrap_or_default().to_string();

    Ok(Some((
        xodus::api::xbox::auth::get_xsts_auth_header(xsts),
        xuid,
        gamertag,
        expiry,
    )))
}

pub async fn parse_message(
    context: &mut SimpleContext,
    message_type: XodusMessageType,
    buffer: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match message_type {
        XodusMessageType::Ping => Ok(buffer),
        XodusMessageType::MsaTokenRequest => {
            log::debug!("Raw buffer: {buffer:?}");
            let string_buf = std::str::from_utf8(&buffer)?;
            log::debug!("String buffer: {string_buf:?}");
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
                            log::warn!("Failed to persist refreshed STS token: {err}");
                        }
                    }
                    let token = collection.security_tokens.remove(0);
                    let expiry = chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)?;
                    let token: Token = token.into();
                    let Token::Compact(user_token) = token else {
                        return Ok(vec![]);
                    };
                    // Same trip also settles the Xbox Live identity, so the caller
                    // gets a real XUID and a usable Authorization header instead of
                    // having to invent them.
                    let relying_party = req
                        .relying_party
                        .as_deref()
                        .unwrap_or("http://xboxlive.com");
                    let identity = match fetch_xbox_identity(
                        context,
                        &req.client_id,
                        relying_party,
                        parse_proof_key(req.proof_key.as_deref()),
                    )
                    .await
                    {
                        Ok(identity) => identity,
                        Err(err) => {
                            log::warn!("Xbox identity unavailable: {err}");
                            None
                        }
                    };

                    let payload = MSATokenResponse {
                        token: user_token,
                        expiry: expiry.timestamp(),
                        xsts_token: identity
                            .as_ref()
                            .map(|(t, _, _, _)| t.clone())
                            .unwrap_or_default(),
                        xuid: identity
                            .as_ref()
                            .map(|(_, x, _, _)| x.clone())
                            .unwrap_or_default(),
                        gamertag: identity
                            .as_ref()
                            .map(|(_, _, g, _)| g.clone())
                            .unwrap_or_default(),
                        device_expiry: ms_device_rps_token.as_ref().map(|(_, r)| *r).unwrap_or(0),
                        device_rps: ms_device_rps_token
                            .map(|(t, _)| t)
                            .unwrap_or_else(String::new),
                    };
                    let payload = quick_xml::se::to_string(&payload)?;
                    Ok(payload.as_bytes().to_vec())
                }
                other => {
                    // Faults and single-token responses are both reachable here
                    // once the stored tokens go stale - an empty payload is how
                    // the rest of this path already reports "no token for you".
                    log::error!("User token exchange returned no token collection: {other:?}");
                    Ok(vec![])
                }
            }
        }
        XodusMessageType::XstsTokenRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            log::debug!("XSTS request: {string_buf:?}");
            let req = quick_xml::de::from_str::<XSTSTokenRequest>(string_buf)?;

            let Token::Legacy(token) = context.tokens().get_user_sts_token()? else {
                return Ok(vec![]);
            };

            // The Xbox user token needs a full-trust RPS ticket, the same one the
            // MSA path asks for with MSAFullTrust set.
            let device_token = context.device_token.as_ref().unwrap();
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
                        // MBI_SSL is rejected for these stored credentials; the signin
                        // scope yields a "d=" compact token, which is exactly the RPS
                        // ticket form user.auth.xboxlive.com accepts.
                        format!(
                            "scope=xboxlive.signin&api-version=2.0&clientid={}",
                            req.client_id
                        ),
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
                log::error!("No token collection for the Xbox user authentication: {user_token:?}");
                return Ok(vec![]);
            };

            // The collection carries the DA token last and the usable compact ticket
            // first, the same way the MSA path takes them apart.
            if let Some(da) = collection.security_tokens.pop() {
                let address = da.applies_to.endpoint_reference.address.clone();
                let da: Token = da.into();
                let address = if let Token::Legacy(legacy) = &da {
                    legacy.key_name.clone().unwrap_or(address)
                } else {
                    address
                };
                if let Err(err) = context.tokens().save_user_token(address, da) {
                    log::warn!("Failed to persist refreshed STS token: {err}");
                }
            }

            if collection.security_tokens.is_empty() {
                log::error!("Token collection held no usable ticket");
                return Ok(vec![]);
            }
            let token: Token = collection.security_tokens.remove(0).into();
            let Token::Compact(rps_ticket) = token else {
                log::error!("Expected a compact RPS ticket, got {token:?}");
                return Ok(vec![]);
            };

            let xbox_user = xodus::api::xbox::auth::authenticate_xbox_user(
                &context.client,
                rps_ticket,
                parse_proof_key(req.proof_key.as_deref()),
            )
            .await?;

            let xsts = xodus::api::xbox::auth::request_xsts_token(
                &context.client,
                xbox_user.token.clone(),
                &req.relying_party,
            )
            .await?;

            let payload = XSTSTokenResponse {
                expiry: xsts.not_after.timestamp(),
                xuid: xsts.xuid().unwrap_or_default().to_string(),
                gamertag: xsts.gamertag().unwrap_or_default().to_string(),
                token: xodus::api::xbox::auth::get_xsts_auth_header(xsts),
            };

            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        _ => Err("Unimplemented".into()),
    }
}
