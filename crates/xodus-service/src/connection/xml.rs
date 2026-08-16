use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::models::xgameruntime::xuser::{
    MSATokenRequest, MSATokenResponse, XstsTokenRequest, XstsTokenResponse,
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
    let message_type = XodusMessageType::try_from(message_type as i32).unwrap_or_default();

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
        XodusMessageType::XstsTokenRequest => {
            let req = quick_xml::de::from_str::<XstsTokenRequest>(std::str::from_utf8(&buffer)?)?;
            log::debug!(
                "XSTS token requested for {} (force_refresh {})",
                req.relying_party,
                req.force_refresh
            );

            // XSTS tokens are good for hours; minting one per HTTP request would
            // put a SOAP round trip in front of every call the title makes.
            // Ask Xbox what this URL's relying party actually is. Falling back
            // to the caller's guess keeps working for the parties named after
            // their own host, which is all the table would tell us anyway.
            let relying_party = match req.url.is_empty() {
                true => req.relying_party.clone(),
                false => xodus::api::xbox::title::relying_party_for_url(&context.client, &req.url)
                    .await
                    .unwrap_or_else(|| req.relying_party.clone()),
            };

            // The app id is part of the identity of the token, not just of the
            // request: a token minted for one title is not usable by another.
            let cache_key = if req.app_id.is_empty() {
                relying_party.clone()
            } else {
                format!("{relying_party}#{}", req.app_id)
            };
            let cached = if req.force_refresh {
                None
            } else {
                context.tokens().get_cached_xsts(&cache_key)
            };

            let xsts = match cached {
                Some(xsts) => {
                    log::debug!("Serving {cache_key} from cache");
                    xsts
                }
                None => {
                    let Token::Legacy(user_sts) = context.tokens().get_user_sts_token()? else {
                        return Err("User STS token isn't legacy".into());
                    };
                    let device_token = context
                        .device_token
                        .as_ref()
                        .ok_or("No device token; the service has no device identity")?;

                    let xsts = if req.app_id.is_empty() {
                        // No title identity to offer; good enough for
                        // http://xboxlive.com, which is what sign-in needs.
                        xodus::api::xbox::run(
                            &context.client,
                            device_token.clone(),
                            user_sts,
                            &relying_party,
                        )
                        .await?
                    } else {
                        let proof_key = context.tokens().get_or_create_proof_key()?;
                        let device_id = context.tokens().get_or_create_device_id()?;

                        match xodus::api::xbox::run_with_title(
                            &context.client,
                            &proof_key,
                            device_token.clone(),
                            user_sts.clone(),
                            &relying_party,
                            &req.app_id,
                            &device_id,
                        )
                        .await
                        {
                            Ok(xsts) => xsts,
                            Err(err) => {
                                // MSA will not always issue a silent ticket for
                                // a title's own app id -- Asphalt Legends'
                                // 00000000441DF337 comes back with reqstatus
                                // 0x8004882c and no token at all. A token
                                // without the title claim still carries the
                                // user, which is enough for relying parties
                                // that only need to know who is signed in, so
                                // offer that rather than nothing.
                                log::warn!(
                                    "No title-bound token for app {} ({err}); \
                                     falling back to a user-only token",
                                    req.app_id
                                );
                                xodus::api::xbox::run(
                                    &context.client,
                                    device_token.clone(),
                                    user_sts,
                                    &relying_party,
                                )
                                .await?
                            }
                        }
                    };
                    context.tokens().cache_xsts(&cache_key, &xsts);
                    xsts
                }
            };

            // Whether the token carries profile claims decides what the title
            // shows: without them XUserGetGamertag falls back to a placeholder,
            // and the player sees a stranger's name on their own save.
            log::debug!(
                "XSTS token for {relying_party}: xuid {:?}, gamertag {:?}",
                xsts.xuid(),
                xsts.gamertag()
            );

            let payload = XstsTokenResponse {
                expiry: xsts.not_after.timestamp(),
                xuid: xsts.xuid().unwrap_or_default().to_string(),
                gamertag: xsts.gamertag().unwrap_or_default().to_string(),
                signature: String::new(),
                token: xodus::api::xbox::get_xsts_auth_header(xsts),
            };
            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        _ => Err("Unimplemented".into()),
    }
}
