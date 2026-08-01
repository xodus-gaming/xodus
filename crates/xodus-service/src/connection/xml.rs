use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::{
    models::{
        live::ExchangeUserTokenOutcome,
        secrets::Token,
        soap,
        xgameruntime::xuser::{
            MSATokenRequest, MSATokenResponse, XstsTokenRequest, XstsTokenResponse,
        },
    },
    proto::xodus::XodusMessageType,
};

use crate::{XML_MAGIC, simple_context::SimpleContext};

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
        // An XSTS carrying the TITLE claim, for one relying party.
        //
        // This is minted here rather than by the caller because the three tokens
        // involved must all describe ONE device: the device token, the SISU title
        // token bound to it, and the user token. Pairing a title token with a
        // device token minted separately is rejected by xsts.auth with
        // `401 XSTS error="title_usage_by_device_exceeded"`, and only this side
        // holds the device identity, so only this side can keep them consistent.
        XodusMessageType::XstsTokenRequest => {
            let req = quick_xml::de::from_str::<XstsTokenRequest>(std::str::from_utf8(&buffer)?)?;
            let title_id: i64 = req.title_id.parse().unwrap_or(0);
            log::debug!(
                "XSTS request: rp={} client={} title={}",
                req.relying_party,
                req.client_id,
                title_id
            );

            // do_sisu returns the device token it was authorized with - use THAT.
            let (mut auth, sisu, device) =
                xodus::auth::do_sisu(&context.client, context.tokens(), &req.client_id, title_id)
                    .await
                    // do_sisu's error is a bare Box<dyn Error>; this handler must
                    // return one that is Send + Sync, so carry the text across.
                    .map_err(|e| std::io::Error::other(format!("sisu failed: {e}")))?;
            let xsts = auth
                .get_xsts_token(
                    Some(&device),
                    Some(&sisu.title_token),
                    Some(&sisu.user_token),
                    &req.relying_party,
                )
                .await?;
            let expiry = xsts.not_after.timestamp();
            log::debug!(
                "XSTS issued for {}: uhs {} ({} chars)",
                req.relying_party,
                xsts.userhash(),
                xsts.token.len()
            );
            let xuid = xsts
                .display_claims
                .as_ref()
                .and_then(|c| c.xui.first())
                .and_then(|x| x.get("xid"))
                .cloned()
                .unwrap_or_default();
            let payload = XstsTokenResponse {
                user_hash: xsts.userhash(),
                xuid,
                token: xsts.token,
                expiry,
            };
            Ok(quick_xml::se::to_string(&payload)?.as_bytes().to_vec())
        }
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
        _ => Err("Unimplemented".into()),
    }
}
