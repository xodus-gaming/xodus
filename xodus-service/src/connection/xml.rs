use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::{
    models::{
        live::ExchangeUserTokenOutcome,
        secrets::Token,
        soap,
        xgameruntime::xuser::{MSATokenRequest, MSATokenResponse},
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
        XodusMessageType::MsaTokenRequest => {
            log::debug!("Raw buffer: {buffer:?}");
            let string_buf = std::str::from_utf8(&buffer)?;
            log::debug!("String buffer: {string_buf:?}");
            let req = quick_xml::de::from_str::<MSATokenRequest>(string_buf)?;
            let Token::Legacy(token) = context.tokens().get_user_sts_token()? else {
                return Ok(vec![]);
            };
            let scope = if req.msa_full_trust {
                "service::user.auth.xboxlive.com::MBI_SSL".to_owned()
            } else {
                "xboxlive.signin".to_owned()
            };
            let device_token = context.device_token.as_ref().unwrap();
            let user_token = xodus::api::live::exchange_user_token(
                &context.client,
                token.token,
                "USERNAME".to_string(),
                device_token.token.clone(),
                device_token.binary_secret.clone().unwrap(),
                None,
                Some("Silent".to_string()),
                "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
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
