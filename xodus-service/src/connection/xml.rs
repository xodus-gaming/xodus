use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::{
    models::{
        live::ExchangeUserTokenOutcome,
        secrets::Token,
        soap,
        xgameruntime::xuser::{
            MSATokenRequest, MSATokenResponse, TitleSignatureAlgorithms, TitleSignaturePolicy,
            TitleSignatureTypes, XSTSTokenRequest, XSTSTokenResponse,
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
        XodusMessageType::XstsTokenRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<XSTSTokenRequest>(string_buf)?;
            log::debug!("Getting title config {}", req.url);
            let (title_cfg, policy) = context
                .get_title_config(&req.url)
                .await
                .ok_or::<String>("Failed to get title cfg".into())?;
            log::debug!("Got title config for {}", title_cfg.host);
            let relying_party = title_cfg
                .relying_party
                .unwrap_or("http://xboxlive.com".to_string());
            log::debug!("Getting token {relying_party}");
            let user_token = context
                .get_token(&relying_party)
                .await
                .ok_or::<String>("Failed to get user cfg".into())?;

            let payload = XSTSTokenResponse {
                token: format!(
                    "XBL3.0 x={};{}",
                    user_token.user_hash().unwrap(),
                    user_token.token
                ),
                expiry: user_token.not_after.timestamp(),
                relying_party,
                signature_policy: TitleSignaturePolicy {
                    algorithms: TitleSignatureAlgorithms {
                        algorithm: policy.supported_algorithms,
                    },
                    signature_types: TitleSignatureTypes {
                        signature: policy.supported_signature_types,
                    },
                    max_body_bytes: policy.max_body_bytes,
                },
            };

            let payload = quick_xml::se::to_string(&payload)?;
            Ok(payload.as_bytes().to_vec())
        }
        XodusMessageType::MsaTokenRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<MSATokenRequest>(string_buf)?;
            let Token::Legacy(token) = crate::user::get_token("http://Passport.NET/STS").unwrap()
            else {
                return Ok(vec![]);
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
                &[(
                    format!("scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0&clientid={}", req.client_id),
                    Some(soap::PolicyReference::token_broker()),
                ), ("http://Passport.NET/tb".to_string(), None)],
            )
            .await?;

            match user_token {
                ExchangeUserTokenOutcome::Issued(
                    soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
                ) => {
                    if let Some(sts) = collection.security_tokens.pop() {
                        log::debug!("FIXME: Store new STS token");
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
