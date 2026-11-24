use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::models::xgameruntime::xuser::MSATokenRequest;
use xodus::proto::xodus::XodusMessageType;

use super::msa::{ServiceError, error_body, handle_msa_token};
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
            let req = match std::str::from_utf8(&buffer)
                .map_err(|e| e.to_string())
                .and_then(|s| quick_xml::de::from_str::<MSATokenRequest>(s).map_err(|e| e.to_string()))
            {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!("Invalid MsaTokenRequest: {e}");
                    return Ok(error_body(&ServiceError::Other(e)));
                }
            };
            Ok(handle_msa_token(&req, context).await)
        }
        _ => Err("Unimplemented".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use xodus::models::secrets::LegacyToken;
    use xodus::models::soap::Timestamp;
    use xodus::tokens::manager::TokenManager;

    #[tokio::test]
    async fn exchange_msa_parse_message_bad_input() {
        let tok = LegacyToken {
            key_name: None,
            token: String::new(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp { id: None, created: String::new(), expires: String::new() },
        };
        let mut ctx = SimpleContext::new(tok, Arc::new(TokenManager::with_memory()));
        for input in [&b""[..], b"\xff", b"<MSATokenRequest>"] {
            let out = parse_message(&mut ctx, XodusMessageType::MsaTokenRequest, input.to_vec())
                .await
                .unwrap();
            assert!(String::from_utf8(out).unwrap().contains("<Error>0x80004005</Error>"));
        }
    }
}
