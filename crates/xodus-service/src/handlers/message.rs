use crate::simple_context::SimpleContext;
use crate::xodus_proto::{
    Hresult, XodusRequest, XodusResponse, xodus_request::Payload as ReqType,
    xodus_response::Payload as ResType,
};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Generic message handler - read from socket and redirect message to specific handler.
pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    // header
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;

    // message
    let length = u32::from_be_bytes(len_buf) as usize;
    let mut payload_buf = vec![0u8; length];
    socket.read_exact(&mut payload_buf).await?;

    // decode request
    let request = XodusRequest::decode(payload_buf.as_slice())?;
    let request_id = request.request_id;
    let payload = request.payload;

    let response_payload = match payload {
        Some(ReqType::XuserAddReq(req)) => {
            let response =
                crate::handlers::user::handle_xuseradd(req, context.tokens().clone()).await;
            ResType::XuserAddRes(response)
        }
        _ => todo!("Error handling sill sucks"),
    };

    // respond here
    Ok(())
}
