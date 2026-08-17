use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::proto::xodus::XodusMessageType;

use crate::PROTO_MAGIC;
use crate::simple_context::SimpleContext;

pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    _context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    // No handlers on this path yet, but a client speaking protobuf shouldn't take
    // the worker down with it. Drain the frame so the stream stays aligned for the
    // next message - bailing out early would leave the payload to be read as the
    // following message's magic - then answer as UNKNOWN, matching how the XML
    // path reports a message it has no handler for.
    let message_type = socket.read_u16_le().await?;
    let message_size = socket.read_u16_le().await?;
    let mut buffer = vec![0; message_size as usize];
    socket.read_exact(&mut buffer).await?;

    log::error!("Protobuf path isnt implemented yet, dropping message type {message_type}");

    let data = super::encode_message(PROTO_MAGIC, XodusMessageType::Unknown as u16, vec![]);
    socket.write_all(&data).await
}
