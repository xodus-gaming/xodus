use crate::simple_context::SimpleContext;

pub async fn handle(
    _socket: &mut tokio::net::UnixStream,
    _context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    unimplemented!("Protobuf path isnt implemented yet");
}
