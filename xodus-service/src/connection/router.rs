use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use xodus::models::secrets::LegacyToken;

use crate::simple_context::SimpleContext;

pub async fn route(
    (mut socket, _address): (tokio::net::UnixStream, tokio::net::unix::SocketAddr),
    token: CancellationToken,
    device_token: LegacyToken,
) {
    let mut context = SimpleContext::new(device_token);
    loop {
        let mut read_magic = [0; 4];
        if token.is_cancelled() {
            return;
        }
        let read = socket.read_exact(&mut read_magic).await;
        if let Err(err) = read {
            log::error!("Failed to read magic: {err:?}");
            return;
        }

        let magic = u32::from_le_bytes(read_magic);
        let res = match magic {
            crate::XML_MAGIC => super::xml::handle(&mut socket, &mut context).await,
            crate::PROTO_MAGIC => super::proto::handle(&mut socket, &mut context).await,
            _ => {
                log::error!("Unknown magic");
                return;
            }
        };

        if let Err(err) = res {
            log::error!("There was an error handling the message: {err}");
        }
    }
}
