use std::{collections::HashMap, pin::Pin};

use tower::{BoxError, Service};

pub mod auth;
pub mod download;

pub struct Router {}

impl Service<xodus_peer::codec::PeerMessage> for Router {
    type Response = xodus_peer::codec::PeerMessage;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<xodus_peer::codec::PeerMessage, BoxError>>>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: xodus_peer::codec::PeerMessage) -> Self::Future {
        todo!()
    }
}
