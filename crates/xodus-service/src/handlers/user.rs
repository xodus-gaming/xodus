use crate::xodus_proto::XUserAddRequest;
use crate::xodus_proto::XUserAddResponse;
use std::sync::Arc;
use xodus::tokens::TokenManager;

// user specific handlers
pub async fn handle_xuseradd(req: XUserAddRequest, tokens: Arc<TokenManager>) -> XUserAddResponse {
    // stub
    XUserAddResponse {
        user_handle: 0x1337,
    }
}
