//! Payload encoding, decoding utilities
//! 
//! ## Format of the payload
//! |  name   | length | comment |
//! | ------- | ------ | ------- |
//! | length  | u16    | size of the payload |
//! | seq     | u16    | sequence number of the message, response will have the same number |
//! | flags   | u8     | See [Flags](#flags) |
//! | service id | u8  | number identifying a service |
//! | message type | u8| type of the message within service |
//! | reserved | u8     | currently unused padding byte |
//! | payload | [u8; length] | protobuf encoded payload described by message type |
//! 
//! ## Flags
//! ```
//! enum MessageFlags {
//!     MESSAGE_RESPONSE = 1 << 1
//!     MESSAGE_ANCILLARY = 1 << 2 // payload is embedded in CMSG frame - requires recvmsg call to read
//! }
//! ```

use tokio::io::{AsyncRead, AsyncReadExt};

