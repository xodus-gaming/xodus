pub mod proto;
pub mod router;
pub mod xml;

pub fn encode_message(magic: u32, msg_type: u16, message_buffer: Vec<u8>) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(8);
    let size = message_buffer.len() as u16;
    buffer.extend(magic.to_le_bytes());
    buffer.extend(msg_type.to_le_bytes());
    buffer.extend(size.to_le_bytes());
    buffer.extend(message_buffer);

    buffer
}
