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

#[cfg(test)]
mod test {
    use super::*;

    /// Frame: u32 LE magic, u16 LE message type, u16 LE payload size, payload.
    #[test]
    fn encode_message_frames_payload() {
        let payload = b"<UserInfoResponse/>".to_vec();
        let frame = encode_message(crate::XML_MAGIC, 8, payload.clone());
        assert_eq!(&frame[..4], b"XSDX");
        assert_eq!(&frame[4..6], &8u16.to_le_bytes());
        assert_eq!(&frame[6..8], &(payload.len() as u16).to_le_bytes());
        assert_eq!(&frame[8..], &payload[..]);
        assert_eq!(frame.len(), 8 + payload.len());

        let empty = encode_message(crate::PROTO_MAGIC, 2, vec![]);
        assert_eq!(empty, [b"PSDX".as_slice(), &[2, 0, 0, 0]].concat());
    }
}
