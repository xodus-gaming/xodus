pub struct XodusIPCPacket {
    pub magic: u32,
    pub message_type: u16,
    pub message_size: u16,
    pub buffer: Vec<u8>,
}
