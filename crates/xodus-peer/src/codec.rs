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
//! - MESSAGE_RESPONSE = 1
//! - MESSAGE_ANCILLARY = 1 << 1 // payload is embedded in CMSG frame - requires recvmsg call to read

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};

use bitflags::bitflags;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, send, sendmsg,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};

const MAX_FDS: usize = 16;

bitflags! {
    pub struct PeerMessageFlags: u8 {
        const Response = 1 << 0;
        const Ancillary = 1 << 1;
    }
}

pub struct PeerMessage {
    pub seq: u16,
    pub flags: PeerMessageFlags,
    pub service: u8,
    pub message: u8,
    pub protobuf: Vec<u8>,
}

/// Receive PeerMessage from tokio UnixStream
pub async fn recv_message(
    stream: &mut tokio::net::UnixStream,
) -> Result<(PeerMessage, Vec<OwnedFd>), std::io::Error> {
    let mut header: [u8; 8] = [0; 8];
    stream.read_exact(&mut header).await?;
    let len = u16::from_le_bytes(header[0..2].try_into().unwrap());
    let mut fds = Vec::with_capacity(MAX_FDS);
    let mut peer_msg = PeerMessage {
        seq: u16::from_le_bytes(header[2..4].try_into().unwrap()),
        flags: PeerMessageFlags::from_bits_retain(header[4]),
        service: header[5],
        message: header[6],
        protobuf: vec![0; len as usize],
    };

    if peer_msg.flags.contains(PeerMessageFlags::Ancillary) {
        let bytes = stream
            .async_io(Interest::READABLE, || {
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
                let mut anc = RecvAncillaryBuffer::new(&mut space);

                let r = recvmsg(
                    &stream,
                    &mut [IoSliceMut::new(&mut peer_msg.protobuf)],
                    &mut anc,
                    RecvFlags::empty(),
                )?;
                for msg in anc.drain() {
                    if let RecvAncillaryMessage::ScmRights(fd) = msg {
                        fds.extend(fd);
                    }
                }
                if r.flags.contains(ReturnFlags::CTRUNC) {
                    return Err(std::io::Error::other(
                        "fds truncated (control buffer too small)",
                    ));
                }
                Ok(r.bytes)
            })
            .await?;
        if bytes == 0 {
            tracing::error!("Unable to receive a message - buffer empty");
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
    } else {
        stream.read_exact(&mut peer_msg.protobuf).await?;
    }

    Ok((peer_msg, fds))
}

/// Send PeerMessage to tokio UnixStream
/// ## Panics
/// If number of fds sent is bigger than 16
pub async fn send_message(
    stream: &mut tokio::net::UnixStream,
    message: PeerMessage,
    fds: &[BorrowedFd<'_>],
) -> Result<(), std::io::Error> {
    assert!(fds.len() <= MAX_FDS);

    let mut header: [u8; 8] = [0; 8];

    header[0..2].copy_from_slice(&(message.protobuf.len() as u16).to_le_bytes());
    header[2..4].copy_from_slice(&message.seq.to_le_bytes());
    header[4] = message.flags.bits();
    header[5] = message.service;
    header[6] = message.message;

    stream.write_all(&header).await?;

    if message.flags.contains(PeerMessageFlags::Ancillary) {
        stream
            .async_io(Interest::WRITABLE, || {
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
                let mut anc = SendAncillaryBuffer::new(&mut space);
                if !fds.is_empty() && !anc.push(SendAncillaryMessage::ScmRights(fds)) {
                    return Err(std::io::Error::other(
                        "ancillary buffer too small to send fds",
                    ));
                }
                let mut sent = sendmsg(
                    &stream,
                    &[IoSlice::new(&message.protobuf)],
                    &mut anc,
                    SendFlags::empty(),
                )?;
                while sent < message.protobuf.len() {
                    sent += send(&stream, &message.protobuf[sent..], SendFlags::empty())?;
                }
                Ok(())
            })
            .await?;
    } else {
        stream.write_all(&message.protobuf).await?;
    }

    Ok(())
}
