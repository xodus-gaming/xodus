// Built based on CikExtractor
// MIT License

// Copyright (c) 2022 LukeFZ

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::{collections::HashMap, io, io::Read};

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use base64::prelude::*;
use num_enum::TryFromPrimitive;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes, transmute};

// pub struct Block<'a> {
//     pub block_id: BlockId,
//     pub size: u32,
//     pub data: &'a [u8],
// }

#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
pub enum BlockId {
    UnkBlock0 = 0x14,
    DeviceLicenseExpirationTime = 0x1f,
    PollingTime = 0xd3,
    LicenseExpirationTime = 0x20,
    ClepSignState = 0x12d,
    LicenseDeviceId = 0xd2,
    UnkBlock1 = 0xd1,
    LicenseId = 0xcb,
    HardwareId = 0xd0,
    UnkBlock2 = 0xcf,
    UplinkKeyId = 0x18,
    UnkBlock3 = 0x0,
    UnkBlock4 = 0x12e,
    UnkBlock5 = 0xd5,
    PackageFullName = 0xce,
    LicenseInformation = 0xc9,
    PackedContentKeys = 0xca,
    EncryptedDeviceKey = 0x1,
    DeviceLicenseDeviceId = 0x2,
    LicenseEntryIds = 0xcd,
    LicensePolicies = 0xd4,
    KeyholderPublicSigningKey = 0xdc,
    KeyholderPolicies = 0xdd,
    KeyholderKeyLicenseId = 0xde,
    SignatureBlock = 0xcc,
}

#[derive(Default)]
pub struct SPLicense {
    pub license_id: uuid::Uuid,
    pub device_id: Vec<u8>,
    pub keyholder_key_license_id: uuid::Uuid,
    pub package_name: String,
    pub signature_origin: u16,
    pub signature_block: Vec<u8>,
    pub clep_sign_state: Vec<u8>,
    pub encrypted_device_key: Option<Box<EncryptedDeviceKey>>,
    pub content_keys: HashMap<uuid::Uuid, Vec<u8>>,
    pub keyholder_public_key: Vec<u8>,
    pub keyholder_policies: Vec<u8>,
    pub license_policies: Vec<u8>,
    pub entry_ids: Vec<[u8; 32]>,
    pub hardware_id: Vec<u8>,
    pub polling_time: u32,
    pub license_expiration_time: u32,
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct EncryptedDeviceKey {
    /// The total size of the encrypted device key, including the size field itself.
    /// Is always 4096.
    size: u16,
    version: u32,
    key_schedule: [u32; 57],
    _unknown1: [u8; 284],
    device_key: [u8; 16],
    _unknown2: [u8; 3562],
}

fn read_array<const N: usize, R: Read>(mut reader: R) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u32<R: Read>(reader: R) -> io::Result<u32> {
    read_array(reader).map(u32::from_le_bytes)
}

fn read_u16<R: Read>(reader: R) -> io::Result<u16> {
    read_array(reader).map(u16::from_le_bytes)
}

fn read_uuid<R: Read>(reader: R) -> io::Result<uuid::Uuid> {
    read_array(reader).map(uuid::Uuid::from_bytes_le)
}

fn read_vec<R: Read>(mut reader: R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("expected to read {expected} bytes but only {read} were read")]
    PayloadLengthMismatch { expected: usize, read: usize },
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("SPLicense decode error: {0}")]
    DecodeError(#[from] DecodeError),

    #[error("could not decode base64 string: {0}")]
    PayloadLengthMismatch(#[from] base64::DecodeError),
}

impl SPLicense {
    /// Merges a tag-length-value from the `reader` into this [`SPLicense`].
    ///
    /// Returns None if there are none TLVs left in the reader.
    fn merge_tlv<R: Read>(&mut self, mut reader: R) -> Result<Option<()>, DecodeError> {
        let mut buffer = [0u8; 4];

        // Doesn't use read_u32 to allow checking for EOF without error
        let block_id: Result<BlockId, _> = {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                return Ok(None);
            }

            // The read function does not guarantee that the buffer is completely filled,
            // read_exact must be called afterwards
            reader.read_exact(&mut buffer[bytes_read..])?;

            u32::from_le_bytes(buffer).try_into()
        };

        let size = read_u32(&mut reader)? as usize;

        // Create a new reader that limits the number of bytes that can be read to `size`
        let mut reader = reader.take(size as u64);

        match block_id {
            Ok(BlockId::LicenseId) => {
                self.license_id = read_uuid(&mut reader)?;
            }
            Ok(BlockId::DeviceLicenseDeviceId | BlockId::LicenseDeviceId) => {
                self.device_id = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::KeyholderKeyLicenseId) => {
                self.keyholder_key_license_id = read_uuid(&mut reader)?;
            }
            Ok(BlockId::EncryptedDeviceKey) => {
                let key: [u8; 4096] = read_array(&mut reader)?;
                self.encrypted_device_key = Some(Box::new(transmute!(key)));
            }
            Ok(BlockId::PackageFullName) => {
                let data = read_vec(&mut reader, size)?;
                let utf16: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                let mut s = String::from_utf16(&utf16).unwrap();
                if s.ends_with('\0') {
                    s.pop();
                }
                self.package_name = s;
            }
            Ok(BlockId::PackedContentKeys) => {
                let mut offset = 0;

                while offset < size {
                    let id_len = read_u16(&mut reader)? as usize;
                    let key_len = read_u16(&mut reader)? as usize;

                    let key_id = read_uuid(&mut reader)?;
                    let _unknown = read_vec(&mut reader, id_len - 16)?;
                    let key = read_vec(&mut reader, key_len)?;

                    self.content_keys.insert(key_id, key);
                    offset += 4 + id_len + key_len;
                }
            }
            Ok(BlockId::ClepSignState) => {
                self.clep_sign_state = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::SignatureBlock) => {
                let _unknown: [u8; 2] = read_array(&mut reader)?;
                self.signature_origin = read_u16(&mut reader)?;
                self.signature_block = read_vec(&mut reader, size - 4)?;
            }
            Ok(BlockId::PollingTime) => {
                self.polling_time = read_u32(&mut reader)?;
            }
            Ok(BlockId::LicenseExpirationTime | BlockId::DeviceLicenseExpirationTime) => {
                self.license_expiration_time = read_u32(&mut reader)?;
            }
            Ok(BlockId::HardwareId) => {
                self.hardware_id = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::LicenseInformation) => {
                let _unknown1: [u8; 2] = read_array(&mut reader)?;
                let _unknown2: [u8; 2] = read_array(&mut reader)?;
                let _unknown3: [u8; 4] = read_array(&mut reader)?;
                let _unknown4: [u8; 2] = read_array(&mut reader)?;
            }
            Ok(BlockId::LicenseEntryIds) => {
                let count = read_u16(&mut reader)?;

                for _ in 0..count {
                    let entry_id: [u8; 32] = read_array(&mut reader)?;
                    self.entry_ids.push(entry_id);
                }
            }
            Ok(BlockId::KeyholderPublicSigningKey) => {
                self.keyholder_public_key = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::KeyholderPolicies) => {
                self.keyholder_policies = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::LicensePolicies) => {
                self.license_policies = read_vec(&mut reader, size)?;
            }
            Ok(
                BlockId::UnkBlock0
                | BlockId::UnkBlock1
                | BlockId::UnkBlock2
                | BlockId::UnkBlock3
                | BlockId::UnkBlock4
                | BlockId::UnkBlock5,
            ) => {
                let _unknown = read_vec(&mut reader, size)?;
            }
            _ => {
                let _unknown = read_vec(&mut reader, size)?;
            }
        }

        // Ensure the number of bytes read is exactly `size`
        if reader.limit() != 0 {
            return Err(DecodeError::PayloadLengthMismatch {
                expected: size,
                read: size - reader.limit() as usize,
            });
        }

        Ok(Some(()))
    }

    pub fn decode<R: Read>(mut reader: R) -> Result<Self, DecodeError> {
        // Decode the header
        let _header: [u8; 4] = read_array(&mut reader)?;
        let _offset = read_u32(&mut reader)?;

        // Create an empty license
        let mut license = Self::default();

        // Merge fields from the stream into the license until EOF
        while let Some(()) = license.merge_tlv(&mut reader)? {}

        Ok(license)
    }

    pub fn parse_base64(string: String) -> Result<SPLicense, ParseError> {
        let data = BASE64_STANDARD.decode(string)?;
        Ok(SPLicense::decode(&*data)?)
    }
}

impl EncryptedDeviceKey {
    fn decryption_key(&self) -> [u8; 16] {
        let mut key = [0u32; 4];

        key[0] = self.key_schedule[46] ^ self.key_schedule[56] ^ 0xE20DF371 ^ 0xCCB22FE6;
        key[1] = self.key_schedule[36] ^ self.key_schedule[47] ^ 0xDF080E39;
        key[2] = self.key_schedule[40] ^ self.key_schedule[51] ^ 0x6D09B2F5 ^ 0x2AE17AB9;
        key[3] = self.key_schedule[30] ^ self.key_schedule[41] ^ 0x37288CEC;

        transmute!(key)
    }

    pub fn derive_device_key(&self) -> [u8; 16] {
        assert!(self.version == 4);

        let decryption_key = self.decryption_key();
        let aes = aes::Aes128::new(&decryption_key.into());

        let mut device_key = self.device_key.into();
        aes.decrypt_block(&mut device_key);

        // Sanity check: the decrypted device key must be equal to the decryption key
        assert_eq!(device_key, decryption_key);

        device_key.0
    }
}

pub fn unpack_key(
    key: &[u8; 16],
    content_key: Vec<u8>,
) -> Result<Vec<u8>, aes_keywrap::KeywrapError> {
    let packer = aes_keywrap::Aes128KeyWrapAligned::new(key);
    packer.decapsulate(&content_key)
}
