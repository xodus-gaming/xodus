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

use std::collections::HashMap;
use std::io;
use std::io::Read;
use std::ops::Deref;

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
    pub clep_sign_state: Option<Box<ClepSignState>>,
    pub encrypted_device_key: Option<Box<EncryptedDeviceKey>>,
    pub content_keys: HashMap<uuid::Uuid, PackedContentKey>,
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
    key_schedule: [u32; 58],
    _unknown1: [u8; 280],
    device_key: [u8; 16],
    _unknown2: [u8; 3562],
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct ClepSignState {
    version: u32,
    key_data: [u8; 544],
    key_schedule: [u32; 58],
    _unknown: [u8; 3316],
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct ClepHmacState {
    version: u32,
    key_data: [u8; 48],
    key_schedule: [u32; 58],
    _unknown: [u8; 3812],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceKey([u8; 16]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BCryptRsaBlock([u8; 544]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HmacBinarySecret([u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PackedContentKey([u8; 40]);
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ContentKey([u8; 32]);

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

fn decryption_key(key_schedule: [u32; 58]) -> [u8; 16] {
    let mut key = [0u32; 4];

    key[0] = key_schedule[46] ^ key_schedule[56] ^ 0xE20DF371 ^ 0xCCB22FE6;
    key[1] = key_schedule[36] ^ key_schedule[47] ^ 0xDF080E39;
    key[2] = key_schedule[40] ^ key_schedule[51] ^ 0x6D09B2F5 ^ 0x2AE17AB9;
    key[3] = key_schedule[30] ^ key_schedule[41] ^ 0x37288CEC;

    transmute!(key)
}

/// Decrypts `data` with AES-128-CBC (zero IV) using the key derived from `key_schedule`.
fn decrypt_cbc_zero_iv<const N: usize>(key_schedule: [u32; 58], data: &[u8; N]) -> [u8; N] {
    const { assert!(N.is_multiple_of(16)) }
    let key = decryption_key(key_schedule);
    let aes = aes::Aes128::new(&key.into());

    let mut out = [0u8; N];
    let mut prev: u128 = 0;
    let data_chunks = data.as_chunks::<16>().0;
    let output_chunks = out.as_chunks_mut::<16>().0;
    for (chunk_in, chunk_out) in data_chunks.iter().zip(output_chunks) {
        let block: [u8; 16] = *chunk_in;
        let next = u128::from_le_bytes(block);

        let mut decrypted = block.into();
        aes.decrypt_block(&mut decrypted);
        let decrypted = decrypted.0;
        let decrypted = u128::from_le_bytes(decrypted);

        chunk_out.copy_from_slice((decrypted ^ prev).as_bytes());
        prev = next;
    }
    out
}

#[derive(Debug, Error)]
pub enum SPLicenseDecodeError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("expected to read {expected} bytes but only {read} were read")]
    PayloadLengthMismatch { expected: usize, read: usize },

    #[error("PackedContentKey id_len {id_len} is less than 16")]
    InvalidPackedContentKeyIdLength { id_len: usize },

    #[error("invalid UTF-16 package name: {0}")]
    InvalidPackageNameUtf16(#[from] std::string::FromUtf16Error),
}

#[derive(Debug, Error)]
pub enum SPLicenseParseError {
    #[error("SPLicense decode error: {0}")]
    DecodeError(#[from] SPLicenseDecodeError),

    #[error("could not decode base64 string: {0}")]
    PayloadLengthMismatch(#[from] base64::DecodeError),
}

impl SPLicense {
    /// Merges a tag-length-value from the `reader` into this [`SPLicense`].
    ///
    /// Returns None if there are none TLVs left in the reader.
    fn merge_tlv<R: Read>(&mut self, mut reader: R) -> Result<Option<()>, SPLicenseDecodeError> {
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
                self.package_name = String::from_utf16le(&data)?;
            }
            Ok(BlockId::PackedContentKeys) => {
                let mut offset = 0;

                while offset < size {
                    let id_len = read_u16(&mut reader)? as usize;
                    // key_len is always 40
                    let _key_len = read_u16(&mut reader)? as usize;

                    if id_len < 16 {
                        return Err(SPLicenseDecodeError::InvalidPackedContentKeyIdLength {
                            id_len,
                        });
                    }

                    let key_id = read_uuid(&mut reader)?;
                    let _unknown = read_vec(&mut reader, id_len - 16)?;
                    let key = PackedContentKey(read_array(&mut reader)?);

                    self.content_keys.insert(key_id, key);
                    offset += 4 + id_len + 40;
                }
            }
            Ok(BlockId::ClepSignState) => {
                let data: [u8; 4096] = read_array(&mut reader)?;
                self.clep_sign_state = Some(Box::new(transmute!(data)));
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
                tracing::warn!("Unknown block in SPLicense");
                let _unknown = read_vec(&mut reader, size)?;
            }
            _ => {
                tracing::warn!("Unknown block in SPLicense");
                let _unknown = read_vec(&mut reader, size)?;
            }
        }

        // Ensure the number of bytes read is exactly `size`
        if reader.limit() != 0 {
            return Err(SPLicenseDecodeError::PayloadLengthMismatch {
                expected: size,
                read: size - reader.limit() as usize,
            });
        }

        Ok(Some(()))
    }

    pub fn decode<R: Read>(mut reader: R) -> Result<Self, SPLicenseDecodeError> {
        // Decode the header
        let _header: [u8; 4] = read_array(&mut reader)?;
        let _offset = read_u32(&mut reader)?;

        // Create an empty license
        let mut license = Self::default();

        // Merge fields from the stream into the license until EOF
        while let Some(()) = license.merge_tlv(&mut reader)? {}

        Ok(license)
    }

    pub fn parse_base64(string: &str) -> Result<SPLicense, SPLicenseParseError> {
        let data = BASE64_STANDARD.decode(string)?;
        Ok(SPLicense::decode(&*data)?)
    }
}

impl EncryptedDeviceKey {
    pub fn derive_device_key(&self) -> DeviceKey {
        assert!(self.version == 4);

        let device_key = decrypt_cbc_zero_iv(self.key_schedule, &self.device_key);

        // Sanity check: the decrypted device key must be equal to the decryption key
        assert_eq!(device_key, decryption_key(self.key_schedule));

        DeviceKey(device_key)
    }
}

impl ClepSignState {
    pub fn get_rsa_key(&self) -> BCryptRsaBlock {
        assert!(self.version == 4);
        BCryptRsaBlock(decrypt_cbc_zero_iv(self.key_schedule, &self.key_data))
    }
}

impl ClepHmacState {
    pub fn get_hmac_state(&self) -> HmacBinarySecret {
        assert!(self.version == 4);
        HmacBinarySecret(
            decrypt_cbc_zero_iv(self.key_schedule, &self.key_data)[12..44]
                .try_into()
                .unwrap(),
        )
    }
}

impl Deref for DeviceKey {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for BCryptRsaBlock {
    type Target = [u8; 544];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for HmacBinarySecret {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Error)]
#[error("the ciphertext couldn't be authenticated")]
pub struct ContentKeyAuthenticationFailed;

impl PackedContentKey {
    pub fn unpack(&self, key: &DeviceKey) -> Result<ContentKey, ContentKeyAuthenticationFailed> {
        let packer = aes_keywrap::Aes128KeyWrapAligned::new(key);

        match packer.decapsulate(&self.0) {
            Ok(unpaked) => Ok(ContentKey(unpaked.try_into().unwrap())),

            // These errors do not make sense for decapsulate
            Err(aes_keywrap::KeywrapError::InvalidExpectedLen)
            | Err(aes_keywrap::KeywrapError::Unpadded) => unreachable!(),

            // The input is always 40 bytes, so these errors are not possible
            Err(aes_keywrap::KeywrapError::NotAligned)
            | Err(aes_keywrap::KeywrapError::TooSmall)
            | Err(aes_keywrap::KeywrapError::TooBig) => unreachable!(),

            // The only possible error is a failure in the authentication of the key
            Err(aes_keywrap::KeywrapError::AuthenticationFailed) => {
                Err(ContentKeyAuthenticationFailed)
            }
        }
    }
}

impl Deref for ContentKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_test_header() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // 4-byte header
        buf.extend_from_slice(&0u32.to_le_bytes()); // 4-byte offset
        buf
    }

    #[test]
    fn test_packed_content_keys_underflow_guard() {
        let mut data = make_test_header();
        // BlockId::PackedContentKeys = 0xca
        data.extend_from_slice(&0xca_u32.to_le_bytes());
        // size: 4 (id_len + key_len) + 8 (id_len) + 40 (key_len) = 52 bytes
        let block_size = 4 + 8 + 40;
        data.extend_from_slice(&(block_size as u32).to_le_bytes());

        // id_len = 8 (< 16, would underflow id_len - 16)
        data.extend_from_slice(&8_u16.to_le_bytes());
        // key_len = 40
        data.extend_from_slice(&40_u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 48]);

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::InvalidPackedContentKeyIdLength { id_len: 8 })
        ));
    }

    #[test]
    fn test_package_full_name_invalid_utf16() {
        let mut data = make_test_header();
        // BlockId::PackageFullName = 0xce
        data.extend_from_slice(&0xce_u32.to_le_bytes());
        // Unpaired high surrogate 0xD800 in LE: [0x00, 0xD8] followed by 'a' (0x0061): [0x61, 0x00]
        let raw_utf16_bytes = vec![0x00, 0xd8, 0x61, 0x00];
        data.extend_from_slice(&(raw_utf16_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&raw_utf16_bytes);

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::InvalidPackageNameUtf16(_))
        ));
    }

    #[test]
    fn test_package_full_name_odd_byte_length() {
        let mut data = make_test_header();
        // BlockId::PackageFullName = 0xce
        data.extend_from_slice(&0xce_u32.to_le_bytes());
        let raw_bytes = vec![0x61, 0x00, 0x62]; // 3 bytes (odd length)
        data.extend_from_slice(&(raw_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&raw_bytes);

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::InvalidPackageNameUtf16(_))
        ));
    }

    #[test]
    fn test_package_full_name_valid() {
        let mut data = make_test_header();
        // BlockId::PackageFullName = 0xce
        data.extend_from_slice(&0xce_u32.to_le_bytes());
        let test_name = "Microsoft.Minecraft_8wekyb3d8bbwe\0";
        let mut utf16_bytes = Vec::new();
        for code_unit in test_name.encode_utf16() {
            utf16_bytes.extend_from_slice(&code_unit.to_le_bytes());
        }
        data.extend_from_slice(&(utf16_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&utf16_bytes);

        let license =
            SPLicense::decode(Cursor::new(data)).expect("Valid UTF-16 package name should decode");
        assert_eq!(license.package_name, test_name);
    }
}
