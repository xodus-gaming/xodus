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

use std::{
    collections::HashMap,
    io::{BufRead, Read},
};

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use base64::prelude::*;
use zerocopy::transmute;

// pub struct Block<'a> {
//     pub block_id: BlockId,
//     pub size: u32,
//     pub data: &'a [u8],
// }

#[derive(Debug)]
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

impl TryFrom<u32> for BlockId {
    type Error = u32;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x14 => Ok(Self::UnkBlock0),
            0x1f => Ok(Self::DeviceLicenseExpirationTime),
            0xd3 => Ok(Self::PollingTime),
            0x20 => Ok(Self::LicenseExpirationTime),
            0x12d => Ok(Self::ClepSignState),
            0xd2 => Ok(Self::LicenseDeviceId),
            0xd1 => Ok(Self::UnkBlock1),
            0xcb => Ok(Self::LicenseId),
            0xd0 => Ok(Self::HardwareId),
            0xcf => Ok(Self::UnkBlock2),
            0x18 => Ok(Self::UplinkKeyId),
            0x0 => Ok(Self::UnkBlock3),
            0x12e => Ok(Self::UnkBlock4),
            0xd5 => Ok(Self::UnkBlock5),
            0xce => Ok(Self::PackageFullName),
            0xc9 => Ok(Self::LicenseInformation),
            0xca => Ok(Self::PackedContentKeys),
            0x1 => Ok(Self::EncryptedDeviceKey),
            0x2 => Ok(Self::DeviceLicenseDeviceId),
            0xcd => Ok(Self::LicenseEntryIds),
            0xd4 => Ok(Self::LicensePolicies),
            0xdc => Ok(Self::KeyholderPublicSigningKey),
            0xdd => Ok(Self::KeyholderPolicies),
            0xde => Ok(Self::KeyholderKeyLicenseId),
            0xcc => Ok(Self::SignatureBlock),
            _ => Err(value),
        }
    }
}

#[derive(Debug)]
pub struct SPLicense {
    pub license_id: uuid::Uuid,
    pub device_id: Vec<u8>,
    pub keyholder_key_license_id: uuid::Uuid,
    pub package_name: String,
    pub signature_origin: u16,
    pub signature_block: Vec<u8>,
    pub clep_sign_state: Vec<u8>,
    pub encrypted_device_key: Vec<u8>,
    pub content_keys: HashMap<uuid::Uuid, Vec<u8>>,
    pub keyholder_public_key: Vec<u8>,
    pub keyholder_policies: Vec<u8>,
    pub license_policies: Vec<u8>,
    pub entry_ids: Vec<[u8; 32]>,
    pub hardware_id: Vec<u8>,
    pub polling_time: u32,
    pub license_expiration_time: u32,
}
impl From<&[u8]> for SPLicense {
    fn from(mut value: &[u8]) -> Self {
        let mut buffer = [0; 4];
        value.read_exact(&mut buffer).unwrap();
        let _header = buffer;
        value.read_exact(&mut buffer).unwrap();
        let _offset = u32::from_le_bytes(buffer);

        let mut license = Self {
            license_id: uuid::Uuid::nil(),
            device_id: Vec::new(),
            keyholder_key_license_id: uuid::Uuid::nil(),
            package_name: String::default(),
            encrypted_device_key: Vec::new(),
            content_keys: HashMap::new(),
            clep_sign_state: Vec::new(),
            polling_time: 0,
            signature_origin: 0,
            license_expiration_time: 0,
            signature_block: Vec::new(),
            entry_ids: Vec::new(),
            keyholder_public_key: Vec::new(),
            keyholder_policies: Vec::new(),
            license_policies: Vec::new(),
            hardware_id: Vec::new(),
        };
        while let Ok(size) = value.read(&mut buffer) {
            if size == 0 {
                break;
            }

            let block_id: Result<BlockId, u32> = u32::from_le_bytes(buffer).try_into();
            value.read_exact(&mut buffer).unwrap();
            let size = u32::from_le_bytes(buffer);
            match block_id {
                Ok(BlockId::LicenseId) => {
                    let mut buffer = [0u8; 16];
                    value.read_exact(&mut buffer).unwrap();
                    license.license_id = uuid::Uuid::from_bytes_le(buffer);
                }
                Ok(BlockId::DeviceLicenseDeviceId | BlockId::LicenseDeviceId) => {
                    let mut buf = vec![0; size as usize];
                    value.read_exact(&mut buf).unwrap();
                    license.device_id = buf;
                }
                Ok(BlockId::KeyholderKeyLicenseId) => {
                    let mut buffer = [0u8; 16];
                    value.read_exact(&mut buffer).unwrap();
                    license.keyholder_key_license_id = uuid::Uuid::from_bytes_le(buffer);
                }
                Ok(BlockId::EncryptedDeviceKey) => {
                    let mut buffer = [0; 2];
                    value.read_exact(&mut buffer).unwrap();
                    let mut data: Vec<u8> = vec![0; size as usize - 2];
                    value.read_exact(&mut data).unwrap();
                    license.encrypted_device_key = data;
                }
                Ok(BlockId::PackageFullName) => {
                    let mut data: Vec<u8> = vec![0; size as usize];
                    value.read_exact(&mut data).unwrap();
                    let utf16: Vec<u16> = data
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    let mut s = String::from_utf16(&utf16).unwrap();
                    if s.ends_with('\0') {
                        s.pop();
                    }
                    license.package_name = s;
                }
                Ok(BlockId::PackedContentKeys) => {
                    let mut offset = 0;
                    let mut buffer = [0; 2];
                    while offset < size {
                        value.read_exact(&mut buffer).unwrap();
                        let id_len = u16::from_le_bytes(buffer);
                        value.read_exact(&mut buffer).unwrap();
                        let key_len = u16::from_le_bytes(buffer);

                        let mut key_id: Vec<u8> = vec![0; id_len as usize];
                        value.read_exact(&mut key_id).unwrap();
                        let mut key: Vec<u8> = vec![0; key_len as usize];
                        value.read_exact(&mut key).unwrap();

                        let key_id = uuid::Uuid::from_bytes_le(key_id[..16].try_into().unwrap());
                        license.content_keys.insert(key_id, key);
                        offset += 4 + id_len as u32 + key_len as u32;
                    }
                }
                Ok(BlockId::ClepSignState) => {
                    let mut data: Vec<u8> = vec![0; size as usize];
                    value.read_exact(&mut data).unwrap();
                    license.clep_sign_state = data;
                }
                Ok(BlockId::SignatureBlock) => {
                    value.consume(2);
                    let mut buffer = [0; 2];
                    value.read_exact(&mut buffer).unwrap();
                    license.signature_origin = u16::from_le_bytes(buffer);
                    let mut data: Vec<u8> = vec![0; size as usize - 4];
                    value.read_exact(&mut data).unwrap();
                    license.signature_block = data;
                }
                Ok(BlockId::PollingTime) => {
                    let mut buffer = [0u8; 4];
                    value.read_exact(&mut buffer).unwrap();
                    let ts = u32::from_le_bytes(buffer);
                    license.polling_time = ts;
                }
                Ok(BlockId::LicenseExpirationTime | BlockId::DeviceLicenseExpirationTime) => {
                    let mut buffer = [0u8; 4];
                    value.read_exact(&mut buffer).unwrap();
                    let ts = u32::from_le_bytes(buffer);
                    license.license_expiration_time = ts;
                }
                Ok(BlockId::HardwareId) => {
                    let mut buffer = vec![0; size as usize];
                    value.read_exact(&mut buffer).unwrap();
                    license.hardware_id = buffer;
                }
                Ok(BlockId::LicenseInformation) => {
                    let mut buffer2 = [0u8; 2];
                    let mut buffer4 = [0u8; 4];

                    value.read_exact(&mut buffer2).unwrap();
                    value.read_exact(&mut buffer2).unwrap();
                    value.read_exact(&mut buffer4).unwrap();
                    value.read_exact(&mut buffer2).unwrap();
                }
                Ok(BlockId::LicenseEntryIds) => {
                    let mut buffer2 = [0; 2];
                    let mut buffer32 = [0; 32];
                    value.read_exact(&mut buffer2).unwrap();
                    let count = u16::from_le_bytes(buffer2);
                    for _ in 0..count {
                        value.read_exact(&mut buffer32).unwrap();
                        license.entry_ids.push(buffer32);
                    }
                }
                Ok(BlockId::KeyholderPublicSigningKey) => {
                    let mut buf = vec![0; size as usize];
                    value.read_exact(&mut buf).unwrap();
                    license.keyholder_public_key = buf;
                }
                Ok(BlockId::KeyholderPolicies) => {
                    let mut buf = vec![0; size as usize];
                    value.read_exact(&mut buf).unwrap();
                    license.keyholder_policies = buf;
                }
                Ok(BlockId::LicensePolicies) => {
                    let mut buf = vec![0; size as usize];
                    value.read_exact(&mut buf).unwrap();
                    license.license_policies = buf;
                }
                Ok(
                    BlockId::UnkBlock0
                    | BlockId::UnkBlock1
                    | BlockId::UnkBlock2
                    | BlockId::UnkBlock3
                    | BlockId::UnkBlock4
                    | BlockId::UnkBlock5,
                ) => {
                    let mut buf = vec![0; size as usize];
                    value.read_exact(&mut buf).unwrap();
                }
                _ => {
                    let mut buf = vec![0; size as usize];
                    value.read_exact(&mut buf).unwrap();
                }
            }
        }
        license
    }
}

pub fn derive_device_key(license: &[u8]) -> Vec<u8> {
    assert!(u32::from_le_bytes(license[..4].try_into().unwrap()) == 4);

    let keyschedule: [u8; 228] = license[4..232].try_into().unwrap();
    let keyschedule: [u32; 57] = transmute!(keyschedule);
    let devicekey: [u8; 16] = license[516..532].try_into().unwrap();

    let mut decryption_key = [0u32; 4];

    decryption_key[0] = keyschedule[46] ^ keyschedule[56] ^ 0xE20DF371 ^ 0xCCB22FE6;
    decryption_key[1] = keyschedule[36] ^ keyschedule[47] ^ 0xDF080E39;
    decryption_key[2] = keyschedule[40] ^ keyschedule[51] ^ 0x6D09B2F5 ^ 0x2AE17AB9;
    decryption_key[3] = keyschedule[30] ^ keyschedule[41] ^ 0x37288CEC;
    let decryption_key: [u8; 16] = transmute!(decryption_key);

    let key = aes::cipher::array::Array::from(decryption_key);
    let aes = aes::Aes128::new(&key);
    let mut data = aes::cipher::Array::from(devicekey);
    aes.decrypt_block(&mut data);

    data.to_vec()
}

pub fn parse_license(splicense_block: String) -> SPLicense {
    SPLicense::from(BASE64_STANDARD.decode(splicense_block).unwrap().as_slice())
}

pub fn unpack_key(
    key: &[u8; 16],
    content_key: Vec<u8>,
) -> Result<Vec<u8>, aes_keywrap::KeywrapError> {
    let packer = aes_keywrap::Aes128KeyWrapAligned::new(key);
    packer.decapsulate(&content_key)
}
