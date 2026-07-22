use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use base64::prelude::*;
use hmac::{Hmac, Mac};
use rsa::rand_core::{OsRng, RngCore};
use rsa::sha2::Sha256;
use std::cmp::min;
use zerocopy::IntoBytes;

use crate::models::soap::{self};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// SP800_108 HMAC with counter
/// - key_usage - KDF_LABEL
/// - nonce - KDF_CONTEXT
pub fn generate_shared_key(
    key_length: usize,
    in_key: &[u8],
    key_usage: &str,
    nonce: &[u8],
) -> [u8; 32] {
    let len: usize = 4 + key_usage.len() + 1 + nonce.len() + 4;
    let mut shared_key_material: Vec<u8> = vec![0; len];

    let mut offset = 0;
    offset += 4;
    shared_key_material[offset..offset + key_usage.len()].copy_from_slice(key_usage.as_bytes());
    offset += key_usage.len();

    // Already zerod
    offset += 1;

    shared_key_material[offset..offset + nonce.len()].copy_from_slice(nonce);
    offset += nonce.len();

    let key_bit_length = u32::try_from(key_length * 8).unwrap();
    shared_key_material[offset..offset + 4].copy_from_slice(&key_bit_length.to_be_bytes());

    offset += 4;

    let mut current_key_length: usize = 0;
    let mut current_hash_count: u32 = 1;

    let mut shared_key = [0; 32];

    while current_key_length < key_length {
        shared_key_material[0..4].copy_from_slice(&current_hash_count.to_be_bytes());

        current_hash_count += 1;

        type HmacSha256 = Hmac<Sha256>;

        let mut hmac = HmacSha256::new_from_slice(in_key).unwrap();
        hmac.update(&shared_key_material[..offset]);
        let signature = hmac.finalize().into_bytes();
        let amount = min(signature.len(), key_length - current_key_length);
        shared_key[current_key_length..current_key_length + amount]
            .copy_from_slice(&signature.as_bytes()[0..amount]);
        current_key_length += amount;
    }

    shared_key
}

pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    _ = OsRng.try_fill_bytes(&mut nonce);
    nonce
}

pub fn decrypt_response(
    envelope: soap::Envelope<String>,
    secret: &[u8],
) -> Result<(soap::BodyContent<String>, Option<soap::PP>), Box<dyn std::error::Error>> {
    let mut pp = envelope.header.pp;
    if let Some(enc_pp) = envelope.header.encrypted_pp {
        let id = enc_pp
            .encrypted_data
            .key_info
            .security_token_reference
            .unwrap()
            .reference
            .uri;
        let mut enc_nonce = None;
        for token in &envelope.header.security.derived_key_tokens {
            if format!("#{}", token.id) == id {
                enc_nonce = Some(token.nonce.clone());
                continue;
            }
        }
        let enc_nonce = enc_nonce.unwrap();
        let enc_nonce = BASE64_STANDARD.decode(enc_nonce).unwrap();

        let enc_key = generate_shared_key(
            32,
            secret,
            "WS-SecureConversationWS-SecureConversation",
            &enc_nonce,
        );
        let value = BASE64_STANDARD
            .decode(enc_pp.encrypted_data.cipher_data.cipher_value)
            .unwrap();
        let (iv, encrypted) = value.split_at(16);
        let iv: &[u8; 16] = iv.try_into().unwrap();
        let decryptor = Aes256CbcDec::new(&enc_key.into(), iv.into());
        let mut block = [0; 8192];

        decryptor
            .decrypt_padded_b2b::<Pkcs7>(encrypted, &mut block)
            .expect("Failed");
        let result = std::str::from_utf8(&block).unwrap();
        let new_pp = quick_xml::de::from_str::<soap::PP>(result).unwrap();
        pp = Some(new_pp);
    }

    if let soap::BodyContent::EncryptedData(data) = envelope.body.body {
        let key_info = data.key_info.as_signature();
        let id = key_info.security_token_reference.reference.uri;
        let mut enc_nonce = None;
        for token in envelope.header.security.derived_key_tokens {
            if format!("#{}", token.id) == id {
                enc_nonce = Some(token.nonce);
                continue;
            }
        }
        let enc_nonce = enc_nonce.unwrap();
        let enc_nonce = BASE64_STANDARD.decode(enc_nonce).unwrap();

        let enc_key = generate_shared_key(
            32,
            secret,
            "WS-SecureConversationWS-SecureConversation",
            &enc_nonce,
        );

        let value = BASE64_STANDARD
            .decode(data.cipher_data.cipher_value)
            .unwrap();
        let (iv, encrypted) = value.split_at(16);
        let iv: &[u8; 16] = iv.try_into().unwrap();

        let decryptor = Aes256CbcDec::new(&enc_key.into(), iv.into());
        let mut block = [0; 8192];

        decryptor.decrypt_padded_b2b::<Pkcs7>(encrypted, &mut block)?;
        let result = std::str::from_utf8(&block).unwrap();
        println!("{result}"); // Useful debugging technique
        let security_token_res: soap::BodyContent<String> = quick_xml::de::from_str(result)?;

        return Ok((security_token_res, pp));
    }

    Ok((envelope.body.body, pp))
}
