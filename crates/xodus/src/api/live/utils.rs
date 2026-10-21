use std::cmp::min;
use std::collections::HashMap;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use rsa::rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zerocopy::IntoBytes;

use crate::api::live::rst;
use crate::models::soap;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[cfg(test)]
mod tests {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    use super::decrypt_cipher_value;

    #[test]
    fn rejects_a_payload_without_an_iv() {
        let error = decrypt_cipher_value(&[0; 15], &[0; 32]).unwrap_err();

        assert!(matches!(
            error,
            crate::api::live::rst::RSTError::InvalidEncryptedPayload
        ));
    }

    #[test]
    fn decrypts_plaintext_larger_than_the_old_eight_kib_limit() {
        let plaintext = vec![b'x'; 8192];
        let mut encrypted = vec![0; plaintext.len() + 16];
        let encrypted = Aes256CbcEnc::new((&[0; 32]).into(), (&[0; 16]).into())
            .encrypt_padded_b2b::<Pkcs7>(&plaintext, &mut encrypted)
            .unwrap();
        let mut cipher_value = vec![0; 16];
        cipher_value.extend_from_slice(encrypted);

        assert_eq!(
            decrypt_cipher_value(&cipher_value, &[0; 32]).unwrap(),
            plaintext
        );
    }
}

fn decrypt_cipher_value(cipher_value: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, rst::RSTError> {
    let (iv, encrypted) = cipher_value
        .split_at_checked(16)
        .ok_or(rst::RSTError::InvalidEncryptedPayload)?;
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| rst::RSTError::InvalidEncryptedPayload)?;
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let mut plaintext = vec![0; encrypted.len()];
    let plaintext = decryptor
        .decrypt_padded_b2b::<Pkcs7>(encrypted, &mut plaintext)
        .map_err(|_| rst::RSTError::Decryption)?;

    Ok(plaintext.to_vec())
}

/// SP800_108 HMAC with counter
/// - key_usage - KDF_LABEL
/// - context - KDF_CONTEXT
pub fn generate_shared_key(
    key_length: usize,
    in_key: &[u8],
    key_usage: &str,
    context: &[u8],
) -> [u8; 32] {
    let len: usize = 4 + key_usage.len() + 1 + context.len() + 4;
    let mut shared_key_material: Vec<u8> = vec![0; len];

    let mut offset = 0;
    offset += 4;
    shared_key_material[offset..offset + key_usage.len()].copy_from_slice(key_usage.as_bytes());
    offset += key_usage.len();

    // Already zerod
    offset += 1;

    shared_key_material[offset..offset + context.len()].copy_from_slice(context);
    offset += context.len();

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

pub fn sign_xml(
    signature: Option<&super::rst::RSTSignature>,
    nonce: &[u8],
    xml_text: String,
) -> Result<String, rst::RSTBuilderError> {
    let Some(signature) = signature else {
        return Ok(xml_text);
    };
    let min_xml = bergshamra::c14n::canonicalize(
        &xml_text,
        bergshamra_c14n::C14nMode::Exclusive,
        None,
        &[] as &[&str],
    )?;

    let mut kmgr = bergshamra::KeysManager::new();
    let key = signature.signing_key(nonce)?;

    kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Sign));
    let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
    let signed = bergshamra::sign(&ctx, std::str::from_utf8(&min_xml).unwrap())?;
    Ok(signed)
}

pub fn decrypt_soap_encrypted_data<T: serde::de::DeserializeOwned>(
    encrypted_data: Box<soap::EncryptedData>,
    signature: &rst::RSTSignature,
    nonces: &HashMap<String, String>,
) -> Result<T, rst::RSTError> {
    let id = &encrypted_data
        .key_info
        .as_signature()
        .security_token_reference
        .reference
        .uri;

    let nonce = nonces.get(&id[1..]).ok_or(rst::RSTError::MissingNonce)?;
    let nonce = BASE64_STANDARD.decode(nonce)?;
    let key = signature.hmac_key(&nonce).ok_or(rst::RSTError::HmacKey)?;
    let cipher_value = BASE64_STANDARD.decode(encrypted_data.cipher_data.cipher_value)?;

    let plaintext = decrypt_cipher_value(&cipher_value, &key)?;
    let result = std::str::from_utf8(&plaintext)?;
    let data = quick_xml::de::from_str::<T>(result)?;

    Ok(data)
}
