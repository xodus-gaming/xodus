use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, KeyInit, KeyIvInit, block_padding::NoPadding};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::cmp::min;
use thiserror::Error;

use super::cbor::{PackagingEncryptionAlgorithm, PackagingKeyPurpose};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("unsupported key derivation purpose or algorithm")]
    UnsupportedDerivation,
    #[error("key wrap error: {0}")]
    KeyWrap(String),
    #[error("decryption error: {0}")]
    Decryption(String),
    #[error("invalid key length (expected 32 bytes)")]
    InvalidKeyLength,
}

pub fn get_kdf_label(
    purpose: PackagingKeyPurpose,
    algorithm: PackagingEncryptionAlgorithm,
) -> Result<&'static [u8], CryptoError> {
    match (purpose, algorithm) {
        (PackagingKeyPurpose::PackageData, PackagingEncryptionAlgorithm::Aes256Cbc) => {
            Ok(b"MSIXVC2:PackageData:AES_256_CBC")
        }
        _ => Err(CryptoError::UnsupportedDerivation),
    }
}

/// NIST SP800-108 HMAC-SHA256 Counter Mode Key Derivation
pub fn derive_sp800_108(
    master_key: &[u8],
    purpose: PackagingKeyPurpose,
    algorithm: PackagingEncryptionAlgorithm,
    context: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let label = get_kdf_label(purpose, algorithm)?;
    let key_length = 32usize;

    // Buffer structure: [i]_2 (4 bytes) || Label || 0x00 (1 byte) || Context || [L]_2 (4 bytes)
    let len = 4 + label.len() + 1 + context.len() + 4;
    let mut msg = vec![0u8; len];

    let mut offset = 4;
    msg[offset..offset + label.len()].copy_from_slice(label);
    offset += label.len();

    // 0x00 separator byte
    msg[offset] = 0;
    offset += 1;

    msg[offset..offset + context.len()].copy_from_slice(context);
    offset += context.len();

    let bit_length = (key_length as u32) * 8;
    msg[offset..offset + 4].copy_from_slice(&bit_length.to_be_bytes());
    offset += 4;

    let mut derived = [0u8; 32];
    let mut counter: u32 = 1;
    let mut generated = 0;

    type HmacSha256 = Hmac<Sha256>;

    while generated < key_length {
        msg[0..4].copy_from_slice(&counter.to_be_bytes());
        counter = counter
            .checked_add(1)
            .ok_or_else(|| CryptoError::KeyWrap("counter overflow".to_string()))?;

        let mut mac = HmacSha256::new_from_slice(master_key)
            .map_err(|e| CryptoError::KeyWrap(e.to_string()))?;
        mac.update(&msg[..offset]);
        let output = mac.finalize().into_bytes();

        let take = min(output.len(), key_length - generated);
        derived[generated..generated + take].copy_from_slice(&output[..take]);
        generated += take;
    }

    Ok(derived)
}

/// Unwraps an encrypted key using AES-256 Key Wrap (RFC 3394 aligned or RFC 5649 padded)
pub fn unwrap_key_material(kek: &[u8; 32], wrapped_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Try RFC 3394 aligned key wrap first (most common for 32-byte keys)
    if wrapped_key.len().is_multiple_of(8) && wrapped_key.len() >= 16 {
        let kw_aligned = aes_keywrap::Aes256KeyWrapAligned::new(kek);
        if let Ok(unwrapped) = kw_aligned.decapsulate(wrapped_key) {
            return Ok(unwrapped);
        }
    }

    // Try RFC 5649 padded key wrap (expecting 32 bytes)
    let kw = aes_keywrap::Aes256KeyWrap::new(kek);
    if let Ok(unwrapped) = kw.decapsulate(wrapped_key, 32) {
        return Ok(unwrapped);
    }

    Err(CryptoError::KeyWrap(
        "failed to unwrap key with AES-256-KW".to_string(),
    ))
}

/// Decrypts AES-256-CBC ciphertext returning plaintext bytes
pub fn decrypt_aes_256_cbc(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err(CryptoError::Decryption(format!(
            "ciphertext length {} is not a multiple of AES block size 16",
            ciphertext.len()
        )));
    }

    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let mut plaintext = vec![0u8; ciphertext.len()];
    let res = decryptor
        .decrypt_padded_b2b::<NoPadding>(ciphertext, &mut plaintext)
        .map_err(|e| CryptoError::Decryption(format!("{e:?}")))?;

    Ok(res.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp800_108_derivation() {
        let master = [0x42u8; 32];
        let context = b"test_context";
        let derived = derive_sp800_108(
            &master,
            PackagingKeyPurpose::PackageData,
            PackagingEncryptionAlgorithm::Aes256Cbc,
            context,
        )
        .expect("derivation ok");

        assert_ne!(derived, master);
        assert_eq!(derived.len(), 32);

        // Deterministic check
        let derived2 = derive_sp800_108(
            &master,
            PackagingKeyPurpose::PackageData,
            PackagingEncryptionAlgorithm::Aes256Cbc,
            context,
        )
        .expect("derivation ok");
        assert_eq!(derived, derived2);
    }

    #[test]
    fn test_aes_256_cbc_round_trip() {
        use aes::cipher::BlockModeEncrypt;

        type Aes256CbcEnc = cbc::Encryptor<Aes256>;

        let key = [0x55u8; 32];
        let iv = [0xAAu8; 16];
        let plaintext = b"Hello from MSIXVC2 Decryption Engine!!.........."; // 48 bytes (multiple of 16)

        let mut ciphertext = vec![0u8; plaintext.len()];
        let encryptor = Aes256CbcEnc::new((&key).into(), (&iv).into());
        encryptor
            .encrypt_padded_b2b::<NoPadding>(plaintext, &mut ciphertext)
            .unwrap();

        let decrypted = decrypt_aes_256_cbc(&key, &iv, &ciphertext).expect("decryption ok");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_key_wrap_round_trip() {
        let kek = [0x11u8; 32];
        let target_key = [0x77u8; 32];

        let kw = aes_keywrap::Aes256KeyWrapAligned::new(&kek);
        let wrapped = kw.encapsulate(&target_key).expect("encapsulate ok");

        let unwrapped = unwrap_key_material(&kek, &wrapped).expect("unwrap ok");
        assert_eq!(unwrapped, target_key);
    }
}
