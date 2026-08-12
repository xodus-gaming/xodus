use crate::xvc2::models::{
    DerivationAlgorithm, EncryptionAlgorithm, KeyPurpose, PackageKeySource, PackagingIv, Xvc2Error,
};
use aes::cipher::{BlockCipherDecrypt, BlockModeDecrypt, KeyInit, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type Aes256CbcDec = Decryptor<Aes256>;

pub fn kdf_sp800_108_hmac_sha256(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, Xvc2Error> {
    let mut output = Vec::with_capacity(output_len);
    let mut counter: u32 = 1;
    let l_bits = (output_len as u32) * 8;

    while output.len() < output_len {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| Xvc2Error::Crypto("Invalid key for HMAC".into()))?;

        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00]);
        mac.update(context);
        mac.update(&l_bits.to_be_bytes());

        let result = mac.finalize().into_bytes();
        let remaining = output_len - output.len();

        if remaining < result.len() {
            output.extend_from_slice(&result[..remaining]);
        } else {
            output.extend_from_slice(&result);
        }
        counter += 1;
    }

    Ok(output)
}

macro_rules! unwrap_aes {
    ($aes_type:ty, $key:expr, $n:expr, $a:expr, $r:expr) => {{
        let aes = <$aes_type>::new_from_slice($key)
            .map_err(|_| Xvc2Error::Crypto("Invalid key length".into()))?;
        let mut block_bytes = [0u8; 16];
        for j in (0..=5).rev() {
            for i in (1..=$n).rev() {
                let t = ($n * j + i) as u64;
                let t_bytes = t.to_be_bytes();

                for k in 0..8 {
                    block_bytes[k] = $a[k] ^ t_bytes[k];
                }

                let r_offset = (i - 1) * 8;
                block_bytes[8..16].copy_from_slice(&$r[r_offset..r_offset + 8]);

                let block: &mut [u8; 16] = (&mut block_bytes).try_into().unwrap();
                aes.decrypt_block(block.into());

                $a.copy_from_slice(&block_bytes[0..8]);
                $r[r_offset..r_offset + 8].copy_from_slice(&block_bytes[8..16]);
            }
        }
    }};
}

pub fn aes_key_unwrap(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Xvc2Error> {
    if ciphertext.len() < 16 || ciphertext.len() % 8 != 0 {
        return Err(Xvc2Error::Crypto(
            "Invalid ciphertext length for AES key unwrap".into(),
        ));
    }

    let n = (ciphertext.len() / 8) - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&ciphertext[0..8]);

    let mut r = vec![0u8; n * 8];
    r.copy_from_slice(&ciphertext[8..]);

    match key.len() {
        16 => unwrap_aes!(Aes128, key, n, a, r),
        24 => unwrap_aes!(Aes192, key, n, a, r),
        32 => unwrap_aes!(Aes256, key, n, a, r),
        _ => return Err(Xvc2Error::Crypto("Invalid key length".into())),
    }

    let default_iv = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
    if a != default_iv {
        return Err(Xvc2Error::Crypto(
            "AES key unwrap integrity check failed".into(),
        ));
    }

    Ok(r)
}

pub fn decrypt_aes_256_cbc(
    key: &[u8; 32],
    iv: &[u8; 16],
    data: &mut [u8],
) -> Result<(), Xvc2Error> {
    if data.len() % 16 != 0 {
        return Err(Xvc2Error::Crypto(
            "Data length is not a multiple of block size".into(),
        ));
    }

    let mut cipher = Aes256CbcDec::new(key.into(), iv.into());
    for chunk in data.chunks_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into().unwrap();
        cipher.decrypt_block(block.into());
    }

    Ok(())
}

pub fn derive_key_material(
    key_source: &PackageKeySource,
    stored_key_material: &[u8],
) -> Result<Vec<u8>, Xvc2Error> {
    let mut wrapping_key = stored_key_material.to_vec();

    if key_source.derivation_algorithm == DerivationAlgorithm::Sp800108HmacSha256 {
        let algo_str = match key_source.algorithm {
            EncryptionAlgorithm::Aes256Cbc => "AES_256_CBC",
            EncryptionAlgorithm::Aes256Kw => "AES_256_KW",
            _ => "NONE",
        };
        let label = format!("MSIXVC2:{}:{}", key_source.source_purpose, algo_str);

        wrapping_key = kdf_sp800_108_hmac_sha256(
            stored_key_material,
            label.as_bytes(),
            &key_source.kdf_context,
            32,
        )?;
    }

    if key_source.wrap_algorithm == EncryptionAlgorithm::Aes256Kw {
        aes_key_unwrap(&wrapping_key, &key_source.wrapped_key)
    } else {
        Ok(wrapping_key)
    }
}

pub fn decrypt_segment_content(
    encrypted: &[u8],
    iv: &[u8; 16],
    key_source: Option<&PackageKeySource>,
    stored_key_material: Option<&[u8]>,
    encryption_key: Option<&[u8]>,
    wrapped_key: Option<&[u8]>,
    _wrap_iv: Option<&PackagingIv>,
    _purpose: KeyPurpose,
) -> Result<Vec<u8>, Xvc2Error> {
    let mut key = [0u8; 32];

    if let Some(ek) = encryption_key {
        if ek.len() != 32 {
            return Err(Xvc2Error::Crypto("Invalid encryption key length".into()));
        }
        key.copy_from_slice(ek);
    } else {
        let mut working_key = if let (Some(ks), Some(skm)) = (key_source, stored_key_material) {
            derive_key_material(ks, skm)?
        } else if let Some(skm) = stored_key_material {
            skm.to_vec()
        } else {
            return Err(Xvc2Error::Crypto("No key material provided".into()));
        };

        if let Some(wk) = wrapped_key {
            working_key = aes_key_unwrap(&working_key, wk)?;
        }

        if working_key.len() != 32 {
            return Err(Xvc2Error::Crypto("Invalid final key length".into()));
        }
        key.copy_from_slice(&working_key);
    }

    let mut data = encrypted.to_vec();
    decrypt_aes_256_cbc(&key, iv, &mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_sp800_108_hmac_sha256() {
        let key = b"my_secret_key";
        let label = b"test_label";
        let context = b"test_context";
        let output = kdf_sp800_108_hmac_sha256(key, label, context, 32).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_aes_key_wrap_unwrap() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let cipher = [
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];
        let plain = aes_key_unwrap(&key, &cipher).unwrap();

        let expected_plain = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        assert_eq!(plain, expected_plain);
    }

    #[test]
    fn test_decrypt_aes_256_cbc() {
        let key = [0x42; 32];
        let iv = [0x11; 16];
        let mut cipher = [
            245, 12, 38, 23, 103, 161, 60, 246, 219, 100, 235, 34, 182, 178, 142, 60,
        ];
        decrypt_aes_256_cbc(&key, &iv, &mut cipher).unwrap();
        assert_eq!(cipher.len(), 16);
    }
}
