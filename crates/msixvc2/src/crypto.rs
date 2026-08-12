use crate::models::{
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
    let output_bits = output_len
        .checked_mul(8)
        .and_then(|bits| u32::try_from(bits).ok())
        .ok_or_else(|| Xvc2Error::Crypto("requested KDF output is too large".into()))?;
    let mut output = Vec::with_capacity(output_len);
    let mut counter: u32 = 1;

    while output.len() < output_len {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| Xvc2Error::Crypto("Invalid key for HMAC".into()))?;

        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00]);
        mac.update(context);
        mac.update(&output_bits.to_be_bytes());

        let result = mac.finalize().into_bytes();
        let remaining = output_len - output.len();

        if remaining < result.len() {
            output.extend_from_slice(&result[..remaining]);
        } else {
            output.extend_from_slice(&result);
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Xvc2Error::Crypto("KDF counter overflow".into()))?;
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

pub fn aes_key_unwrap_padded(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Xvc2Error> {
    if ciphertext.len() < 16 || !ciphertext.len().is_multiple_of(8) {
        return Err(Xvc2Error::Crypto(
            "Invalid ciphertext length for AES key unwrap".into(),
        ));
    }

    let mut a = [0u8; 8];
    let mut r;

    if ciphertext.len() == 16 {
        let mut block = [0u8; 16];
        block.copy_from_slice(ciphertext);
        match key.len() {
            16 => Aes128::new_from_slice(key)
                .map_err(|_| Xvc2Error::Crypto("Invalid key length".into()))?
                .decrypt_block((&mut block).into()),
            24 => Aes192::new_from_slice(key)
                .map_err(|_| Xvc2Error::Crypto("Invalid key length".into()))?
                .decrypt_block((&mut block).into()),
            32 => Aes256::new_from_slice(key)
                .map_err(|_| Xvc2Error::Crypto("Invalid key length".into()))?
                .decrypt_block((&mut block).into()),
            _ => return Err(Xvc2Error::Crypto("Invalid key length".into())),
        }
        a.copy_from_slice(&block[..8]);
        r = block[8..].to_vec();
    } else {
        let n = (ciphertext.len() / 8) - 1;
        a.copy_from_slice(&ciphertext[..8]);
        r = ciphertext[8..].to_vec();

        match key.len() {
            16 => unwrap_aes!(Aes128, key, n, a, r),
            24 => unwrap_aes!(Aes192, key, n, a, r),
            32 => unwrap_aes!(Aes256, key, n, a, r),
            _ => return Err(Xvc2Error::Crypto("Invalid key length".into())),
        }
    }

    if a[..4] != [0xA6, 0x59, 0x59, 0xA6] {
        return Err(Xvc2Error::Crypto(
            "AES key unwrap integrity check failed".into(),
        ));
    }

    let message_len = usize::try_from(u32::from_be_bytes(a[4..].try_into().unwrap()))
        .map_err(|_| Xvc2Error::Crypto("wrapped key length is too large".into()))?;
    if message_len > r.len() || message_len <= r.len().saturating_sub(8) {
        return Err(Xvc2Error::Crypto(
            "AES key unwrap length check failed".into(),
        ));
    }
    if r[message_len..].iter().any(|byte| *byte != 0) {
        return Err(Xvc2Error::Crypto(
            "AES key unwrap padding check failed".into(),
        ));
    }
    r.truncate(message_len);

    Ok(r)
}

pub fn decrypt_aes_256_cbc(
    key: &[u8; 32],
    iv: &[u8; 16],
    data: &mut [u8],
) -> Result<(), Xvc2Error> {
    if !data.len().is_multiple_of(16) {
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
        let algorithm = match key_source.wrap_algorithm {
            EncryptionAlgorithm::Automatic | EncryptionAlgorithm::Aes256Cbc => {
                EncryptionAlgorithm::Aes256Cbc
            }
            other => other,
        };
        if algorithm != EncryptionAlgorithm::Aes256Cbc {
            return Err(Xvc2Error::Crypto(format!(
                "unsupported derived wrapping algorithm: {algorithm}"
            )));
        }
        let label = format!("MSIXVC2:{}:AES_256_CBC", KeyPurpose::PackageData);

        wrapping_key = kdf_sp800_108_hmac_sha256(
            stored_key_material,
            label.as_bytes(),
            &key_source.kdf_context,
            32,
        )?;
    }

    if key_source.wrapped_key.is_empty() {
        return Ok(wrapping_key);
    }

    unwrap_key_material(
        &wrapping_key,
        &key_source.wrapped_key,
        key_source.wrap_algorithm,
        key_source.wrap_iv.as_ref(),
    )
}

fn unwrap_key_material(
    key: &[u8],
    wrapped_key: &[u8],
    algorithm: EncryptionAlgorithm,
    iv: Option<&PackagingIv>,
) -> Result<Vec<u8>, Xvc2Error> {
    match algorithm {
        EncryptionAlgorithm::Automatic | EncryptionAlgorithm::Aes256Cbc => {
            let key: &[u8; 32] = key
                .try_into()
                .map_err(|_| Xvc2Error::Crypto("invalid CBC wrapping key length".into()))?;
            let iv = iv.ok_or_else(|| Xvc2Error::Crypto("CBC key unwrap requires an IV".into()))?;
            let mut unwrapped = wrapped_key.to_vec();
            decrypt_aes_256_cbc(key, &iv.to_bytes(), &mut unwrapped)?;
            Ok(unwrapped)
        }
        EncryptionAlgorithm::Aes256Kw => aes_key_unwrap_padded(key, wrapped_key),
        EncryptionAlgorithm::None => Err(Xvc2Error::Crypto(
            "cannot unwrap a key without a wrapping algorithm".into(),
        )),
    }
}

pub fn decrypt_segment_content(
    encrypted: &[u8],
    iv: &[u8; 16],
    key_source: Option<&PackageKeySource>,
    stored_key_material: Option<&[u8]>,
    encryption_key: Option<&[u8]>,
    wrapped_key: Option<&[u8]>,
    wrap_iv: Option<&PackagingIv>,
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
            let algorithm = key_source
                .map(|source| source.wrap_algorithm)
                .ok_or_else(|| Xvc2Error::Crypto("missing key source for wrapped key".into()))?;
            working_key = unwrap_key_material(&working_key, wk, algorithm, wrap_iv)?;
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
        let key = [0u8; 32];
        let label = b"MSIXVC2:PackageData:AES_256_CBC";
        let context = [0u8; 16];
        let output = kdf_sp800_108_hmac_sha256(&key, label, &context, 32).unwrap();
        assert_eq!(
            output,
            [
                0xdd, 0xbf, 0x6f, 0x06, 0xcc, 0x73, 0x46, 0xc6, 0xb0, 0xbc, 0xd3, 0xe1, 0x29, 0x87,
                0x5a, 0x5d, 0x48, 0xe5, 0x88, 0x47, 0x2c, 0xed, 0x56, 0x29, 0x2a, 0xf7, 0x84, 0x4b,
                0xf2, 0x2d, 0x4f, 0x56,
            ]
        );
    }

    #[test]
    fn test_aes_key_wrap_padded_unwrap() {
        let key = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let cipher = [
            0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22,
            0x48, 0xee, 0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73,
            0xfa, 0x54, 0x3b, 0x6a,
        ];
        let plain = aes_key_unwrap_padded(&key, &cipher).unwrap();

        let expected_plain = [
            0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89,
            0x41, 0x15, 0x50, 0x68, 0xf7, 0x38,
        ];
        assert_eq!(plain, expected_plain);
    }

    #[test]
    fn test_aes_key_wrap_padded_single_block() {
        let key = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        let cipher = [
            0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b,
            0xb2, 0x4f,
        ];

        assert_eq!(aes_key_unwrap_padded(&key, &cipher).unwrap(), b"ForPasi");
    }

    #[test]
    fn test_decrypt_aes_256_cbc() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut cipher = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b,
            0xfb, 0xd6,
        ];
        decrypt_aes_256_cbc(&key, &iv, &mut cipher).unwrap();
        assert_eq!(
            cipher,
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ]
        );
    }

    #[test]
    fn test_cbc_key_unwrap_uses_the_supplied_iv() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv = PackagingIv::from_bytes(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let wrapped = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b,
            0xfb, 0xd6,
        ];

        let unwrapped =
            unwrap_key_material(&key, &wrapped, EncryptionAlgorithm::Aes256Cbc, Some(&iv)).unwrap();

        assert_eq!(
            unwrapped,
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ]
        );
    }
}
