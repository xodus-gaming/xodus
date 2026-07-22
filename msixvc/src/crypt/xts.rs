use crate::math::gf_mul_x;
use crate::models::xvd::{PAGE_SIZE, XvcRegionId};

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt};
use aes::{Aes128Dec, Aes128Enc};
use uuid::Uuid;

/// A [`TweakGenerator`] stores all common fields needed to generate every [`Tweak`]
/// for an XVC region.
#[derive(Clone, Copy, Debug)]
pub struct TweakGenerator {
    region_id: [u8; 4],
    vduid: [u8; 8],
}

impl TweakGenerator {
    pub fn new(region_id: XvcRegionId, vduid: Uuid) -> Self {
        Self {
            region_id: region_id.to_le_bytes(),
            vduid: vduid.to_bytes_le()[..8].try_into().unwrap(),
        }
    }

    pub fn with_data_unit(self, data_unit: u32) -> Tweak {
        let mut buf = [0u8; 16];

        buf[0..4].copy_from_slice(&data_unit.to_le_bytes());
        buf[4..8].copy_from_slice(&self.region_id);
        buf[8..16].copy_from_slice(&self.vduid);

        Tweak(buf)
    }
}

/// A [`Tweak`] is the per-page tweak input, derived from a [`TweakGenerator`] by adding
/// a unique `data_unit` via [`TweakGenerator::with_data_unit`].
#[derive(Clone, Copy, Debug)]
pub struct Tweak([u8; 16]);

impl Tweak {
    fn encrypt(self, tweak_cipher: &Aes128Enc) -> u128 {
        let mut block = aes::Block::from(self.0);
        tweak_cipher.encrypt_block(&mut block);
        u128::from_le_bytes(block.0)
    }
}

/// Decrypts a page using XTS-AES (IEEE 1619-2007).
///
/// XTS-AES uses two keys: a tweak key to derive a per-page tweak, and a data key
/// to decrypt the data. Each 16-byte block is decrypted as `P = AES_dec(C ⊕ T) ⊕ T`,
/// where `T` is the AES-encrypted tweak, advanced by one GF(2¹²⁸) multiplication per block.
pub fn decrypt_page_xts(
    page: &mut [u8; PAGE_SIZE],
    tweak: Tweak,
    tweak_cipher: &Aes128Enc,
    data_cipher: &Aes128Dec,
) {
    transform_page_xts(page, tweak, tweak_cipher, |block| {
        data_cipher.decrypt_block(block);
    });
}

/// Encrypts a page using XTS-AES (IEEE 1619-2007).
///
/// XTS-AES uses two keys: a tweak key to derive a per-page tweak, and a data key
/// to encrypt the data. Each 16-byte block is encrypted as `C = AES_enc(P ⊕ T) ⊕ T`,
/// where `T` is the AES-encrypted tweak, advanced by one GF(2¹²⁸) multiplication per block.
#[expect(dead_code)]
pub fn encrypt_page_xts(
    page: &mut [u8; PAGE_SIZE],
    tweak: Tweak,
    tweak_cipher: &Aes128Enc,
    data_cipher: &Aes128Enc,
) {
    transform_page_xts(page, tweak, tweak_cipher, |block| {
        data_cipher.encrypt_block(block);
    });
}

/// Transforms a page using XTS-AES (IEEE 1619-2007).
///
/// Each 16-byte block is transformed as `out = transform(in ⊕ T) ⊕ T`, where `T` is the
/// AES-encrypted tweak, advanced by one GF(2¹²⁸) multiplication per block.
///
/// The `transform` function is called with each block after the tweak is applied, and should
/// perform either AES encryption or decryption.
#[inline]
fn transform_page_xts<F>(
    page: &mut [u8; PAGE_SIZE],
    tweak: Tweak,
    tweak_cipher: &Aes128Enc,
    transform: F,
) where
    F: Fn(&mut aes::Block),
{
    // XTS requires the data length to be a multiple of the block size (16 bytes).
    const { assert!(PAGE_SIZE.is_multiple_of(16)) };

    // Every tweak in the iterator is calculated by applying `gf_mul_x` to the previous one.
    let tweaks = std::iter::successors(Some(tweak.encrypt(tweak_cipher)), |t| Some(gf_mul_x(*t)));

    for (block, tweak) in page.as_chunks_mut::<16>().0.iter_mut().zip(tweaks) {
        let mut out = u128::from_le_bytes(*block);

        out ^= tweak;
        out = {
            let mut buf = aes::Block::from(out.to_le_bytes());
            transform(&mut buf);
            u128::from_le_bytes(buf.0)
        };
        out ^= tweak;

        *block = out.to_le_bytes();
    }
}
