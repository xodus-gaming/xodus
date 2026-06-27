use crate::math::gf_mul_x;
use crate::models::xvd::{PAGE_SIZE, XvcRegionId};

use std::io::{self, Read, Seek, SeekFrom};
use std::iter;

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

pub trait PageSource: Read + Seek {}
impl<T: Read + Seek> PageSource for T {}

#[derive(Clone, Copy)]
pub struct Tweak([u8; 16]);

impl Tweak {
    pub fn new(data_unit: u32, header_id: XvcRegionId, vduid: [u8; 8]) -> Self {
        let mut buf = [0u8; 16];

        buf[0..4].copy_from_slice(&data_unit.to_le_bytes());
        buf[4..8].copy_from_slice(&header_id.to_le_bytes());
        buf[8..16].copy_from_slice(&vduid);

        Self(buf)
    }

    pub fn update_data_unit(&mut self, data_unit: u32) {
        self.0[0..4].copy_from_slice(&data_unit.to_le_bytes());
    }

    fn encrypt(self, tweak_cipher: &Aes128) -> u128 {
        let mut block = aes::Block::from(self.0);
        tweak_cipher.encrypt_block(&mut block);
        u128::from_le_bytes(block.0)
    }
}

pub struct SectionReader<R> {
    inner: R,
    section_offset: u64,
    section_length: u64,

    tweak: Tweak,
    tweak_cipher: Aes128,

    data_cipher: Aes128,

    // If integrity is enabled, this must contain one entry per page in the section.
    // If integrity is disabled, use page_in_section as the data unit instead.
    data_units: Option<Vec<u32>>,

    // simplest useful cache
    cached_page_index: Option<u64>,
    cached_page_plaintext: [u8; PAGE_SIZE],
}

impl<R: PageSource> SectionReader<R> {
    pub fn new(
        inner: R,
        section_offset: u64,
        section_length: u64,
        header_id: XvcRegionId,
        vduid: [u8; 8],
        full_key: [u8; 32],
        data_units: Option<Vec<u32>>,
    ) -> Self {
        let mut tweak_key = [0u8; 16];
        let mut data_key = [0u8; 16];
        tweak_key.copy_from_slice(&full_key[..16]);
        data_key.copy_from_slice(&full_key[16..]);

        Self {
            inner,
            section_offset,
            section_length,
            tweak: Tweak::new(0, header_id, vduid),
            tweak_cipher: Aes128::new((&tweak_key).into()),
            data_cipher: Aes128::new((&data_key).into()),
            data_units,
            cached_page_index: None,
            cached_page_plaintext: [0u8; PAGE_SIZE],
        }
    }

    pub fn read_at(&mut self, offset_in_section: u64, out: &mut [u8]) -> io::Result<()> {
        let end = offset_in_section
            .checked_add(out.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range overflow"))?;

        if end > self.section_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read exceeds section length",
            ));
        }

        let mut remaining = out.len();
        let mut dst_off = 0usize;
        let mut cur_off = offset_in_section;

        while remaining > 0 {
            let page_in_section = cur_off / PAGE_SIZE as u64;
            let in_page = (cur_off % PAGE_SIZE as u64) as usize;
            let copy_len = remaining.min(PAGE_SIZE - in_page);

            self.ensure_page_decrypted(page_in_section)?;
            out[dst_off..dst_off + copy_len]
                .copy_from_slice(&self.cached_page_plaintext[in_page..in_page + copy_len]);

            cur_off += copy_len as u64;
            dst_off += copy_len;
            remaining -= copy_len;
        }

        Ok(())
    }

    fn ensure_page_decrypted(&mut self, page_in_section: u64) -> io::Result<()> {
        if self.cached_page_index == Some(page_in_section) {
            return Ok(());
        }

        let file_offset = self
            .section_offset
            .checked_add(page_in_section * PAGE_SIZE as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow"))?;

        self.tweak.update_data_unit(match &self.data_units {
            Some(units) => *units
                .get(page_in_section as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing data unit"))?,
            None => page_in_section as u32,
        });

        let mut page = [0u8; PAGE_SIZE];
        self.inner.seek(SeekFrom::Start(file_offset))?;
        self.inner.read_exact(&mut page)?;

        decrypt_page_xts(&mut page, self.tweak, &self.tweak_cipher, &self.data_cipher);

        self.cached_page_plaintext = page;
        self.cached_page_index = Some(page_in_section);
        Ok(())
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
    tweak_cipher: &Aes128,
    data_cipher: &Aes128,
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
    tweak_cipher: &Aes128,
    data_cipher: &Aes128,
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
    tweak_cipher: &Aes128,
    transform: F,
) where
    F: Fn(&mut aes::Block),
{
    // XTS requires the data length to be a multiple of the block size (16 bytes).
    const { assert!(PAGE_SIZE.is_multiple_of(16)) };

    // Every tweak in the iterator is calculated by applying `gf_mul_x` to the previous one.
    let tweaks = iter::successors(Some(tweak.encrypt(tweak_cipher)), |t| Some(gf_mul_x(*t)));

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
