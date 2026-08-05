use zerocopy::{FromZeros, transmute, transmute_mut};

use crate::models::clep::*;

pub fn get_license_challange(smbios: [u8; 256], disk_serial: [u8; 64]) -> ([u8; 2048], [u8; 2048]) {
    let mut clepv2 = ClepV2::new_zeroed();
    clepv2.version = 2;
    clepv2.always_0 = 0;
    clepv2.always_1 = true;
    clepv2.smbios.copy_from_slice(&smbios);
    clepv2.disk_serial.copy_from_slice(&disk_serial);
    let mut clepv4 = ClepV4::new_zeroed();
    clepv4.version = 4;
    clepv4.debuger_not_present = 1;
    clepv4.smbios = smbios;
    clepv4.disk_serial = disk_serial;

    let mut obfuscatedv2 = transmute!(clepv2);
    let mut obfuscatedv4 = transmute!(clepv4);

    clep_obfuscate(&mut obfuscatedv2);
    clep_obfuscate(&mut obfuscatedv4);

    (obfuscatedv2, obfuscatedv4)
}

struct Cipher {
    lo: u32,
    hi: u32,

    plain: u64,
}

impl Cipher {
    const MAGIC: u64 = 0x2418_1621_4139_3243;

    const MAGIC_LO: u32 = Self::MAGIC as u32; // 0x41393243
    const MAGIC_HI: u32 = (Self::MAGIC >> 32) as u32; // 0x24181621

    const MAGIC_01: u32 = Self::MAGIC_HI >> 16; // 0x2418
    const MAGIC_02: u32 = Self::MAGIC_HI << 16 >> 16; // 0x1621
    const MAGIC_03: u32 = Self::MAGIC_LO >> 16; // 0x4139
    const MAGIC_04: u32 = Self::MAGIC_LO << 16 >> 16; // 0x3243

    const INITIAL_STATE: u32 = Cipher::initial_state();

    // The 8 round functions shared by the key schedule and the Feistel
    // cipher below: the key schedule walks them forward (round_1..round_8),
    // the cipher walks the same functions backward (round_8..round_1).
    #[inline]
    const fn round_1(x: u32) -> u32 {
        Self::MAGIC_04
            .wrapping_mul((x ^ Self::MAGIC_HI).rotate_right(22))
            .wrapping_sub(x.rotate_right(8))
    }

    #[inline]
    const fn round_2(x: u32) -> u32 {
        Self::MAGIC_04.wrapping_mul(x.rotate_right(15) ^ Self::MAGIC_01)
    }

    #[inline]
    const fn round_3(x: u32) -> u32 {
        (x >> 9).wrapping_add(Self::MAGIC_02.wrapping_mul((x ^ Self::MAGIC_03).rotate_left(3)))
    }

    #[inline]
    const fn round_4(x: u32) -> u32 {
        x.rotate_right(28) ^ Self::MAGIC_03.wrapping_mul((x ^ Self::MAGIC_HI).rotate_right(9))
    }

    #[inline]
    const fn round_5(x: u32) -> u32 {
        x.rotate_right(12).wrapping_add(
            Self::MAGIC_04.wrapping_mul(x.wrapping_sub(Self::MAGIC_HI).rotate_right(14)),
        )
    }

    #[inline]
    const fn round_6(x: u32) -> u32 {
        x.rotate_right(11) ^ Self::MAGIC_01.wrapping_mul((x ^ Self::MAGIC_02).rotate_left(2))
    }

    #[inline]
    const fn round_7(x: u32) -> u32 {
        x.wrapping_sub(Self::MAGIC_LO).wrapping_sub(Self::MAGIC_02)
    }

    #[inline]
    const fn round_8(x: u32) -> u32 {
        Self::MAGIC_03
            .wrapping_mul((x ^ Self::MAGIC_01).rotate_left(2))
            .wrapping_sub(x.rotate_right(18))
    }

    // Extra rounds used only by `encrypt_int`: `round_0` mixes the high
    // block word into the state, `whiten` produces the final output word.
    #[inline]
    const fn round_0(x: u32) -> u32 {
        Self::MAGIC_04
            .wrapping_mul(x.wrapping_sub(Self::MAGIC_HI).rotate_right(18))
            .wrapping_sub(x.rotate_right(9))
    }

    #[inline]
    const fn whiten(x: u32) -> u32 {
        Self::MAGIC_03
            .wrapping_mul(x.wrapping_add(Self::MAGIC_HI).rotate_right(10))
            .wrapping_sub(x.rotate_right(29))
    }

    /// Walks `rounds` in order, folding each round's output back into a
    /// 2-word Feistel state: `(a, b) -> (b, a ^ round(b))`.
    const fn run_rounds(a: u32, b: u32) -> (u32, u32) {
        let (a, b) = (b, a ^ Self::round_1(b));
        let (a, b) = (b, a ^ Self::round_2(b));
        let (a, b) = (b, a ^ Self::round_3(b));
        let (a, b) = (b, a ^ Self::round_4(b));
        let (a, b) = (b, a ^ Self::round_5(b));
        let (a, b) = (b, a ^ Self::round_6(b));
        let (a, b) = (b, a ^ Self::round_7(b));
        let (a, b) = (b, a ^ Self::round_8(b));
        (a, b)
    }

    /// Inverse of `run_rounds`: given the state produced by
    /// `run_rounds(a, b, rounds)`, recovers the original `(a, b)`.
    ///
    /// Each forward step `(a, b) -> (b, a ^ round(b))` is undone by
    /// `(a, b) -> (b ^ round(a), a)`, walking `rounds` back to front.
    const fn run_rounds_inverse(a: u32, b: u32) -> (u32, u32) {
        let (a, b) = (b ^ Self::round_8(a), a);
        let (a, b) = (b ^ Self::round_7(a), a);
        let (a, b) = (b ^ Self::round_6(a), a);
        let (a, b) = (b ^ Self::round_5(a), a);
        let (a, b) = (b ^ Self::round_4(a), a);
        let (a, b) = (b ^ Self::round_3(a), a);
        let (a, b) = (b ^ Self::round_2(a), a);
        let (a, b) = (b ^ Self::round_1(a), a);
        (a, b)
    }

    const fn initial_state() -> u32 {
        // --- Key schedule: derive initial cipher state from hardcoded constants ---
        let k0 = !(Self::MAGIC_03.wrapping_mul(Self::MAGIC_HI.rotate_right(10)));
        let (_, k8) = Self::run_rounds(0, k0);
        // let k9 = Self::MAGIC_04
        //    .wrapping_mul(k8.wrapping_sub(Self::MAGIC_HI).rotate_right(18))
        //    .wrapping_sub(k8.rotate_right(9));

        k8
    }

    pub const fn new(iv: u32) -> Self {
        Self {
            lo: Self::INITIAL_STATE ^ iv,
            hi: 0,
            plain: iv as u64,
        }
    }

    const fn encrypt_int(&mut self, block: u64) -> u64 {
        let block_lo = block as u32;
        let block_hi = (block >> 32) as u32;
        let pp_lo = self.plain as u32;
        let pp_hi = (self.plain >> 32) as u32;

        // 10 Feistel rounds: a seed round mixing in the high block word,
        // then the 8 shared round functions walked in reverse order
        // (round_8..round_1) relative to the key schedule.
        let r0 = self.lo ^ block_lo;
        let r1 = self.hi ^ block_hi ^ Self::round_0(r0);
        let (r8, r9) = Self::run_rounds_inverse(r0, r1);

        // Output with CBC-like plaintext feedback
        let new_lo = pp_lo ^ r8 ^ Self::whiten(r9);
        let new_hi = r9 ^ pp_hi;

        // Update cipher state
        self.lo = new_lo;
        self.hi = new_hi;
        self.plain = block;

        // Return the encrypted int by joining the new low and high
        (new_lo as u64) | ((new_hi as u64) << 32)
    }

    pub const fn encrypt_block(&mut self, block: &mut [u8; 8]) {
        let block_num = u64::from_le_bytes(*block);
        let encrypted = self.encrypt_int(block_num);
        *block = encrypted.to_le_bytes();
    }

    const fn decrypt_int(&mut self, block: u64) -> u64 {
        let new_lo = block as u32;
        let new_hi = (block >> 32) as u32;
        let old_lo = self.lo;
        let old_hi = self.hi;
        let pp_lo = self.plain as u32;
        let pp_hi = (self.plain >> 32) as u32;

        // Undo the output whitening to recover the post-round Feistel state
        let r9 = new_hi ^ pp_hi;
        let r8 = new_lo ^ pp_lo ^ Self::whiten(r9);

        // Undo the 8 shared rounds to recover the pre-round Feistel state
        let (r0, r1) = Self::run_rounds(r8, r9);

        // Undo the seed round to recover the plaintext block
        let block_lo = old_lo ^ r0;
        let block_hi = old_hi ^ r1 ^ Self::round_0(r0);
        let plain = (block_lo as u64) | ((block_hi as u64) << 32);

        // Update cipher state exactly as `encrypt_int` does
        self.lo = new_lo;
        self.hi = new_hi;
        self.plain = plain;

        plain
    }

    pub const fn decrypt_block(&mut self, block: &mut [u8; 8]) {
        let block_num = u64::from_le_bytes(*block);
        let decrypted = self.decrypt_int(block_num);
        *block = decrypted.to_le_bytes();
    }
}

/// Custom Feistel cipher used by CLEP to obfuscate the challenge request buffer.
///
/// Operates in a CBC-like mode on 8-byte blocks over the 2044-byte data region
/// (skipping the 4-byte version header)
pub fn clep_obfuscate(buffer: &mut [u8; 2048]) {
    // --- IV setup: XOR state with first data word, write back ---
    let blocks: &mut [[u8; 8]; 256] = transmute_mut!(buffer);
    let [_word1, word2]: &mut [[u8; 4]; 2] = transmute_mut!(&mut blocks[0]);

    let iv = u32::from_le_bytes(*word2);
    let mut cipher = Cipher::new(iv);

    *word2 = cipher.lo.to_le_bytes();

    // --- CBC-like encryption of 255 blocks (buffer[8..2048]) ---
    for block in blocks.iter_mut().skip(1) {
        cipher.encrypt_block(block);
    }
}

/// Inverse of [`clep_obfuscate`].
pub fn clep_deobfuscate(buffer: &mut [u8; 2048]) {
    // --- IV setup: recover the original IV that was XORed into word2 ---
    let blocks: &mut [[u8; 8]; 256] = transmute_mut!(buffer);
    let [_word1, word2]: &mut [[u8; 4]; 2] = transmute_mut!(&mut blocks[0]);

    let obfuscated_lo = u32::from_le_bytes(*word2);
    let iv = Cipher::INITIAL_STATE ^ obfuscated_lo;
    let mut cipher = Cipher::new(iv);

    *word2 = iv.to_le_bytes();

    // --- CBC-like decryption of 255 blocks (buffer[8..2048]) ---
    for block in blocks.iter_mut().skip(1) {
        cipher.decrypt_block(block);
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;

    use super::*;

    #[test]
    fn test_obfuscation() {
        let data = BASE64_STANDARD.decode("ARsBAAECAwRURVNUgAiBEM+htizwXQaZ3wYFBkJJT1MgbWFudWZhY3R1cmVyIGdvZXMgaGVyZSwgTHRkAFNPTUVJRAAzLjAAVG8gYmUgZmlsbGVkIGJ5IE8uRS5NLgBUbyBiZSBmaWxsZWQgYnkgTy5FLk0uAFRvIGJlIGZpbGxlZCBieSBPLkUuTS4AAA==").unwrap();
        let mut smbios = [0; 256];
        let disk_serial = [0; 64];
        smbios[..data.len()].copy_from_slice(&data);

        get_license_challange(smbios, disk_serial);
    }

    #[test]
    fn test_deobfuscation_round_trip() {
        let data = BASE64_STANDARD.decode("ARsBAAECAwRURVNUgAiBEM+htizwXQaZ3wYFBkJJT1MgbWFudWZhY3R1cmVyIGdvZXMgaGVyZSwgTHRkAFNPTUVJRAAzLjAAVG8gYmUgZmlsbGVkIGJ5IE8uRS5NLgBUbyBiZSBmaWxsZWQgYnkgTy5FLk0uAFRvIGJlIGZpbGxlZCBieSBPLkUuTS4AAA==").unwrap();
        let mut smbios = [0; 256];
        let disk_serial = [7u8; 64];
        smbios[..data.len()].copy_from_slice(&data);

        let (v2, v4) = get_license_challange(smbios, disk_serial);

        let mut v2_roundtrip = v2;
        clep_deobfuscate(&mut v2_roundtrip);
        let mut v4_roundtrip = v4;
        clep_deobfuscate(&mut v4_roundtrip);

        let mut clepv2 = ClepV2::new_zeroed();
        clepv2.version = 2;
        clepv2.always_0 = 0;
        clepv2.always_1 = true;
        clepv2.smbios.copy_from_slice(&smbios);
        clepv2.disk_serial.copy_from_slice(&disk_serial);
        let mut clepv4 = ClepV4::new_zeroed();
        clepv4.version = 4;
        clepv4.debuger_not_present = 1;
        clepv4.smbios = smbios;
        clepv4.disk_serial = disk_serial;

        let original_v2: [u8; 2048] = transmute!(clepv2);
        let original_v4: [u8; 2048] = transmute!(clepv4);

        assert_eq!(v2_roundtrip, original_v2);
        assert_eq!(v4_roundtrip, original_v4);
    }
}
