use crate::models::clep::*;

use zerocopy::{FromZeros, transmute, transmute_mut};

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

    return (obfuscatedv2, obfuscatedv4);
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

    const fn initial_state() -> u32 {
        // --- Key schedule: derive initial cipher state from hardcoded constants ---
        let k0 = !(Self::MAGIC_03.wrapping_mul(Self::MAGIC_HI.rotate_right(10)));
        let k1 = Self::MAGIC_04
            .wrapping_mul((k0 ^ Self::MAGIC_HI).rotate_right(22))
            .wrapping_sub(k0.rotate_right(8));
        let k2 = k0 ^ Self::MAGIC_04.wrapping_mul(k1.rotate_right(15) ^ Self::MAGIC_01);
        let k3 = k1
            ^ (k2 >> 9)
                .wrapping_add(Self::MAGIC_02.wrapping_mul((k2 ^ Self::MAGIC_03).rotate_left(3)));
        let k4 = k2
            ^ k3.rotate_right(28)
            ^ Self::MAGIC_03.wrapping_mul((k3 ^ Self::MAGIC_HI).rotate_right(9));
        let k5 = k3
            ^ k4.rotate_right(12).wrapping_add(
                Self::MAGIC_04.wrapping_mul(k4.wrapping_sub(Self::MAGIC_HI).rotate_right(14)),
            );
        let k6 = k4
            ^ k5.rotate_right(11)
            ^ Self::MAGIC_01.wrapping_mul((k5 ^ Self::MAGIC_02).rotate_left(2));
        let k7 = k5 ^ k6.wrapping_sub(Self::MAGIC_LO).wrapping_sub(Self::MAGIC_02);
        let k8 = k6
            ^ Self::MAGIC_03
                .wrapping_mul((k7 ^ Self::MAGIC_01).rotate_left(2))
                .wrapping_sub(k7.rotate_right(18));
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

        // 10 Feistel rounds
        let r0 = self.lo ^ block_lo;
        let r1 = self.hi
            ^ block_hi
            ^ Self::MAGIC_04
                .wrapping_mul(r0.wrapping_sub(Self::MAGIC_HI).rotate_right(18))
                .wrapping_sub(r0.rotate_right(9));
        let r2 = r0
            ^ Self::MAGIC_03
                .wrapping_mul((r1 ^ Self::MAGIC_01).rotate_left(2))
                .wrapping_sub(r1.rotate_right(18));
        let r3 = r1 ^ r2.wrapping_sub(Self::MAGIC_02).wrapping_sub(Self::MAGIC_LO);
        let r4 = r2
            ^ r3.rotate_right(11)
            ^ Self::MAGIC_01.wrapping_mul((r3 ^ Self::MAGIC_02).rotate_left(2));
        let r5 = r3
            ^ r4.rotate_right(12).wrapping_add(
                Self::MAGIC_04.wrapping_mul(r4.wrapping_sub(Self::MAGIC_HI).rotate_right(14)),
            );
        let r6 = r4
            ^ r5.rotate_right(28)
            ^ Self::MAGIC_03.wrapping_mul((r5 ^ Self::MAGIC_HI).rotate_right(9));
        let r7 = r5
            ^ (r6 >> 9)
                .wrapping_add(Self::MAGIC_02.wrapping_mul((r6 ^ Self::MAGIC_03).rotate_left(3)));
        let r8 = r6 ^ Self::MAGIC_04.wrapping_mul(r7.rotate_right(15) ^ Self::MAGIC_01);
        let r9 = r7
            ^ Self::MAGIC_04
                .wrapping_mul((r8 ^ Self::MAGIC_HI).rotate_right(22))
                .wrapping_sub(r8.rotate_right(8));

        // Output with CBC-like plaintext feedback
        let new_lo = pp_lo
            ^ r8
            ^ Self::MAGIC_03
                .wrapping_mul(r9.wrapping_add(Self::MAGIC_HI).rotate_right(10))
                .wrapping_sub(r9.rotate_right(29));
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    #[test]
    fn test_obfuscation() {
        let data = BASE64_STANDARD.decode("ARsBAAECAwRURVNUgAiBEM+htizwXQaZ3wYFBkJJT1MgbWFudWZhY3R1cmVyIGdvZXMgaGVyZSwgTHRkAFNPTUVJRAAzLjAAVG8gYmUgZmlsbGVkIGJ5IE8uRS5NLgBUbyBiZSBmaWxsZWQgYnkgTy5FLk0uAFRvIGJlIGZpbGxlZCBieSBPLkUuTS4AAA==").unwrap();
        let mut smbios = [0; 256];
        let disk_serial = [0; 64];
        smbios[..data.len()].copy_from_slice(&data);

        get_license_challange(smbios, disk_serial);
    }
}
