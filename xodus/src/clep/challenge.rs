use crate::models::clep::*;

use zerocopy::{FromZeros, transmute};

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

const MAGIC: u64 = 0x2418_1621_4139_3243;

const MAGIC_LO: u32 = MAGIC as u32; // 0x41393243
const MAGIC_HI: u32 = (MAGIC >> 32) as u32; // 0x24181621

const MAGIC_01: u32 = MAGIC_HI >> 16; // 0x2418
const MAGIC_02: u32 = MAGIC_HI << 16 >> 16; // 0x1621
const MAGIC_03: u32 = MAGIC_LO >> 16; // 0x4139
const MAGIC_04: u32 = MAGIC_LO << 16 >> 16; // 0x3243

/// Custom Feistel cipher used by CLEP to obfuscate the challenge request buffer.
///
/// Operates in a CBC-like mode on 8-byte blocks over the 2044-byte data region
/// (skipping the 4-byte version header)
pub fn clep_obfuscate(buffer: &mut [u8; 2048]) {
    // --- Key schedule: derive initial cipher state from hardcoded constants ---
    let k0 = !(MAGIC_03.wrapping_mul(MAGIC_HI.rotate_right(10)));
    let k1 = MAGIC_04
        .wrapping_mul((k0 ^ MAGIC_HI).rotate_right(22))
        .wrapping_sub(k0.rotate_right(8));
    let k2 = k0 ^ MAGIC_04.wrapping_mul(k1.rotate_right(15) ^ MAGIC_01);
    let k3 = k1 ^ (k2 >> 9).wrapping_add(MAGIC_02.wrapping_mul((k2 ^ MAGIC_03).rotate_left(3)));
    let k4 = k2 ^ k3.rotate_right(28) ^ MAGIC_03.wrapping_mul((k3 ^ MAGIC_HI).rotate_right(9));
    let k5 = k3
        ^ k4.rotate_right(12)
            .wrapping_add(MAGIC_04.wrapping_mul(k4.wrapping_sub(MAGIC_HI).rotate_right(14)));
    let k6 = k4 ^ k5.rotate_right(11) ^ MAGIC_01.wrapping_mul((k5 ^ MAGIC_02).rotate_left(2));
    let k7 = k5 ^ k6.wrapping_sub(MAGIC_LO).wrapping_sub(MAGIC_02);
    let k8 = k6
        ^ MAGIC_03
            .wrapping_mul((k7 ^ MAGIC_01).rotate_left(2))
            .wrapping_sub(k7.rotate_right(18));
    // let k9 = MAGIC_04
    //     .wrapping_mul(k8.wrapping_sub(MAGIC_HI).rotate_right(18))
    //     .wrapping_sub(k8.rotate_right(9));

    // Initial cipher state (two 32-bit halves)
    let mut state_lo: u32 = k8;
    // let mut state_hi: u32 = k7 ^ k9;

    // --- IV setup: XOR state with first data word, write back ---
    let iv = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
    state_lo ^= iv;
    // state_hi = 0; // high half of IV is zero

    buffer[4..8].copy_from_slice(&state_lo.to_le_bytes());

    // --- CBC-like encryption of 255 blocks (buffer[8..2048]) ---
    let mut prev_lo = state_lo;
    let mut prev_hi: u32 = 0;
    let mut prev_plain: u64 = iv as u64;

    for i in 0..255usize {
        let off = 8 + i * 8;
        let block = u64::from_le_bytes(buffer[off..off + 8].try_into().unwrap());
        let block_lo = block as u32;
        let block_hi = (block >> 32) as u32;
        let pp_lo = prev_plain as u32;
        let pp_hi = (prev_plain >> 32) as u32;

        // 10 Feistel rounds
        let r0 = prev_lo ^ block_lo;
        let r1 = prev_hi
            ^ block_hi
            ^ MAGIC_04
                .wrapping_mul(r0.wrapping_sub(MAGIC_HI).rotate_right(18))
                .wrapping_sub(r0.rotate_right(9));
        let r2 = r0
            ^ MAGIC_03
                .wrapping_mul((r1 ^ MAGIC_01).rotate_left(2))
                .wrapping_sub(r1.rotate_right(18));
        let r3 = r1 ^ r2.wrapping_sub(MAGIC_02).wrapping_sub(MAGIC_LO);
        let r4 = r2 ^ r3.rotate_right(11) ^ MAGIC_01.wrapping_mul((r3 ^ MAGIC_02).rotate_left(2));
        let r5 = r3
            ^ r4.rotate_right(12)
                .wrapping_add(MAGIC_04.wrapping_mul(r4.wrapping_sub(MAGIC_HI).rotate_right(14)));
        let r6 = r4 ^ r5.rotate_right(28) ^ MAGIC_03.wrapping_mul((r5 ^ MAGIC_HI).rotate_right(9));
        let r7 = r5 ^ (r6 >> 9).wrapping_add(MAGIC_02.wrapping_mul((r6 ^ MAGIC_03).rotate_left(3)));
        let r8 = r6 ^ MAGIC_04.wrapping_mul(r7.rotate_right(15) ^ MAGIC_01);
        let r9 = r7
            ^ MAGIC_04
                .wrapping_mul((r8 ^ MAGIC_HI).rotate_right(22))
                .wrapping_sub(r8.rotate_right(8));

        // Output with CBC-like plaintext feedback
        let new_lo = pp_lo
            ^ r8
            ^ MAGIC_03
                .wrapping_mul(r9.wrapping_add(MAGIC_HI).rotate_right(10))
                .wrapping_sub(r9.rotate_right(29));
        let new_hi = r9 ^ pp_hi;

        buffer[off..off + 4].copy_from_slice(&new_lo.to_le_bytes());
        buffer[off + 4..off + 8].copy_from_slice(&new_hi.to_le_bytes());

        prev_lo = new_lo;
        prev_hi = new_hi;
        prev_plain = block;
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
