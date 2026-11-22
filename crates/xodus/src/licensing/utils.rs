use rand::distr::{Alphanumeric, SampleString};
use rsa::{BoxedUint, PrivateKey};

use crate::licensing::splicense::BCryptRsaBlock;

pub fn generate_suid() -> String {
    "S-1-5-21-0000000000-0000000000-0000000000-1001".to_string()
}

pub fn generate_string(length: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), length)
}

pub fn parse_bcrypt_rsa_private(blob: &BCryptRsaBlock) -> rsa::errors::Result<PrivateKey> {
    let u32_at = |o: usize| u32::from_le_bytes(blob[o..o + 4].try_into().unwrap()) as usize;

    let magic = u32_at(0);
    let cb_pub_exp = u32_at(8);
    let cb_mod = u32_at(12);
    let cb_p1 = u32_at(16);
    let cb_p2 = u32_at(20);

    const RSAPRIVATE_MAGIC: usize = 0x3241_5352; // "RSA2"
    const RSAFULLPRIVATE_MAGIC: usize = 0x3341_5352; // "RSA3"

    let mut off = 24;
    let mut take = |n: usize| {
        let s = &blob[off..off + n];
        off += n;
        BoxedUint::from_be_slice_truncated(s, n as u32 * 8)
    };

    let n_rsa = take(cb_mod);
    let e_rsa = take(cb_pub_exp);
    let p_rsa = take(cb_p1);
    let q_rsa = take(cb_p2);

    match magic {
        RSAFULLPRIVATE_MAGIC => {
            tracing::trace!("Got RSA Full Private");

            // read d after p and q
            let d_rsa = take(cb_mod);

            PrivateKey::from_components(n_rsa, e_rsa, d_rsa, vec![p_rsa, q_rsa])
        }
        RSAPRIVATE_MAGIC => {
            tracing::trace!("Got RSA Private");

            // No d in the blob, recompute it.
            PrivateKey::from_p_q(p_rsa, q_rsa, e_rsa)
        }
        _ => panic!("not an RSA private blob"),
    }
}
