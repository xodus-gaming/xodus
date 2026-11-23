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
    let u32_at = |o: usize| u32::from_le_bytes(blob[o..o + 4].try_into().unwrap());

    let magic = u32_at(0);
    let cb_pub_exp = u32_at(8);
    let cb_mod = u32_at(12);
    let cb_p1 = u32_at(16);
    let cb_p2 = u32_at(20);

    const RSAPRIVATE_MAGIC: u32 = u32::from_le_bytes(*b"RSA2");
    const RSAFULLPRIVATE_MAGIC: u32 = u32::from_le_bytes(*b"RSA3");

    let mut off = 24;
    let mut take = |n: u32| {
        let s = &blob[off..off + n as usize];
        off += n as usize;
        BoxedUint::from_be_slice_vartime(s)
    };

    let e = take(cb_pub_exp);
    let n = take(cb_mod);
    let p = take(cb_p1);
    let q = take(cb_p2);

    match magic {
        RSAFULLPRIVATE_MAGIC => {
            tracing::error!(
                "TODO (BCRYPT_RSAFULLPRIVATE_BLOB) code path has not been tested and may cause follow up errors"
            );

            // read d after p and q
            let _exp_p = take(cb_p1);
            let _exp_q = take(cb_p2);
            let _coefficient = take(cb_p1);
            let d = take(cb_mod);

            PrivateKey::from_components(n, e, d, vec![p, q])
        }
        RSAPRIVATE_MAGIC => {
            tracing::trace!("Got RSA Private");

            // No d in the blob, recompute it.
            PrivateKey::from_p_q(p, q, e)
        }
        _ => panic!("not an RSA private blob"),
    }
}
