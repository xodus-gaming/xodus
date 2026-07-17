use num_bigint_dig::ModInverse;
use rand::distr::{Alphanumeric, SampleString};
use rsa::{BigUint, RsaPrivateKey};

pub fn generate_suid() -> String {
    "S-1-5-21-0000000000-0000000000-0000000000-1001".to_string()
}

pub fn generate_string(length: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), length)
}

pub fn parse_bcrypt_rsa_private(blob: &[u8]) -> rsa::errors::Result<RsaPrivateKey> {
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
        BigUint::from_bytes_be(s)
    };

    let e = take(cb_pub_exp);
    let n = take(cb_mod);
    let p = take(cb_p1);
    let q = take(cb_p2);

    match magic {
        RSAFULLPRIVATE_MAGIC => {
            let _dp = take(cb_p1);
            let _dq = take(cb_p2);
            let _qinv = take(cb_p1);
            let d = take(cb_mod);
            RsaPrivateKey::from_components(n, e, d, vec![p, q])
        }
        RSAPRIVATE_MAGIC => {
            // No d in the blob — recompute it.
            let one = BigUint::from(1u32);
            let lambda = (&p - &one) * (&q - &one); // or lcm for stricter form
            let d = BigUint::from_bytes_be(&e.to_bytes_be())
                .mod_inverse(&lambda)
                .expect("e not invertible")
                .to_biguint()
                .unwrap();
            RsaPrivateKey::from_components(n, e, d, vec![p, q])
        }
        _ => panic!("not an RSA private blob"),
    }
}
