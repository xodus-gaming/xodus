use num_bigint_dig::ModInverse;
use num_integer::Integer;
use rand::distr::{Alphanumeric, SampleString};
use rsa::{BigUint, RsaPrivateKey};

use crate::licensing::splicense::BCryptRsaBlock;

pub fn generate_suid() -> String {
    "S-1-5-21-0000000000-0000000000-0000000000-1001".to_string()
}

pub fn generate_string(length: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), length)
}

pub fn parse_bcrypt_rsa_private(blob: &BCryptRsaBlock) -> rsa::errors::Result<RsaPrivateKey> {
    let u32_at = |o: usize| u32::from_le_bytes(blob[o..o + 4].try_into().unwrap()) as usize;

    let magic = u32_at(0);
    let cb_pub_exp = u32_at(8);
    let cb_mod = u32_at(12);
    let cb_p1 = u32_at(16);
    let cb_p2 = u32_at(20);

    const RSAPRIVATE_MAGIC: usize = 0x3241_5352; // "RSA2"
    const RSAFULLPRIVATE_MAGIC: usize = 0x3341_5352; // "RSA3"

    let mut off = 24;
    // take returns both the parsed BigUint (for arithmetic) and a Vec<u8> copy of the raw bytes
    let mut take = |n: usize| {
        let s = &blob[off..off + n];
        off += n;
        (num_bigint_dig::BigUint::from_bytes_be(s), s.to_vec())
    };

    // use nb_* names for internal arithmetic BigUints and store raw bytes for conversion back
    let (e_nb, e_bytes) = take(cb_pub_exp);
    let (_n_nb, n_bytes) = take(cb_mod);
    let (p_nb, p_bytes) = take(cb_p1);
    let (q_nb, q_bytes) = take(cb_p2);

    match magic {
        RSAFULLPRIVATE_MAGIC => {
            log::trace!("Got RSA Full Private");
            // read d after p and q
            let (_d_nb, d_bytes) = take(cb_mod);
            // convert nb BigUints back to rsa::BigUint for API using original bytes
            let n_rsa = BigUint::from_bytes_be(&n_bytes);
            let e_rsa = BigUint::from_bytes_be(&e_bytes);
            let d_rsa = BigUint::from_bytes_be(&d_bytes);
            let p_rsa = BigUint::from_bytes_be(&p_bytes);
            let q_rsa = BigUint::from_bytes_be(&q_bytes);
            RsaPrivateKey::from_components(n_rsa, e_rsa, d_rsa, vec![p_rsa, q_rsa])
        }
        RSAPRIVATE_MAGIC => {
            log::trace!("Got RSA Private");
            // No d in the blob — recompute it.
            let one = num_bigint_dig::BigUint::from(1u32);
            let p1 = &p_nb - &one;
            let p2 = &q_nb - &one;
            let lambda = p1.lcm(&p2);
            let d_nb = e_nb.clone().mod_inverse(&lambda).expect("e not invertible");
            let d_rsa = BigUint::from_bytes_be(
                &d_nb
                    .to_biguint()
                    .expect("inverse should be positive")
                    .to_bytes_be(),
            );
            // convert nb BigUints back to rsa::BigUint for API using original bytes
            let n_rsa = BigUint::from_bytes_be(&n_bytes);
            let e_rsa = BigUint::from_bytes_be(&e_bytes);
            let p_rsa = BigUint::from_bytes_be(&p_bytes);
            let q_rsa = BigUint::from_bytes_be(&q_bytes);
            RsaPrivateKey::from_components(n_rsa, e_rsa, d_rsa, vec![p_rsa, q_rsa])
        }
        _ => panic!("not an RSA private blob"),
    }
}
