//! TODO: DOCS

use rsa::{BoxedUint, Error, PrivateKey, PublicKey, Result};

struct BlobReader<'a>(&'a [u8]);

impl BlobReader<'_> {
    /// Parse the next unsigned integer of size `n` from the blob, advancing it.
    fn parse_uint(&mut self, n: u32) -> Result<BoxedUint> {
        let (bytes, rest) = self
            .0
            .split_at_checked(n as usize)
            .ok_or(Error::InvalidArguments)?;

        self.0 = rest;
        Ok(BoxedUint::from_be_slice_vartime(bytes))
    }

    /// Advance the blob `n` bytes.
    fn skip(&mut self, n: u32) -> Result<()> {
        self.0 = self.0.get(n as usize..).ok_or(Error::InvalidArguments)?;
        Ok(())
    }
}

/// A Microsoft `BCRYPT_RSAKEY_BLOB` structure.
///
/// <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob>
struct RsaKeyBlob {
    magic: u32,
    _bit_length: u32,
    cb_public_exp: u32,
    cb_modulus: u32,
    cb_prime1: u32,
    cb_prime2: u32,
}

impl RsaKeyBlob {
    const PUBLIC_MAGIC: u32 = u32::from_le_bytes(*b"RSA1");
    const PRIVATE_MAGIC: u32 = u32::from_le_bytes(*b"RSA2");
    const FULLPRIVATE_MAGIC: u32 = u32::from_le_bytes(*b"RSA3");

    fn parse(header: &[u8; 24]) -> Self {
        let fields = header.as_chunks::<4>().0;
        let get_field = |i: usize| u32::from_le_bytes(fields[i]);

        Self {
            magic: get_field(0),
            _bit_length: get_field(1),
            cb_public_exp: get_field(2),
            cb_modulus: get_field(3),
            cb_prime1: get_field(4),
            cb_prime2: get_field(5),
        }
    }
}

fn parse_public(header: &RsaKeyBlob, mut reader: BlobReader<'_>) -> Result<PublicKey> {
    let public_exponent = reader.parse_uint(header.cb_public_exp)?;
    let modulus = reader.parse_uint(header.cb_modulus)?;

    PublicKey::new(modulus, public_exponent)
}

fn parse_private(header: &RsaKeyBlob, mut reader: BlobReader<'_>) -> Result<PrivateKey> {
    tracing::trace!("Got RSA Private");

    let e = reader.parse_uint(header.cb_public_exp)?;
    reader.skip(header.cb_modulus)?; // modulus
    let prime1 = reader.parse_uint(header.cb_prime1)?;
    let prime2 = reader.parse_uint(header.cb_prime2)?;

    // No private exponent in the blob, recompute it.
    PrivateKey::from_p_q(prime1, prime2, e)
}

fn parse_full_private(header: &RsaKeyBlob, mut reader: BlobReader<'_>) -> Result<PrivateKey> {
    tracing::error!(
        "TODO (BCRYPT_RSAFULLPRIVATE_BLOB) code path has not been tested and may cause follow up errors"
    );

    let e = reader.parse_uint(header.cb_public_exp)?;
    let modulus = reader.parse_uint(header.cb_modulus)?;
    let prime1 = reader.parse_uint(header.cb_prime1)?;
    let prime2 = reader.parse_uint(header.cb_prime2)?;
    reader.skip(header.cb_prime1)?; // exponent1
    reader.skip(header.cb_prime2)?; // exponent2
    reader.skip(header.cb_prime1)?; // coefficient
    let private_exponent = reader.parse_uint(header.cb_modulus)?;

    PrivateKey::from_components(modulus, e, private_exponent, vec![prime1, prime2])
}

fn split_blob(blob: &[u8]) -> Result<(RsaKeyBlob, BlobReader<'_>)> {
    let (header, blob) = blob.split_first_chunk().ok_or(Error::InvalidArguments)?;
    Ok((RsaKeyBlob::parse(header), BlobReader(blob)))
}

pub fn parse_rsa_public(blob: &[u8]) -> Result<PublicKey> {
    let (header, reader) = split_blob(blob)?;
    if header.magic != RsaKeyBlob::PUBLIC_MAGIC {
        return Err(Error::InvalidArguments);
    }

    parse_public(&header, reader)
}

pub fn parse_rsa_private(blob: &[u8]) -> Result<PrivateKey> {
    let (header, reader) = split_blob(blob)?;

    match header.magic {
        RsaKeyBlob::PRIVATE_MAGIC => parse_private(&header, reader),
        RsaKeyBlob::FULLPRIVATE_MAGIC => parse_full_private(&header, reader),
        _ => Err(Error::InvalidArguments),
    }
}
