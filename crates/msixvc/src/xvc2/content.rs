use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use uuid::Uuid;

use crate::xvc2::cbor::{deserialize_box_manifest, deserialize_seal};
use crate::xvc2::crypto::decrypt_segment_content;
use crate::xvc2::models::*;

/// Decompresses data using Brotli or Deflate algorithms.
pub fn decompress_content(
    compressed: &[u8],
    decompressed_len: usize,
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, Xvc2Error> {
    match compression {
        CompressionAlgorithm::None => Ok(compressed.to_vec()),
        CompressionAlgorithm::Deflate => {
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            let mut decompressed = Vec::with_capacity(decompressed_len);
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| Xvc2Error::Decompression(format!("Deflate error: {e}")))?;
            Ok(decompressed)
        }
        CompressionAlgorithm::Brotli => {
            let mut decompressor = brotli::Decompressor::new(compressed, 4096);
            let mut decompressed = Vec::with_capacity(decompressed_len);
            decompressor
                .read_to_end(&mut decompressed)
                .map_err(|e| Xvc2Error::Decompression(format!("Brotli error: {e}")))?;
            Ok(decompressed)
        }
    }
}

/// Validates content hash against a PackagingHash descriptor.
pub fn validate_hash(content: &[u8], packaging_hash: &PackagingHash) -> Result<(), Xvc2Error> {
    match packaging_hash.algorithm {
        HashAlgorithm::None => Ok(()),
        HashAlgorithm::Sha256 => {
            let actual = Sha256::digest(content);
            if actual.as_slice() == packaging_hash.hash.as_slice() {
                Ok(())
            } else {
                Err(Xvc2Error::HashValidation)
            }
        }
        HashAlgorithm::Sha384 => {
            let actual = Sha384::digest(content);
            if actual.as_slice() == packaging_hash.hash.as_slice() {
                Ok(())
            } else {
                Err(Xvc2Error::HashValidation)
            }
        }
        HashAlgorithm::Sha512 => {
            let actual = Sha512::digest(content);
            if actual.as_slice() == packaging_hash.hash.as_slice() {
                Ok(())
            } else {
                Err(Xvc2Error::HashValidation)
            }
        }
    }
}

/// Reads and parses a box manifest and its seal from an open box stream.
pub fn read_box_manifest_from_stream<R: Read + Seek>(
    mut stream: R,
) -> Result<BoxManifest, Xvc2Error> {
    // Check total stream length
    let stream_len = stream.seek(SeekFrom::End(0))?;
    if stream_len < 20 {
        return Err(Xvc2Error::InvalidBoxHeader);
    }

    // Read header magic (8 bytes)
    stream.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 8];
    stream.read_exact(&mut header)?;
    if &header != b"XBOXBOX\0" {
        return Err(Xvc2Error::InvalidBoxHeader);
    }

    // Read manifest_offset (u64) and manifest_length (u32) at stream_len - 12
    stream.seek(SeekFrom::Start(stream_len - 12))?;
    let mut offset_bytes = [0u8; 8];
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut offset_bytes)?;
    stream.read_exact(&mut len_bytes)?;

    let manifest_offset = u64::from_le_bytes(offset_bytes);
    let manifest_length = u32::from_le_bytes(len_bytes) as u64;

    let manifest_end = manifest_offset
        .checked_add(manifest_length)
        .ok_or(Xvc2Error::InvalidBoxHeader)?;

    if manifest_end > stream_len {
        return Err(Xvc2Error::InvalidBoxHeader);
    }

    // Read manifest CBOR bytes
    stream.seek(SeekFrom::Start(manifest_offset))?;
    let mut manifest_bytes = vec![0u8; manifest_length as usize];
    stream.read_exact(&mut manifest_bytes)?;

    // Read seal CBOR bytes (between manifest_end and trailer offsets)
    let seal_length = stream_len.saturating_sub(manifest_end + 12);
    let mut seal_bytes = vec![0u8; seal_length as usize];
    stream.read_exact(&mut seal_bytes)?;

    // Parse seal and validate manifest hash
    let seal = deserialize_seal(&seal_bytes)?;
    if seal.target != cbor_tag::XVCB {
        return Err(Xvc2Error::Cbor("Seal did not target box manifest".into()));
    }
    validate_hash(&manifest_bytes, &seal.hash)?;

    // Parse box manifest
    deserialize_box_manifest(&manifest_bytes)
}

/// Reads, validates, decrypts, and decompresses segment content directly from an in-memory box slice (zero-copy box reading).
pub fn read_segment_content_from_slice(
    box_bytes: &[u8],
    segment: &SegmentReference,
    key_source: Option<&PackageKeySource>,
    stored_keys: &HashMap<Uuid, Vec<u8>>,
    purpose: KeyPurpose,
) -> Result<Vec<u8>, Xvc2Error> {
    let start = segment.box_offset as usize;
    let end = start + segment.box_length as usize;

    if end > box_bytes.len() {
        return Err(Xvc2Error::InvalidBoxHeader);
    }

    let box_slice = &box_bytes[start..end];

    // 1. Validate box content hash
    validate_hash(box_slice, &segment.box_hash)?;

    // 2. Decrypt content if encrypted
    let decrypted_storage;
    let payload = if segment.encryption_key.is_some() || segment.wrapped_key.is_some() {
        let stored_material = key_source
            .and_then(|ks| stored_keys.get(&ks.source_key_id))
            .map(|v| v.as_slice());
        let iv = PackagingIv::from_bytes(&segment.hash.hash[..16]);

        decrypted_storage = decrypt_segment_content(
            box_slice,
            &iv.to_bytes(),
            key_source,
            stored_material,
            segment.encryption_key.as_deref(),
            segment.wrapped_key.as_deref(),
            segment.wrap_iv.as_ref(),
            purpose,
        )?;
        &decrypted_storage[..]
    } else {
        box_slice
    };

    // 3. Decompress if compressed
    let content = if segment.compression != CompressionAlgorithm::None {
        let compressed_slice = &payload[..segment.compressed_length as usize];
        decompress_content(
            compressed_slice,
            segment.length as usize,
            segment.compression,
        )?
    } else {
        payload[..segment.length as usize].to_vec()
    };

    // 4. Validate decompressed/decrypted content hash
    validate_hash(&content, &segment.hash)?;

    Ok(content)
}

/// Reads, validates, decrypts, and decompresses segment content from a box stream.
pub fn read_segment_content<R: Read + Seek>(
    box_stream: &mut R,
    segment: &SegmentReference,
    key_source: Option<&PackageKeySource>,
    stored_keys: &HashMap<Uuid, Vec<u8>>,
    purpose: KeyPurpose,
) -> Result<Vec<u8>, Xvc2Error> {
    box_stream.seek(SeekFrom::Start(segment.box_offset as u64))?;
    let mut box_content = vec![0u8; segment.box_length as usize];
    box_stream.read_exact(&mut box_content)?;

    // Delegate hash validation, decryption, decompression to zero-copy slice reader
    let mut temp_segment = segment.clone();
    temp_segment.box_offset = 0; // offset is now 0 relative to box_content buffer
    read_segment_content_from_slice(
        &box_content,
        &temp_segment,
        key_source,
        stored_keys,
        purpose,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hash_none() {
        let hash = PackagingHash {
            algorithm: HashAlgorithm::None,
            hash: vec![],
        };
        assert!(validate_hash(b"test data", &hash).is_ok());
    }

    #[test]
    fn test_validate_hash_sha256() {
        let content = b"hello world";
        let digest = Sha256::digest(content).to_vec();
        let hash = PackagingHash {
            algorithm: HashAlgorithm::Sha256,
            hash: digest,
        };
        assert!(validate_hash(content, &hash).is_ok());

        let bad_hash = PackagingHash {
            algorithm: HashAlgorithm::Sha256,
            hash: vec![0u8; 32],
        };
        assert!(validate_hash(content, &bad_hash).is_err());
    }

    #[test]
    fn test_decompress_deflate() {
        use std::io::Write;
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"sample decompressed payload").unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed =
            decompress_content(&compressed, 27, CompressionAlgorithm::Deflate).unwrap();
        assert_eq!(decompressed, b"sample decompressed payload");
    }
}
