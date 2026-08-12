use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use uuid::Uuid;

use crate::cbor::{deserialize_box_manifest, deserialize_seal};
use crate::crypto::decrypt_segment_content;
use crate::models::*;
use crate::{MAX_BOX_SIZE, MAX_METADATA_SIZE, MAX_SEGMENT_SIZE};

/// Decompresses data using Brotli or Deflate algorithms.
pub fn decompress_content(
    compressed: &[u8],
    decompressed_len: usize,
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, Xvc2Error> {
    if decompressed_len > MAX_SEGMENT_SIZE {
        return Err(Xvc2Error::Decompression(
            "declared segment size exceeds the limit".into(),
        ));
    }

    fn read_exact_size<R: Read>(reader: R, expected: usize) -> Result<Vec<u8>, Xvc2Error> {
        let read_limit = expected
            .checked_add(1)
            .ok_or_else(|| Xvc2Error::Decompression("declared size is too large".into()))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(expected)
            .map_err(|_| Xvc2Error::Decompression("declared size is too large".into()))?;
        reader
            .take(
                u64::try_from(read_limit)
                    .map_err(|_| Xvc2Error::Decompression("declared size is too large".into()))?,
            )
            .read_to_end(&mut output)
            .map_err(|e| Xvc2Error::Decompression(e.to_string()))?;

        if output.len() != expected {
            return Err(Xvc2Error::Decompression(format!(
                "expected {expected} bytes, got {}",
                output.len()
            )));
        }
        Ok(output)
    }

    match compression {
        CompressionAlgorithm::None if compressed.len() == decompressed_len => {
            Ok(compressed.to_vec())
        }
        CompressionAlgorithm::None => Err(Xvc2Error::Decompression(format!(
            "expected {decompressed_len} bytes, got {}",
            compressed.len()
        ))),
        CompressionAlgorithm::Deflate => read_exact_size(
            flate2::read::DeflateDecoder::new(compressed),
            decompressed_len,
        ),
        CompressionAlgorithm::Brotli => read_exact_size(
            brotli::Decompressor::new(compressed, 4096),
            decompressed_len,
        ),
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
    if manifest_length > MAX_METADATA_SIZE {
        return Err(Xvc2Error::InvalidBoxHeader);
    }

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
    let trailer_start = stream_len - 12;
    if manifest_end > trailer_start {
        return Err(Xvc2Error::InvalidBoxHeader);
    }
    let seal_length = trailer_start - manifest_end;
    if seal_length > MAX_METADATA_SIZE {
        return Err(Xvc2Error::InvalidBoxHeader);
    }
    let seal_length = usize::try_from(seal_length).map_err(|_| Xvc2Error::InvalidBoxHeader)?;
    let mut seal_bytes = vec![0u8; seal_length];
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
) -> Result<Vec<u8>, Xvc2Error> {
    let start = usize::try_from(segment.box_offset).map_err(|_| Xvc2Error::InvalidBoxHeader)?;
    let box_length =
        usize::try_from(segment.box_length).map_err(|_| Xvc2Error::InvalidBoxHeader)?;
    let end = start
        .checked_add(box_length)
        .ok_or(Xvc2Error::InvalidBoxHeader)?;

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
        let iv_bytes =
            segment.hash.hash.get(..PackagingIv::SIZE).ok_or_else(|| {
                Xvc2Error::Crypto("segment hash is too short to derive an IV".into())
            })?;
        let iv = PackagingIv::from_bytes(iv_bytes);

        decrypted_storage = decrypt_segment_content(
            box_slice,
            &iv.to_bytes(),
            key_source,
            stored_material,
            segment.encryption_key.as_deref(),
            segment.wrapped_key.as_deref(),
            segment.wrap_iv.as_ref(),
        )?;
        &decrypted_storage[..]
    } else {
        box_slice
    };

    // 3. Decompress if compressed
    let content_length =
        usize::try_from(segment.length).map_err(|_| Xvc2Error::InvalidBoxHeader)?;
    if content_length > MAX_SEGMENT_SIZE {
        return Err(Xvc2Error::InvalidMetadata(
            "segment length exceeds the size limit".into(),
        ));
    }
    let content = if segment.compression != CompressionAlgorithm::None {
        let compressed_length =
            usize::try_from(segment.compressed_length).map_err(|_| Xvc2Error::InvalidBoxHeader)?;
        let compressed_slice = payload
            .get(..compressed_length)
            .ok_or(Xvc2Error::InvalidBoxHeader)?;
        decompress_content(compressed_slice, content_length, segment.compression)?
    } else {
        payload
            .get(..content_length)
            .ok_or(Xvc2Error::InvalidBoxHeader)?
            .to_vec()
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
) -> Result<Vec<u8>, Xvc2Error> {
    let box_offset = u64::try_from(segment.box_offset).map_err(|_| Xvc2Error::InvalidBoxHeader)?;
    box_stream.seek(SeekFrom::Start(box_offset))?;
    let box_length =
        usize::try_from(segment.box_length).map_err(|_| Xvc2Error::InvalidBoxHeader)?;
    if u64::try_from(box_length).map_err(|_| Xvc2Error::InvalidBoxHeader)? > MAX_BOX_SIZE {
        return Err(Xvc2Error::InvalidBoxHeader);
    }
    let mut box_content = vec![0u8; box_length];
    box_stream.read_exact(&mut box_content)?;

    // Delegate hash validation, decryption, decompression to zero-copy slice reader
    let mut temp_segment = segment.clone();
    temp_segment.box_offset = 0; // offset is now 0 relative to box_content buffer
    read_segment_content_from_slice(&box_content, &temp_segment, key_source, stored_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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

    #[test]
    fn decompression_rejects_an_incorrect_declared_size() {
        use std::io::Write;

        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"payload").unwrap();
        let compressed = encoder.finish().unwrap();

        assert!(decompress_content(&compressed, 3, CompressionAlgorithm::Deflate).is_err());
    }

    #[test]
    fn malformed_segment_bounds_return_an_error() {
        let segment = SegmentReference {
            hash: PackagingHash::default(),
            length: 1,
            compression: CompressionAlgorithm::None,
            compressed_length: 0,
            encryption_key: None,
            wrapped_key: None,
            wrap_iv: None,
            box_hash: PackagingHash::default(),
            box_index: BoxIndex(0),
            box_offset: -1,
            box_length: 1,
            secondary: false,
        };

        assert!(read_segment_content_from_slice(&[0], &segment, None, &HashMap::new(),).is_err());
    }

    #[test]
    fn oversized_manifest_is_rejected_before_allocation() {
        let mut box_bytes = vec![0u8; 20];
        box_bytes[..8].copy_from_slice(b"XBOXBOX\0");
        box_bytes[8..16].copy_from_slice(&8u64.to_le_bytes());
        box_bytes[16..20].copy_from_slice(&(MAX_METADATA_SIZE as u32 + 1).to_le_bytes());

        assert!(matches!(
            read_box_manifest_from_stream(Cursor::new(box_bytes)),
            Err(Xvc2Error::InvalidBoxHeader)
        ));
    }

    #[test]
    fn oversized_segment_is_rejected_before_decompression() {
        assert!(
            decompress_content(&[], MAX_SEGMENT_SIZE + 1, CompressionAlgorithm::Deflate,).is_err()
        );
    }
}
