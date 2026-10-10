use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;
use zip::ZipArchive;

use super::cbor::*;
use super::crypto::*;

#[derive(Error, Debug)]
pub enum Msixvc2Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("CBOR deserialization error: {0}")]
    Cbor(String),
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Invalid container: {0}")]
    InvalidContainer(String),
    #[error("Hash verification failed")]
    HashMismatch,
}

pub struct Msixvc2Archive<R: Read + Seek> {
    archive: ZipArchive<R>,
    package: Package,
    chunks: HashMap<u32, Chunk>,
    chunk_details: HashMap<u32, ChunkDetails>,
    chunk_secrets: HashMap<u32, ChunkDetailsSecret>,
    files: HashMap<String, FileEntry>,
    stored_keys: HashMap<Uuid, Vec<u8>>,
    cached_boxes: HashMap<u32, Vec<u8>>,
}

impl Msixvc2Archive<File> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Msixvc2Error> {
        let file = File::open(path)?;
        Self::new(file)
    }
}

impl<R: Read + Seek> Msixvc2Archive<R> {
    pub fn new(reader: R) -> Result<Self, Msixvc2Error> {
        let mut archive = ZipArchive::new(reader)?;

        // 1. Read XboxPackage.cbor using index_for_name to avoid borrow conflicts
        let package = {
            let idx = archive
                .index_for_name("XboxPackage.cbor")
                .or_else(|| archive.index_for_name("/XboxPackage.cbor"))
                .ok_or_else(|| {
                    Msixvc2Error::InvalidContainer("missing XboxPackage.cbor".to_string())
                })?;

            let mut entry = archive.by_index(idx)?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            parse::parse_package(&bytes).map_err(|e| Msixvc2Error::Cbor(e.to_string()))?
        };

        let mut chunks = HashMap::new();
        for chunk in &package.chunks {
            chunks.insert(chunk.id, chunk.clone());
        }

        let mut instance = Self {
            archive,
            package,
            chunks,
            chunk_details: HashMap::new(),
            chunk_secrets: HashMap::new(),
            files: HashMap::new(),
            stored_keys: HashMap::new(),
            cached_boxes: HashMap::new(),
        };

        // 2. Load chunk details
        instance.load_chunk_details()?;

        Ok(instance)
    }

    pub fn package(&self) -> &Package {
        &self.package
    }

    pub fn files(&self) -> &HashMap<String, FileEntry> {
        &self.files
    }

    /// Submit license keys acquired from Xbox licensing services
    pub fn submit_keys(&mut self, content_key: Option<&[u8]>, version_key: Option<&[u8]>) {
        if self.package.keys.is_empty() {
            return;
        }

        let sources = &self.package.keys[0].sources;

        if let Some(key) = content_key
            && let Some(source) = sources
                .iter()
                .find(|s| s.source_purpose == PackagingKeyPurpose::Content)
        {
            self.stored_keys.insert(source.source_key_id, key.to_vec());
        }

        if let Some(key) = version_key
            && let Some(source) = sources
                .iter()
                .find(|s| s.source_purpose == PackagingKeyPurpose::Version)
        {
            self.stored_keys.insert(source.source_key_id, key.to_vec());
        }
    }

    fn load_chunk_details(&mut self) -> Result<(), Msixvc2Error> {
        let chunk_ids: Vec<u32> = self.chunks.keys().copied().collect();

        for id in chunk_ids {
            let path1 = format!("Chunks/{}.cbor", id);
            let path2 = format!("/Chunks/{}.cbor", id);
            let idx = self
                .archive
                .index_for_name(&path1)
                .or_else(|| self.archive.index_for_name(&path2));

            if let Some(i) = idx {
                let mut entry = self.archive.by_index(i)?;
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                if let Ok(details) = parse::parse_chunk_details(&bytes) {
                    self.chunk_details.insert(id, details);
                }
            }
        }

        Ok(())
    }

    /// Loads filenames by reading and decrypting chunk secrets from zip entries or box segments
    pub fn load_filenames(&mut self) -> Result<(), Msixvc2Error> {
        let chunk_ids: Vec<u32> = self.chunks.keys().copied().collect();

        for id in chunk_ids {
            let path_sec1 = format!("Chunks/{}-secret.cbor", id);
            let path_sec2 = format!("/Chunks/{}-secret.cbor", id);
            let idx_sec = self
                .archive
                .index_for_name(&path_sec1)
                .or_else(|| self.archive.index_for_name(&path_sec2));

            let secret_opt = if let Some(i) = idx_sec {
                let mut entry = self.archive.by_index(i)?;
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                parse::parse_chunk_secret(&bytes).ok()
            } else if let Some(chunk) = self.chunks.get(&id).cloned() {
                if let Ok(bytes) = self.get_segment_content(
                    &chunk.secret_reference,
                    chunk.key_index,
                    PackagingKeyPurpose::Content,
                ) {
                    parse::parse_chunk_secret(&bytes).ok()
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(secret) = secret_opt {
                if let Some(details) = self.chunk_details.get(&id) {
                    for (i, file_entry) in details.files.iter().enumerate() {
                        if let Some(file_sec) = secret.files.get(i)
                            && !file_sec.file_name.is_empty()
                        {
                            let mut f = file_entry.clone();
                            f.chunk_id = id;
                            self.files.insert(file_sec.file_name.clone(), f);
                        }
                    }
                }
                self.chunk_secrets.insert(id, secret);
            }
        }

        Ok(())
    }

    /// Read raw box content
    fn read_box_content(
        &mut self,
        box_index: u32,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Msixvc2Error> {
        if let Some(box_data) = self.cached_boxes.get(&box_index) {
            let start = offset as usize;
            let end = (start + length).min(box_data.len());
            return Ok(box_data[start..end].to_vec());
        }

        let box_ref = self.package.boxes.get(box_index as usize).ok_or_else(|| {
            Msixvc2Error::InvalidContainer(format!("invalid box index {box_index}"))
        })?;

        let alt_name = format!("/{}", box_ref.name);
        let idx = self
            .archive
            .index_for_name(&box_ref.name)
            .or_else(|| self.archive.index_for_name(&alt_name))
            .ok_or_else(|| {
                Msixvc2Error::InvalidContainer(format!("failed to find box {}", box_ref.name))
            })?;

        let mut entry = self.archive.by_index(idx)?;
        let mut box_data = Vec::new();
        entry.read_to_end(&mut box_data)?;

        let start = offset as usize;
        let end = (start + length).min(box_data.len());
        let slice = box_data[start..end].to_vec();

        self.cached_boxes.insert(box_index, box_data);
        Ok(slice)
    }

    /// Read and decrypt segment content
    pub fn get_segment_content(
        &mut self,
        segment: &SegmentReference,
        key_id: u32,
        purpose: PackagingKeyPurpose,
    ) -> Result<Vec<u8>, Msixvc2Error> {
        let mut box_content =
            self.read_box_content(segment.box_index, segment.box_offset, segment.box_length)?;

        // Validate box content hash if present
        if let Some(expected_box_hash) = &segment.box_hash
            && !validate_hash(&box_content, expected_box_hash)
        {
            return Err(Msixvc2Error::HashMismatch);
        }

        // Decrypt if encrypted
        if segment.encryption_key.is_some() || segment.wrapped_key.is_some() {
            let mut iv = [0u8; 16];
            if segment.hash.hash.len() >= 16 {
                iv.copy_from_slice(&segment.hash.hash[..16]);
            }

            let decrypted = self.decrypt_content(
                &box_content,
                &iv,
                key_id,
                segment.encryption_key.as_deref(),
                segment.wrapped_key.as_deref(),
                purpose,
            )?;
            box_content = decrypted;
        }

        // Decompress if compressed
        let final_content = match segment.compression {
            PackagingCompression::Deflate => {
                let compressed_slice =
                    &box_content[..segment.compressed_length.min(box_content.len())];
                let mut decoder = flate2::read::DeflateDecoder::new(Cursor::new(compressed_slice));
                let mut decompressed = Vec::with_capacity(segment.length);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            PackagingCompression::None => {
                box_content.truncate(segment.length);
                box_content
            }
            PackagingCompression::Brotli => {
                return Err(Msixvc2Error::InvalidContainer(
                    "Brotli compression is not yet implemented".to_string(),
                ));
            }
        };

        Ok(final_content)
    }

    fn decrypt_content(
        &self,
        encrypted: &[u8],
        iv: &[u8; 16],
        key_id: u32,
        direct_key: Option<&[u8]>,
        wrapped_key: Option<&[u8]>,
        purpose: PackagingKeyPurpose,
    ) -> Result<Vec<u8>, Msixvc2Error> {
        let key_entry = self
            .package
            .keys
            .get(key_id as usize)
            .ok_or_else(|| Msixvc2Error::InvalidContainer(format!("key {key_id} not found")))?;

        let key_source = key_entry
            .sources
            .iter()
            .find(|s| s.source_purpose == purpose)
            .ok_or_else(|| {
                Msixvc2Error::InvalidContainer(format!("key source for {purpose:?} not found"))
            })?;

        let mut actual_key = direct_key.map(|k| k.to_vec());

        if let Some(wrapped) = wrapped_key {
            let master_key = self
                .stored_keys
                .get(&key_source.source_key_id)
                .ok_or_else(|| {
                    Msixvc2Error::InvalidContainer(format!(
                        "missing key material for {}",
                        key_source.source_key_id
                    ))
                })?;

            let wrapping_derived = derive_sp800_108(
                master_key,
                PackagingKeyPurpose::PackageData,
                key_source.wrap_algorithm,
                &key_source.kdf_context,
            )?;

            let intermediate_key = unwrap_key_material(&wrapping_derived, &key_source.wrapped_key)?;
            let intermediate_arr: [u8; 32] = intermediate_key
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength)?;

            let unwrapped = unwrap_key_material(&intermediate_arr, wrapped)?;
            actual_key = Some(unwrapped);
        }

        let key_material = actual_key.ok_or_else(|| {
            Msixvc2Error::InvalidContainer("no encryption key material available".to_string())
        })?;

        let key_arr: [u8; 32] = key_material
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        let decrypted = decrypt_aes_256_cbc(&key_arr, iv, encrypted)?;
        Ok(decrypted)
    }

    /// Extract all files in the package directly to a target directory on disk
    pub fn extract_all<P: AsRef<Path>>(&mut self, destination: P) -> Result<(), Msixvc2Error> {
        let dest = destination.as_ref();
        std::fs::create_dir_all(dest)?;

        // Ensure filenames are loaded
        if self.files.is_empty() {
            self.load_filenames()?;
        }

        let file_entries: Vec<(String, FileEntry)> = self
            .files
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (file_name, file_entry) in file_entries {
            let target_path = dest.join(file_name.replace('\\', "/"));
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut file_content = Vec::with_capacity(file_entry.length as usize);
            let chunk_key_index = self
                .chunks
                .get(&file_entry.chunk_id)
                .map(|c| c.key_index)
                .unwrap_or(0);

            for segment in &file_entry.segments {
                let seg_data = self.get_segment_content(
                    segment,
                    chunk_key_index,
                    PackagingKeyPurpose::Content,
                )?;
                file_content.extend_from_slice(&seg_data);
            }

            file_content.truncate(file_entry.length as usize);

            // Validate full file hash
            if !validate_hash(&file_content, &file_entry.hash) {
                return Err(Msixvc2Error::HashMismatch);
            }

            std::fs::write(&target_path, &file_content)?;
        }

        Ok(())
    }
}

fn validate_hash(data: &[u8], expected: &PackagingHash) -> bool {
    match expected.algorithm {
        PackagingHashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().as_slice() == expected.hash.as_slice()
        }
        PackagingHashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().as_slice() == expected.hash.as_slice()
        }
        PackagingHashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().as_slice() == expected.hash.as_slice()
        }
        PackagingHashAlgorithm::None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use ciborium::Value;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    #[test]
    fn test_synthetic_msixvc2_container_round_trip() {
        let master_key = [0x42u8; 32];
        let key_source_id = Uuid::new_v4();
        let kdf_context = b"test_kdf_context";

        // 1. Derive wrapping key
        let wrapping_derived = derive_sp800_108(
            &master_key,
            PackagingKeyPurpose::PackageData,
            PackagingEncryptionAlgorithm::Aes256Cbc,
            kdf_context,
        )
        .unwrap();

        // 2. Intermediate key & wrap it
        let intermediate_key = [0x33u8; 32];
        let kw_wrapping = aes_keywrap::Aes256KeyWrapAligned::new(&wrapping_derived);
        let wrapped_intermediate = kw_wrapping.encapsulate(&intermediate_key).unwrap();

        // 3. Segment encryption key & wrap it
        let segment_key = [0x77u8; 32];
        let kw_intermediate = aes_keywrap::Aes256KeyWrapAligned::new(&intermediate_key);
        let wrapped_segment = kw_intermediate.encapsulate(&segment_key).unwrap();

        // 4. Create plaintext Windows executable header (exactly 64 bytes)
        let plaintext = b"MZ\x90\x00This is a decrypted 64-byte Windows PE header from MSIXVC2!!";
        assert_eq!(plaintext.len(), 64);
        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        let file_hash = hasher.finalize().to_vec();

        // 5. Encrypt with AES-256-CBC
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&file_hash[..16]);
        let mut ciphertext = vec![0u8; plaintext.len()];
        Aes256CbcEnc::new((&segment_key).into(), (&iv).into())
            .encrypt_padded_b2b::<aes::cipher::block_padding::NoPadding>(plaintext, &mut ciphertext)
            .unwrap();

        // 6. Build in-memory CBOR: XboxPackage.cbor
        let mut pkg_map = Vec::new();
        // FileFormat (256)
        let ff_map = vec![
            (
                Value::Integer((SerializedLabel::MajorVersion as u64).into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Integer((SerializedLabel::MinorVersion as u64).into()),
                Value::Integer(0.into()),
            ),
        ];
        pkg_map.push((
            Value::Integer((SerializedLabel::FileFormat as u64).into()),
            Value::Map(ff_map),
        ));

        // ContentId (260)
        let content_id = Uuid::new_v4();
        pkg_map.push((
            Value::Integer((SerializedLabel::ContentId as u64).into()),
            Value::Bytes(content_id.as_bytes().to_vec()),
        ));

        // Version (261)
        let ver_map = vec![
            (
                Value::Integer((SerializedLabel::MajorVersion as u64).into()),
                Value::Integer(1.into()),
            ),
            (
                Value::Integer((SerializedLabel::MinorVersion as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::Build as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::Revision as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::BuildId as u64).into()),
                Value::Bytes(Uuid::new_v4().as_bytes().to_vec()),
            ),
        ];
        pkg_map.push((
            Value::Integer((SerializedLabel::Version as u64).into()),
            Value::Map(ver_map),
        ));

        // Keys (262)
        let src_map = vec![
            (
                Value::Integer((SerializedLabel::SourceKeyId as u64).into()),
                Value::Bytes(key_source_id.as_bytes().to_vec()),
            ),
            (
                Value::Integer((SerializedLabel::SourcePurpose as u64).into()),
                Value::Integer(0.into()),
            ), // Content
            (
                Value::Integer((SerializedLabel::DerivationAlgorithm as u64).into()),
                Value::Integer(1024.into()),
            ), // Sp800108
            (
                Value::Integer((SerializedLabel::KdfContext as u64).into()),
                Value::Bytes(kdf_context.to_vec()),
            ),
            (
                Value::Integer((SerializedLabel::WrapAlgorithm as u64).into()),
                Value::Integer(256.into()),
            ), // Aes256Cbc
            (
                Value::Integer((SerializedLabel::WrappedKey as u64).into()),
                Value::Bytes(wrapped_intermediate),
            ),
            (
                Value::Integer((SerializedLabel::Algorithm as u64).into()),
                Value::Integer(256.into()),
            ), // Aes256Cbc
        ];
        let keys_arr = Value::Array(vec![Value::Array(vec![Value::Map(src_map)])]);
        pkg_map.push((
            Value::Integer((SerializedLabel::Keys as u64).into()),
            keys_arr,
        ));

        // Segmentation (263)
        let seg_map = vec![(
            Value::Integer((SerializedLabel::Algorithm as u64).into()),
            Value::Integer(0.into()),
        )];
        pkg_map.push((
            Value::Integer((SerializedLabel::Segmentation as u64).into()),
            Value::Map(seg_map),
        ));

        // Boxes (264)
        let box_ref_map = vec![(
            Value::Integer((SerializedLabel::Name as u64).into()),
            Value::Text("box0".to_string()),
        )];
        pkg_map.push((
            Value::Integer((SerializedLabel::Boxes as u64).into()),
            Value::Array(vec![Value::Map(box_ref_map)]),
        ));

        // Secret segment for chunk
        let chunk_sec_map = vec![
            (
                Value::Integer((SerializedLabel::Hash as u64).into()),
                Value::Tag(18540, Box::new(Value::Bytes(file_hash.clone()))),
            ),
            (
                Value::Integer((SerializedLabel::Length as u64).into()),
                Value::Integer(64.into()),
            ),
        ];

        // Chunks (265)
        let chunk_map = vec![
            (
                Value::Integer((SerializedLabel::Id as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::Length as u64).into()),
                Value::Integer(64.into()),
            ),
            (
                Value::Integer((SerializedLabel::SecretReference as u64).into()),
                Value::Map(chunk_sec_map),
            ),
        ];
        pkg_map.push((
            Value::Integer((SerializedLabel::Chunks as u64).into()),
            Value::Array(vec![Value::Map(chunk_map)]),
        ));

        let mut pkg_cbor = Vec::new();
        ciborium::into_writer(&Value::Map(pkg_map), &mut pkg_cbor).unwrap();

        // 7. Build Chunks/0.cbor
        let seg_ref_map = vec![
            (
                Value::Integer((SerializedLabel::Hash as u64).into()),
                Value::Tag(18540, Box::new(Value::Bytes(file_hash.clone()))),
            ),
            (
                Value::Integer((SerializedLabel::Length as u64).into()),
                Value::Integer(64.into()),
            ),
            (
                Value::Integer((SerializedLabel::WrappedKey as u64).into()),
                Value::Bytes(wrapped_segment),
            ),
            (
                Value::Integer((SerializedLabel::BoxIndex as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::BoxOffset as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::BoxLength as u64).into()),
                Value::Integer(64.into()),
            ),
        ];

        let file_map = vec![
            (
                Value::Integer((SerializedLabel::Id as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::ChunkId as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::Length as u64).into()),
                Value::Integer(64.into()),
            ),
            (
                Value::Integer((SerializedLabel::Hash as u64).into()),
                Value::Tag(18540, Box::new(Value::Bytes(file_hash.clone()))),
            ),
            (
                Value::Integer((SerializedLabel::Segments as u64).into()),
                Value::Array(vec![Value::Map(seg_ref_map)]),
            ),
        ];

        let chunk0_map = vec![
            (
                Value::Integer((SerializedLabel::Id as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::Files as u64).into()),
                Value::Array(vec![Value::Map(file_map)]),
            ),
        ];

        let mut chunk0_cbor = Vec::new();
        ciborium::into_writer(&Value::Map(chunk0_map), &mut chunk0_cbor).unwrap();

        // 8. Build Chunks/0-secret.cbor
        let file_sec_map = vec![(
            Value::Integer((SerializedLabel::Name as u64).into()),
            Value::Text("bin/game.exe".to_string()),
        )];
        let secret_map = vec![
            (
                Value::Integer((SerializedLabel::Id as u64).into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Integer((SerializedLabel::Files as u64).into()),
                Value::Array(vec![Value::Map(file_sec_map)]),
            ),
        ];

        let mut secret_cbor = Vec::new();
        ciborium::into_writer(&Value::Map(secret_map), &mut secret_cbor).unwrap();

        // 9. Pack into in-memory ZIP
        let mut zip_buf = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut zip_buf);
            let opts = SimpleFileOptions::default();

            writer.start_file("XboxPackage.cbor", opts).unwrap();
            writer.write_all(&pkg_cbor).unwrap();

            writer.start_file("Chunks/0.cbor", opts).unwrap();
            writer.write_all(&chunk0_cbor).unwrap();

            writer.start_file("Chunks/0-secret.cbor", opts).unwrap();
            writer.write_all(&secret_cbor).unwrap();

            writer.start_file("box0", opts).unwrap();
            writer.write_all(&ciphertext).unwrap();

            writer.finish().unwrap();
        }

        // 10. Extract using our Msixvc2Archive implementation
        zip_buf.set_position(0);
        let mut archive = Msixvc2Archive::new(zip_buf).expect("archive opened ok");
        archive.submit_keys(Some(&master_key), None);

        let temp_dir = tempfile::tempdir().unwrap();
        archive
            .extract_all(temp_dir.path())
            .expect("extract_all succeeded");

        // 11. Verify extracted file
        let extracted_path = temp_dir.path().join("bin/game.exe");
        assert!(
            extracted_path.exists(),
            "extracted file bin/game.exe must exist"
        );
        let extracted_content = std::fs::read(&extracted_path).unwrap();
        assert_eq!(
            extracted_content, plaintext,
            "decrypted file content must match original plaintext"
        );
    }
}
