use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;
use zip::ZipArchive;

use crate::cbor::{
    deserialize_chunk_details, deserialize_chunk_details_secret, deserialize_package,
};
use crate::content::{
    read_box_manifest_from_stream, read_segment_content_from_slice, validate_hash,
};
use crate::models::*;
use crate::{
    MAX_BOX_SIZE, MAX_CACHED_BOX_BYTES, MAX_EXTRACTION_SIZE, MAX_FILE_SIZE, MAX_METADATA_SIZE,
};

/// Represents an opened MSIXVC2 package container (.msixvc v2 ZIP file).
pub struct Msixvc2File<R: Read + Seek> {
    archive: ZipArchive<R>,
    package: Package,
    chunks: HashMap<i32, Chunk>,
    chunk_details: HashMap<i32, ChunkDetails>,
    chunk_secrets: HashMap<i32, ChunkDetailsSecret>,
    files: HashMap<String, Xvc2File>,
    boxes: HashMap<BoxIndex, BoxManifest>,
    cached_box_bytes: HashMap<BoxIndex, Vec<u8>>,
    stored_keys: HashMap<Uuid, Vec<u8>>,
    loaded_file_names: bool,
}

impl Msixvc2File<File> {
    /// Opens an MSIXVC2 package from a filesystem path.
    pub fn open_path<P: AsRef<Path>>(path: P) -> Result<Self, Xvc2Error> {
        let file = File::open(path)?;
        Self::open(file)
    }
}

impl<R: Read + Seek> Msixvc2File<R> {
    fn remaining_box_cache(current_size: usize) -> Result<u64, Xvc2Error> {
        let remaining = MAX_CACHED_BOX_BYTES
            .checked_sub(current_size)
            .ok_or_else(|| Xvc2Error::InvalidMetadata("box cache exceeds the size limit".into()))?;
        u64::try_from(remaining)
            .map_err(|_| Xvc2Error::InvalidMetadata("box cache is too large".into()))
    }

    fn checked_file_length(length: i64) -> Result<usize, Xvc2Error> {
        let length = usize::try_from(length)
            .map_err(|_| Xvc2Error::InvalidMetadata("negative file length".into()))?;
        if length > MAX_FILE_SIZE {
            return Err(Xvc2Error::InvalidMetadata(
                "file length exceeds the size limit".into(),
            ));
        }
        Ok(length)
    }

    fn read_zip_entry(
        entry: &mut zip::read::ZipFile<'_>,
        limit: u64,
    ) -> Result<Vec<u8>, Xvc2Error> {
        if entry.size() > limit {
            return Err(Xvc2Error::InvalidMetadata(format!(
                "ZIP entry {} exceeds the size limit",
                entry.name()
            )));
        }

        let capacity = usize::try_from(entry.size())
            .map_err(|_| Xvc2Error::InvalidMetadata("ZIP entry is too large".into()))?;
        let read_limit = limit
            .checked_add(1)
            .ok_or_else(|| Xvc2Error::InvalidMetadata("ZIP entry limit is too large".into()))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| Xvc2Error::InvalidMetadata("ZIP entry is too large".into()))?;
        entry.by_ref().take(read_limit).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len())
            .map_err(|_| Xvc2Error::InvalidMetadata("ZIP entry is too large".into()))?
            > limit
        {
            return Err(Xvc2Error::InvalidMetadata(format!(
                "ZIP entry {} exceeds the size limit",
                entry.name()
            )));
        }
        Ok(bytes)
    }

    fn output_path(output_dir: &Path, file_name: &str) -> Result<PathBuf, Xvc2Error> {
        let relative = Path::new(file_name);
        if file_name.is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(Xvc2Error::InvalidPath(file_name.to_owned()));
        }
        Ok(output_dir.join(relative))
    }

    /// Opens an MSIXVC2 package from a `Read + Seek` stream (e.g. `File` or `Cursor<Vec<u8>>`).
    pub fn open(reader: R) -> Result<Self, Xvc2Error> {
        let mut archive = ZipArchive::new(reader).map_err(|e| Xvc2Error::Zip(e.to_string()))?;

        // 1. Read XboxPackage.cbor metadata entry from ZIP archive
        let package = {
            let mut pkg_entry = archive.by_name("XboxPackage.cbor").map_err(|_| {
                Xvc2Error::MissingField("XboxPackage.cbor not found in ZIP archive")
            })?;
            let pkg_bytes = Self::read_zip_entry(&mut pkg_entry, MAX_METADATA_SIZE)?;
            deserialize_package(&pkg_bytes)?
        };

        // 2. Read Chunks/{id}.cbor metadata for each chunk
        let mut chunks = HashMap::new();
        let mut chunk_details = HashMap::new();

        for chunk in &package.chunks {
            if chunks.insert(chunk.id, chunk.clone()).is_some() {
                return Err(Xvc2Error::InvalidMetadata(format!(
                    "duplicate chunk id: {}",
                    chunk.id
                )));
            }

            let chunk_path = format!("Chunks/{}.cbor", chunk.id);
            let mut chunk_entry = archive
                .by_name(&chunk_path)
                .map_err(|_| Xvc2Error::MissingField("Chunk metadata not found in ZIP archive"))?;
            let chunk_bytes = Self::read_zip_entry(&mut chunk_entry, MAX_METADATA_SIZE)?;

            let details = deserialize_chunk_details(&chunk_bytes)?;
            if details.id != chunk.id {
                return Err(Xvc2Error::InvalidMetadata(format!(
                    "chunk {} metadata contains id {}",
                    chunk.id, details.id
                )));
            }
            chunk_details.insert(chunk.id, details);
        }

        // 3. Read Box manifests for each Box in package
        let mut box_manifests = HashMap::new();
        for (i, box_ref) in package.boxes.iter().enumerate() {
            let box_path = format!("Boxes/{}", box_ref.name);
            let mut box_entry = archive
                .by_name(&box_path)
                .map_err(|_| Xvc2Error::MissingField("Box blob entry not found in ZIP archive"))?;

            let box_bytes = Self::read_zip_entry(&mut box_entry, MAX_BOX_SIZE)?;

            let box_cursor = Cursor::new(box_bytes);
            let manifest = read_box_manifest_from_stream(box_cursor)?;
            box_manifests.insert(BoxIndex(i as i32), manifest);
        }

        Ok(Self {
            archive,
            package,
            chunks,
            chunk_details,
            chunk_secrets: HashMap::new(),
            files: HashMap::new(),
            boxes: box_manifests,
            cached_box_bytes: HashMap::new(),
            stored_keys: HashMap::new(),
            loaded_file_names: false,
        })
    }

    /// Ensures uncompressed box bytes are loaded and cached in memory.
    pub fn ensure_box_cached(&mut self, box_index: BoxIndex) -> Result<(), Xvc2Error> {
        if !self.cached_box_bytes.contains_key(&box_index) {
            let package_box_index = usize::try_from(box_index.0)
                .map_err(|_| Xvc2Error::MissingField("Box index out of bounds"))?;
            let box_name = &self
                .package
                .boxes
                .get(package_box_index)
                .ok_or(Xvc2Error::MissingField("Box index out of bounds"))?
                .name;

            let box_path = format!("Boxes/{box_name}");
            let mut box_entry = self
                .archive
                .by_name(&box_path)
                .map_err(|_| Xvc2Error::MissingField("Box entry not found in ZIP archive"))?;

            let cached_size = self
                .cached_box_bytes
                .values()
                .try_fold(0usize, |total, value| total.checked_add(value.len()))
                .ok_or_else(|| Xvc2Error::InvalidMetadata("box cache is too large".into()))?;
            let remaining = Self::remaining_box_cache(cached_size)?;
            let bytes = Self::read_zip_entry(&mut box_entry, remaining.min(MAX_BOX_SIZE))?;
            self.cached_box_bytes.insert(box_index, bytes);
        }

        Ok(())
    }

    /// Access the parsed package metadata header.
    pub fn package(&self) -> &Package {
        &self.package
    }

    /// Access parsed box manifests map.
    pub fn box_manifests(&self) -> &HashMap<BoxIndex, BoxManifest> {
        &self.boxes
    }

    /// Access loaded files map (path -> Xvc2File).
    pub fn files(&self) -> &HashMap<String, Xvc2File> {
        &self.files
    }

    /// Returns true if file names have been decrypted and loaded.
    pub fn is_file_names_loaded(&self) -> bool {
        self.loaded_file_names
    }

    /// Submits raw key material for a specific Key ID (UUID).
    pub fn submit_key_material(&mut self, key_id: Uuid, key_material: Vec<u8>) {
        self.stored_keys.insert(key_id, key_material);
    }

    /// Submits content and/or version keys for package decryption.
    pub fn submit_keys(&mut self, content_key: Option<Vec<u8>>, version_key: Option<Vec<u8>>) {
        if self.package.keys.is_empty() {
            return;
        }

        let content_key_id = self.package.keys[0]
            .sources
            .iter()
            .find(|x| x.source_purpose == KeyPurpose::Content)
            .map(|x| x.source_key_id);

        let version_key_id = self.package.keys[0]
            .sources
            .iter()
            .find(|x| x.source_purpose == KeyPurpose::Version)
            .map(|x| x.source_key_id);

        if let (Some(ck), Some(key_id)) = (content_key, content_key_id) {
            self.submit_key_material(key_id, ck);
        }

        if let (Some(vk), Some(key_id)) = (version_key, version_key_id) {
            self.submit_key_material(key_id, vk);
        }
    }

    /// Decrypts chunk secrets and loads relative file names into `self.files`.
    pub fn load_file_names(&mut self) -> Result<(), Xvc2Error> {
        let chunk_list: Vec<Chunk> = self.chunks.values().cloned().collect();

        // Pre-cache all required box streams
        for chunk in &chunk_list {
            self.ensure_box_cached(chunk.secret_reference.box_index)?;
        }

        for chunk in chunk_list {
            let key_source = if let Ok(key_index) = usize::try_from(chunk.key_index) {
                self.package.keys.get(key_index).and_then(|key| {
                    key.sources
                        .iter()
                        .find(|source| source.source_purpose == KeyPurpose::Content)
                })
            } else {
                None
            };

            // Read secret reference content directly from cached box bytes
            let box_bytes = &self.cached_box_bytes[&chunk.secret_reference.box_index];
            let secret_bytes = read_segment_content_from_slice(
                box_bytes,
                &chunk.secret_reference,
                key_source,
                &self.stored_keys,
            )?;

            let secret = deserialize_chunk_details_secret(&secret_bytes)?;
            if secret.id != chunk.id {
                return Err(Xvc2Error::InvalidMetadata(format!(
                    "chunk {} secret contains id {}",
                    chunk.id, secret.id
                )));
            }

            if let Some(details) = self.chunk_details.get(&chunk.id) {
                if details.files.len() != secret.files.len() {
                    return Err(Xvc2Error::InvalidMetadata(format!(
                        "chunk {} file metadata count does not match its secret",
                        chunk.id
                    )));
                }
                for (file_entry, file_secret) in details.files.iter().zip(&secret.files) {
                    let file_name = file_secret.file_name.clone();
                    let mut f = file_entry.clone();
                    f.chunk_id = chunk.id;
                    if self.files.insert(file_name.clone(), f).is_some() {
                        return Err(Xvc2Error::InvalidMetadata(format!(
                            "duplicate file name: {file_name}"
                        )));
                    }
                }
            }

            self.chunk_secrets.insert(chunk.id, secret);
        }

        self.loaded_file_names = true;
        Ok(())
    }

    /// Extract and return the uncompressed bytes for a single file path in the package.
    pub fn get_file_content(&mut self, file_path: &str) -> Result<Vec<u8>, Xvc2Error> {
        let file = self
            .files
            .get(file_path)
            .cloned()
            .ok_or(Xvc2Error::MissingField(
                "Requested file path not found in package",
            ))?;

        let segments = file
            .segments
            .as_ref()
            .ok_or(Xvc2Error::MissingField("File segments missing"))?;

        // Pre-cache required boxes for this file
        for segment in segments {
            self.ensure_box_cached(segment.box_index)?;
        }

        let chunk = self
            .chunks
            .get(&file.chunk_id)
            .ok_or(Xvc2Error::MissingField("Chunk not found"))?;

        let key_source = if let Ok(key_index) = usize::try_from(chunk.key_index) {
            self.package.keys.get(key_index).and_then(|key| {
                key.sources
                    .iter()
                    .find(|source| source.source_purpose == KeyPurpose::Content)
            })
        } else {
            None
        };

        let expected_length = Self::checked_file_length(file.length)?;
        let mut file_content = Vec::new();
        file_content
            .try_reserve_exact(expected_length)
            .map_err(|_| Xvc2Error::InvalidMetadata("file length is too large".into()))?;

        for segment in segments {
            let box_bytes = &self.cached_box_bytes[&segment.box_index];
            let segment_content =
                read_segment_content_from_slice(box_bytes, segment, key_source, &self.stored_keys)?;

            if file_content.len().saturating_add(segment_content.len()) > expected_length {
                return Err(Xvc2Error::InvalidMetadata(format!(
                    "segments exceed the declared length of {file_path}"
                )));
            }
            file_content.extend_from_slice(&segment_content);
        }

        if file_content.len() != expected_length {
            return Err(Xvc2Error::InvalidMetadata(format!(
                "segments do not fill the declared length of {file_path}"
            )));
        }

        validate_hash(&file_content, &file.hash)?;
        Ok(file_content)
    }

    /// Extract all loaded package files to an output directory.
    pub fn extract_files<P: AsRef<Path>>(&mut self, output_dir: P) -> Result<(), Xvc2Error> {
        if !self.loaded_file_names {
            return Err(Xvc2Error::MissingField(
                "Cannot extract files without filenames loaded (call load_file_names first)",
            ));
        }

        let output_dir = output_dir.as_ref();
        let extraction_size = self.files.values().try_fold(0u64, |total, file| {
            let length = u64::try_from(Self::checked_file_length(file.length)?).map_err(|_| {
                Xvc2Error::InvalidMetadata("file length exceeds the size limit".into())
            })?;
            total
                .checked_add(length)
                .ok_or_else(|| Xvc2Error::InvalidMetadata("extraction size is too large".into()))
        })?;
        if extraction_size > MAX_EXTRACTION_SIZE {
            return Err(Xvc2Error::InvalidMetadata(
                "extraction size exceeds the limit".into(),
            ));
        }

        fs::create_dir_all(output_dir)?;
        let output_dir = output_dir.canonicalize()?;
        let file_paths: Vec<String> = self.files.keys().cloned().collect();

        for rel_path in file_paths {
            let out_path = Self::output_path(&output_dir, &rel_path)?;
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
                if !parent.canonicalize()?.starts_with(&output_dir) {
                    return Err(Xvc2Error::InvalidPath(rel_path));
                }
            }

            let content = self.get_file_content(&rel_path)?;
            File::options()
                .write(true)
                .create_new(true)
                .open(out_path)?
                .write_all(&content)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_path_rejects_paths_outside_the_destination() {
        let output = Path::new("/tmp/extracted");

        assert!(Msixvc2File::<Cursor<Vec<u8>>>::output_path(output, "../escape").is_err());
        assert!(Msixvc2File::<Cursor<Vec<u8>>>::output_path(output, "/tmp/escape").is_err());
        assert_eq!(
            Msixvc2File::<Cursor<Vec<u8>>>::output_path(output, "dir/file.bin").unwrap(),
            output.join("dir/file.bin")
        );
    }

    #[test]
    fn file_length_limit_is_checked_before_allocation() {
        assert!(Msixvc2File::<Cursor<Vec<u8>>>::checked_file_length(-1).is_err());
        assert!(
            Msixvc2File::<Cursor<Vec<u8>>>::checked_file_length(MAX_FILE_SIZE as i64 + 1).is_err()
        );
    }

    #[test]
    fn box_cache_limit_is_checked_before_allocation() {
        assert_eq!(
            Msixvc2File::<Cursor<Vec<u8>>>::remaining_box_cache(MAX_CACHED_BOX_BYTES).unwrap(),
            0
        );
        assert!(
            Msixvc2File::<Cursor<Vec<u8>>>::remaining_box_cache(MAX_CACHED_BOX_BYTES + 1).is_err()
        );
    }
}
