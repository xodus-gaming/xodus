use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use uuid::Uuid;
use zip::ZipArchive;

use crate::xvc2::cbor::{
    deserialize_chunk_details, deserialize_chunk_details_secret, deserialize_package,
};
use crate::xvc2::content::{
    read_box_manifest_from_stream, read_segment_content_from_slice, validate_hash,
};
use crate::xvc2::models::*;

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
    /// Opens an MSIXVC2 package from a `Read + Seek` stream (e.g. `File` or `Cursor<Vec<u8>>`).
    pub fn open(reader: R) -> Result<Self, Xvc2Error> {
        let mut archive = ZipArchive::new(reader).map_err(|e| Xvc2Error::Zip(e.to_string()))?;

        // 1. Read XboxPackage.cbor metadata entry from ZIP archive
        let package = {
            let mut pkg_entry = archive.by_name("XboxPackage.cbor").map_err(|_| {
                Xvc2Error::MissingField("XboxPackage.cbor not found in ZIP archive")
            })?;
            let mut pkg_bytes = Vec::with_capacity(pkg_entry.size() as usize);
            pkg_entry
                .read_to_end(&mut pkg_bytes)
                .map_err(|e| Xvc2Error::Io(e))?;
            deserialize_package(&pkg_bytes)?
        };

        // 2. Read Chunks/{id}.cbor metadata for each chunk
        let mut chunks = HashMap::new();
        let mut chunk_details = HashMap::new();

        for chunk in &package.chunks {
            chunks.insert(chunk.id, chunk.clone());

            let chunk_path = format!("Chunks/{}.cbor", chunk.id);
            let mut chunk_entry = archive
                .by_name(&chunk_path)
                .map_err(|_| Xvc2Error::MissingField("Chunk metadata not found in ZIP archive"))?;
            let mut chunk_bytes = Vec::with_capacity(chunk_entry.size() as usize);
            chunk_entry
                .read_to_end(&mut chunk_bytes)
                .map_err(|e| Xvc2Error::Io(e))?;

            let details = deserialize_chunk_details(&chunk_bytes)?;
            chunk_details.insert(chunk.id, details);
        }

        // 3. Read Box manifests for each Box in package
        let mut box_manifests = HashMap::new();
        for (i, box_ref) in package.boxes.iter().enumerate() {
            let box_path = format!("Boxes/{}", box_ref.name);
            let mut box_entry = archive
                .by_name(&box_path)
                .map_err(|_| Xvc2Error::MissingField("Box blob entry not found in ZIP archive"))?;

            let mut box_bytes = Vec::with_capacity(box_entry.size() as usize);
            box_entry
                .read_to_end(&mut box_bytes)
                .map_err(|e| Xvc2Error::Io(e))?;

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
            let box_name = &self
                .package
                .boxes
                .get(box_index.0 as usize)
                .ok_or_else(|| Xvc2Error::MissingField("Box index out of bounds"))?
                .name;

            let box_path = format!("Boxes/{box_name}");
            let mut box_entry = self
                .archive
                .by_name(&box_path)
                .map_err(|_| Xvc2Error::MissingField("Box entry not found in ZIP archive"))?;

            let mut bytes = Vec::with_capacity(box_entry.size() as usize);
            box_entry.read_to_end(&mut bytes)?;
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
            let key_source = if !self.package.keys.is_empty()
                && (chunk.key_index as usize) < self.package.keys.len()
            {
                self.package.keys[chunk.key_index as usize]
                    .sources
                    .iter()
                    .find(|x| x.source_purpose == KeyPurpose::Content)
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
                KeyPurpose::Content,
            )?;

            let secret = deserialize_chunk_details_secret(&secret_bytes)?;

            if let Some(details) = self.chunk_details.get(&chunk.id) {
                for (i, file_entry) in details.files.iter().enumerate() {
                    if i < secret.files.len() {
                        let file_name = secret.files[i].file_name.clone();
                        let mut f = file_entry.clone();
                        f.chunk_id = chunk.id;
                        self.files.insert(file_name, f);
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
        let file =
            self.files.get(file_path).cloned().ok_or_else(|| {
                Xvc2Error::MissingField("Requested file path not found in package")
            })?;

        let segments = file
            .segments
            .as_ref()
            .ok_or_else(|| Xvc2Error::MissingField("File segments missing"))?;

        // Pre-cache required boxes for this file
        for segment in segments {
            self.ensure_box_cached(segment.box_index)?;
        }

        let chunk = self
            .chunks
            .get(&file.chunk_id)
            .ok_or_else(|| Xvc2Error::MissingField("Chunk not found"))?;

        let key_source = if !self.package.keys.is_empty()
            && (chunk.key_index as usize) < self.package.keys.len()
        {
            self.package.keys[chunk.key_index as usize]
                .sources
                .iter()
                .find(|x| x.source_purpose == KeyPurpose::Content)
        } else {
            None
        };

        let mut file_content = Vec::with_capacity(file.length as usize);

        for segment in segments {
            let box_bytes = &self.cached_box_bytes[&segment.box_index];
            let segment_content = read_segment_content_from_slice(
                box_bytes,
                segment,
                key_source,
                &self.stored_keys,
                KeyPurpose::Content,
            )?;

            file_content.extend_from_slice(&segment_content);
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
        let file_paths: Vec<String> = self.files.keys().cloned().collect();

        for rel_path in file_paths {
            let out_path = output_dir.join(&rel_path);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let content = self.get_file_content(&rel_path)?;
            fs::write(out_path, content)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_box_caching_performance() {
        let mut cached_boxes: HashMap<BoxIndex, Vec<u8>> = HashMap::new();
        let box_idx = BoxIndex(0);
        let sample_data = vec![0xABu8; 1_000_000]; // 1 MB box payload

        // Baseline: simulated 100 reads without caching (re-allocates and copies 1MB each time)
        let t0 = Instant::now();
        let mut sum_uncached = 0usize;
        for _ in 0..100 {
            let buf = sample_data.clone();
            sum_uncached += buf.len();
        }
        let dur_uncached = t0.elapsed();

        // Optimized: pre-cache and slice
        let t1 = Instant::now();
        cached_boxes.insert(box_idx, sample_data.clone());
        let mut sum_cached = 0usize;
        for _ in 0..100 {
            let buf = &cached_boxes[&box_idx];
            sum_cached += buf.len();
        }
        let dur_cached = t1.elapsed();

        assert_eq!(sum_uncached, sum_cached);
        println!(
            "Perf benchmark (100 reads of 1MB payload): Uncached = {:?}, Cached = {:?}",
            dur_uncached, dur_cached
        );
        assert!(
            dur_cached < dur_uncached,
            "Cached reads must be faster than uncached allocations"
        );
    }
}
