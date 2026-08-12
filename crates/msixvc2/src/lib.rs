pub mod cbor;
pub mod content;
pub mod crypto;
pub mod file;
pub mod models;

pub use file::Msixvc2File;

pub(crate) const MAX_METADATA_SIZE: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_BOX_SIZE: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_CACHED_BOX_BYTES: usize = 1024 * 1024 * 1024;
pub(crate) const MAX_SEGMENT_SIZE: usize = 512 * 1024 * 1024;
pub(crate) const MAX_FILE_SIZE: usize = 1024 * 1024 * 1024;
pub(crate) const MAX_EXTRACTION_SIZE: u64 = 16 * 1024 * 1024 * 1024;
