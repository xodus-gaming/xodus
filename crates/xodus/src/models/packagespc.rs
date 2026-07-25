use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", untagged)]
pub enum PackageResponse {
    Found(PackageDetails),
    NotFound { package_found: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageDetails {
    pub package_found: bool,
    pub content_id: String,
    pub version_id: String,
    pub package_files: Vec<PackageFile>,
    pub version: String,
    // pub package_metadata: PackageMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_of_hashes: Option<String>,
    pub update_predownload: bool,
    pub availability_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageFile {
    pub content_id: String,
    pub version_id: String,
    pub file_name: String,
    pub file_size: i64,
    pub file_hash: String,
    pub key_blob: String,
    pub cdn_root_paths: Vec<String>,
    pub background_cdn_root_paths: Vec<String>,
    pub relative_url: String,
    pub update_type: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_version_id: Option<String>,
    pub license_usage_type: i32,
    pub modified_date: String,
}

impl Display for PackageFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} - {}", self.file_name, self.file_size))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageMetadata {
    pub estimated_total_download_size: i64,
    pub background_cdn_root_paths: Vec<String>,
    pub cdn_roots: Vec<String>,
    pub files: Vec<MetadataFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MetadataFile {
    pub name: String,
    pub size: i64,
    pub relative_url: String,
    pub license: String,
}
