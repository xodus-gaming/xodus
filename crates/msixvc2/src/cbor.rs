use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

pub const MAGIC_XBOXBOX: &[u8; 8] = b"XBOXBOX\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SerializedLabel {
    Unknown = 0,
    Hash = 1,
    Length = 2,
    Compression = 3,
    CompressedLength = 4,
    EncryptionKey = 5,
    WrappedKey = 6,
    WrapIV = 7,
    BoxHash = 8,
    BoxIndex = 9,
    BoxOffset = 10,
    BoxLength = 11,
    Secondary = 12,
    Id = 24,
    Name = 25,
    SecretReference = 26,
    InitialIV = 27,
    Files = 28,
    Segments = 29,
    Tags = 30,
    Languages = 31,
    Devices = 32,
    RequiredToLaunch = 33,
    KeyIndex = 34,
    ChunkId = 35,
    OnDemand = 36,
    ReadProtected = 37,
    FileFormat = 256,
    MajorVersion = 257,
    MinorVersion = 258,
    Algorithm = 259,
    ContentId = 260,
    Version = 261,
    Keys = 262,
    Segmentation = 263,
    Boxes = 264,
    Chunks = 265,
    Options = 266,
    Build = 267,
    Revision = 268,
    BuildId = 269,
    ContentKeyId = 270,
    VersionKeyId = 271,
    WrappedPackageKey = 272,
    Min = 273,
    Avg = 274,
    Max = 275,
    PackageUri = 276,
    FileName = 277,
    UserDataName = 278,
    FulfillmentContentId = 279,
    ProductId = 280,
    MinimumSystemVersion = 281,
    StoreId = 282,
    SupportedPlatforms = 283,
    DerivationAlgorithm = 284,
    WrapAlgorithm = 285,
    KdfContext = 286,
    SourcePurpose = 287,
    SourceKeyId = 288,
    Target = 289,
    WrittenBy = 290,
    HashAlgorithm = 291,
    OriginalBuildId = 292,
}

impl SerializedLabel {
    pub fn from_u64(val: u64) -> Self {
        match val {
            1 => Self::Hash,
            2 => Self::Length,
            3 => Self::Compression,
            4 => Self::CompressedLength,
            5 => Self::EncryptionKey,
            6 => Self::WrappedKey,
            7 => Self::WrapIV,
            8 => Self::BoxHash,
            9 => Self::BoxIndex,
            10 => Self::BoxOffset,
            11 => Self::BoxLength,
            12 => Self::Secondary,
            24 => Self::Id,
            25 => Self::Name,
            26 => Self::SecretReference,
            27 => Self::InitialIV,
            28 => Self::Files,
            29 => Self::Segments,
            30 => Self::Tags,
            31 => Self::Languages,
            32 => Self::Devices,
            33 => Self::RequiredToLaunch,
            34 => Self::KeyIndex,
            35 => Self::ChunkId,
            36 => Self::OnDemand,
            37 => Self::ReadProtected,
            256 => Self::FileFormat,
            257 => Self::MajorVersion,
            258 => Self::MinorVersion,
            259 => Self::Algorithm,
            260 => Self::ContentId,
            261 => Self::Version,
            262 => Self::Keys,
            263 => Self::Segmentation,
            264 => Self::Boxes,
            265 => Self::Chunks,
            266 => Self::Options,
            267 => Self::Build,
            268 => Self::Revision,
            269 => Self::BuildId,
            270 => Self::ContentKeyId,
            271 => Self::VersionKeyId,
            272 => Self::WrappedPackageKey,
            273 => Self::Min,
            274 => Self::Avg,
            275 => Self::Max,
            276 => Self::PackageUri,
            277 => Self::FileName,
            278 => Self::UserDataName,
            279 => Self::FulfillmentContentId,
            280 => Self::ProductId,
            281 => Self::MinimumSystemVersion,
            282 => Self::StoreId,
            283 => Self::SupportedPlatforms,
            284 => Self::DerivationAlgorithm,
            285 => Self::WrapAlgorithm,
            286 => Self::KdfContext,
            287 => Self::SourcePurpose,
            288 => Self::SourceKeyId,
            289 => Self::Target,
            290 => Self::WrittenBy,
            291 => Self::HashAlgorithm,
            292 => Self::OriginalBuildId,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborTagEx {
    Sha512 = 18512,
    Sha384 = 18513,
    Sha256 = 18540,
    LogicalAny = 32871,
    LogicalAll = 32872,
    Xvc2 = 1482048306,
    Xvcb = 1482048322,
    Xvcc = 1482048323,
    Xvcp = 1482048336,
    Xvcz = 1482048346,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializedAlgorithm {
    None,
    Deflate,
    Brotli,
    Aes256Cbc,
    Aes256Kw,
    FastCdc,
    Fixed,
    Sha256,
    Sha384,
    Sha512,
    Sp800108HmacSha256,
    Unknown(u64),
}

impl SerializedAlgorithm {
    pub fn from_u64(v: u64) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Deflate,
            2 => Self::Brotli,
            256 => Self::Aes256Cbc,
            257 => Self::Aes256Kw,
            512 => Self::FastCdc,
            513 => Self::Fixed,
            768 => Self::Sha256,
            769 => Self::Sha384,
            770 => Self::Sha512,
            1024 => Self::Sp800108HmacSha256,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagingCompression {
    None = 0,
    Deflate = 1,
    Brotli = 2,
}

impl PackagingCompression {
    pub fn from_algorithm(alg: SerializedAlgorithm) -> Self {
        match alg {
            SerializedAlgorithm::Deflate => Self::Deflate,
            SerializedAlgorithm::Brotli => Self::Brotli,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagingEncryptionAlgorithm {
    None = 0,
    Automatic = 1,
    Aes256Cbc = 2,
    Aes256Kw = 3,
}

impl PackagingEncryptionAlgorithm {
    pub fn from_algorithm(alg: SerializedAlgorithm) -> Self {
        match alg {
            SerializedAlgorithm::Aes256Cbc => Self::Aes256Cbc,
            SerializedAlgorithm::Aes256Kw => Self::Aes256Kw,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagingDerivationAlgorithm {
    None = 0,
    Sp800108HmacSha256 = 1,
}

impl PackagingDerivationAlgorithm {
    pub fn from_algorithm(alg: SerializedAlgorithm) -> Self {
        match alg {
            SerializedAlgorithm::Sp800108HmacSha256 => Self::Sp800108HmacSha256,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagingKeyPurpose {
    Content = 0,
    Version = 1,
    PackageData = 2,
}

impl PackagingKeyPurpose {
    pub fn from_u64(v: u64) -> Self {
        match v {
            1 => Self::Version,
            2 => Self::PackageData,
            _ => Self::Content,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentationAlgorithm {
    None = 0,
    FastCdc = 1,
    Fixed = 2,
}

impl SegmentationAlgorithm {
    pub fn from_algorithm(alg: SerializedAlgorithm) -> Self {
        match alg {
            SerializedAlgorithm::FastCdc => Self::FastCdc,
            SerializedAlgorithm::Fixed => Self::Fixed,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagingHashAlgorithm {
    None = 0,
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagingHash {
    pub algorithm: PackagingHashAlgorithm,
    pub hash: Vec<u8>,
}

impl PackagingHash {
    pub fn from_cbor_tag(tag: u64, bytes: Vec<u8>) -> Self {
        let algorithm = match tag {
            18540 => PackagingHashAlgorithm::Sha256,
            18513 => PackagingHashAlgorithm::Sha384,
            18512 => PackagingHashAlgorithm::Sha512,
            _ => PackagingHashAlgorithm::None,
        };
        Self {
            algorithm,
            hash: bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackagingIV {
    counter1: u64,
    counter0: u64,
}

impl PackagingIV {
    pub fn from_bytes(slice: &[u8]) -> Self {
        let mut c1 = 0u64;
        let mut c0 = 0u64;
        if slice.len() >= 16 {
            c1 = u64::from_be_bytes(slice[0..8].try_into().unwrap());
            c0 = u64::from_be_bytes(slice[8..16].try_into().unwrap());
        } else if slice.len() >= 8 {
            c0 = u64::from_be_bytes(slice[0..8].try_into().unwrap());
        }
        Self {
            counter1: c1,
            counter0: c0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&self.counter1.to_be_bytes());
        buf[8..16].copy_from_slice(&self.counter0.to_be_bytes());
        buf
    }

    pub fn increment(&mut self) {
        let prev = self.counter0;
        self.counter0 = self.counter0.wrapping_add(1);
        if prev > self.counter0 {
            self.counter1 = self.counter1.wrapping_add(1);
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileFormat {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub written_by: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PackageVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub build_id: Uuid,
    pub original_build_id: Option<Uuid>,
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision, self.build_id
        )
    }
}

#[derive(Debug, Clone)]
pub struct PackageKeySource {
    pub source_key_id: Uuid,
    pub source_purpose: PackagingKeyPurpose,
    pub derivation_algorithm: PackagingDerivationAlgorithm,
    pub kdf_context: Vec<u8>,
    pub wrap_algorithm: PackagingEncryptionAlgorithm,
    pub wrap_iv: Option<PackagingIV>,
    pub wrapped_key: Vec<u8>,
    pub algorithm: PackagingEncryptionAlgorithm,
}

#[derive(Debug, Clone)]
pub struct PackageKey {
    pub sources: Vec<PackageKeySource>,
}

#[derive(Debug, Clone)]
pub struct SegmentReference {
    pub hash: PackagingHash,
    pub length: usize,
    pub compression: PackagingCompression,
    pub compressed_length: usize,
    pub encryption_key: Option<Vec<u8>>,
    pub wrapped_key: Option<Vec<u8>>,
    pub wrap_iv: Option<PackagingIV>,
    pub box_hash: Option<PackagingHash>,
    pub box_index: u32,
    pub box_offset: u64,
    pub box_length: usize,
    pub secondary: bool,
}

#[derive(Debug, Clone)]
pub struct BoxReference {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct BoxManifest {
    pub file_format: FileFormat,
    pub name: String,
    pub segments: Vec<SegmentReference>,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub id: u32,
    pub length: u64,
    pub on_demand: bool,
    pub required_to_launch: bool,
    pub key_index: u32,
    pub box_length: u32,
    pub secret_reference: SegmentReference,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub id: u32,
    pub chunk_id: u32,
    pub iv: Option<PackagingIV>,
    pub length: u64,
    pub hash: PackagingHash,
    pub read_protected: bool,
    pub segments: Vec<SegmentReference>,
}

#[derive(Debug, Clone)]
pub struct ChunkDetails {
    pub id: u32,
    pub iv: Option<PackagingIV>,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone)]
pub struct FileSecret {
    pub file_name: String,
}

#[derive(Debug, Clone)]
pub struct ChunkDetailsSecret {
    pub id: u32,
    pub files: Vec<FileSecret>,
}

#[derive(Debug, Clone)]
pub struct Segmentation {
    pub algorithm: SegmentationAlgorithm,
    pub options: HashMap<u64, ciborium::Value>,
    pub hash_algorithm: u32,
}

#[derive(Debug, Clone)]
pub struct Package {
    pub file_format: FileFormat,
    pub content_id: Uuid,
    pub version: PackageVersion,
    pub initial_iv: Option<PackagingIV>,
    pub keys: Vec<PackageKey>,
    pub segmentation: Segmentation,
    pub boxes: Vec<BoxReference>,
    pub chunks: Vec<Chunk>,
    pub fulfillment_content_id: Uuid,
    pub product_id: Uuid,
    pub minimum_system_version: PackageVersion,
    pub store_id: String,
    pub supported_platforms: u32,
}

// Helper parsing routines for ciborium::Value maps
pub mod parse {
    use super::*;
    use ciborium::Value;

    pub fn get_map(val: &Value) -> Option<&Vec<(Value, Value)>> {
        match val {
            Value::Map(entries) => Some(entries),
            Value::Tag(_, inner) => get_map(inner),
            _ => None,
        }
    }

    pub fn get_label_val(entries: &[(Value, Value)], label: SerializedLabel) -> Option<&Value> {
        let target = label as u64;
        for (k, v) in entries {
            if let Value::Integer(i) = k {
                let u: Result<u64, _> = (*i).try_into();
                if let Ok(u) = u
                    && u == target
                {
                    return Some(v);
                }
            }
        }
        None
    }

    pub fn read_u64(val: &Value) -> Option<u64> {
        match val {
            Value::Integer(i) => (*i).try_into().ok(),
            _ => None,
        }
    }

    pub fn read_bool(val: &Value) -> Option<bool> {
        match val {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn read_str(val: &Value) -> Option<String> {
        match val {
            Value::Text(s) => Some(s.clone()),
            _ => None,
        }
    }

    pub fn read_bytes(val: &Value) -> Option<Vec<u8>> {
        match val {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        }
    }

    pub fn read_uuid(val: &Value) -> Option<Uuid> {
        match val {
            Value::Bytes(b) if b.len() == 16 => Uuid::from_slice(b).ok(),
            Value::Text(s) => Uuid::parse_str(s).ok(),
            _ => None,
        }
    }

    pub fn read_hash(val: &Value) -> Option<PackagingHash> {
        match val {
            Value::Tag(tag, inner) => {
                if let Value::Bytes(bytes) = &**inner {
                    Some(PackagingHash::from_cbor_tag(*tag, bytes.clone()))
                } else {
                    None
                }
            }
            Value::Bytes(bytes) => Some(PackagingHash {
                algorithm: PackagingHashAlgorithm::Sha256,
                hash: bytes.clone(),
            }),
            _ => None,
        }
    }

    pub fn parse_file_format(val: &Value) -> Option<FileFormat> {
        let entries = get_map(val)?;
        let major =
            get_label_val(entries, SerializedLabel::MajorVersion).and_then(read_u64)? as u32;
        let minor =
            get_label_val(entries, SerializedLabel::MinorVersion).and_then(read_u64)? as u32;
        let build = get_label_val(entries, SerializedLabel::Build)
            .and_then(read_u64)
            .unwrap_or(0) as u32;
        let mut written_by = Vec::new();
        if let Some(Value::Array(arr)) = get_label_val(entries, SerializedLabel::WrittenBy) {
            for item in arr {
                if let Some(s) = read_str(item) {
                    written_by.push(s);
                }
            }
        }
        Some(FileFormat {
            major,
            minor,
            build,
            written_by,
        })
    }

    pub fn parse_version(val: &Value) -> Option<PackageVersion> {
        let entries = get_map(val)?;
        let major =
            get_label_val(entries, SerializedLabel::MajorVersion).and_then(read_u64)? as u16;
        let minor =
            get_label_val(entries, SerializedLabel::MinorVersion).and_then(read_u64)? as u16;
        let build = get_label_val(entries, SerializedLabel::Build).and_then(read_u64)? as u16;
        let revision = get_label_val(entries, SerializedLabel::Revision).and_then(read_u64)? as u16;
        let build_id = get_label_val(entries, SerializedLabel::BuildId).and_then(read_uuid)?;
        let original_build_id =
            get_label_val(entries, SerializedLabel::OriginalBuildId).and_then(read_uuid);
        Some(PackageVersion {
            major,
            minor,
            build,
            revision,
            build_id,
            original_build_id,
        })
    }

    pub fn parse_segment_reference(
        val: &Value,
        rolling_iv: &mut Option<PackagingIV>,
    ) -> Option<SegmentReference> {
        let entries = get_map(val)?;
        let hash = get_label_val(entries, SerializedLabel::Hash).and_then(read_hash)?;
        let length = get_label_val(entries, SerializedLabel::Length).and_then(read_u64)? as usize;
        let compression = get_label_val(entries, SerializedLabel::Compression)
            .and_then(read_u64)
            .map(|a| PackagingCompression::from_algorithm(SerializedAlgorithm::from_u64(a)))
            .unwrap_or(PackagingCompression::None);
        let compressed_length = get_label_val(entries, SerializedLabel::CompressedLength)
            .and_then(read_u64)
            .map(|n| n as usize)
            .unwrap_or(length);

        let encryption_key =
            get_label_val(entries, SerializedLabel::EncryptionKey).and_then(read_bytes);
        let wrapped_key = get_label_val(entries, SerializedLabel::WrappedKey).and_then(read_bytes);
        let wrap_iv = get_label_val(entries, SerializedLabel::WrapIV)
            .and_then(read_bytes)
            .map(|b| PackagingIV::from_bytes(&b));

        let box_hash = get_label_val(entries, SerializedLabel::BoxHash).and_then(read_hash);
        let box_index = get_label_val(entries, SerializedLabel::BoxIndex)
            .and_then(read_u64)
            .unwrap_or(0) as u32;
        let box_offset = get_label_val(entries, SerializedLabel::BoxOffset)
            .and_then(read_u64)
            .unwrap_or(0);
        let box_length = get_label_val(entries, SerializedLabel::BoxLength)
            .and_then(read_u64)
            .map(|n| n as usize)
            .unwrap_or(length);
        let secondary = get_label_val(entries, SerializedLabel::Secondary)
            .and_then(read_bool)
            .unwrap_or(false);

        if let Some(iv) = rolling_iv {
            iv.increment();
        }

        Some(SegmentReference {
            hash,
            length,
            compression,
            compressed_length,
            encryption_key,
            wrapped_key,
            wrap_iv,
            box_hash,
            box_index,
            box_offset,
            box_length,
            secondary,
        })
    }

    pub fn parse_package_key_source(val: &Value) -> Option<PackageKeySource> {
        let entries = get_map(val)?;
        let source_key_id =
            get_label_val(entries, SerializedLabel::SourceKeyId).and_then(read_uuid)?;
        let source_purpose = get_label_val(entries, SerializedLabel::SourcePurpose)
            .and_then(read_u64)
            .map(PackagingKeyPurpose::from_u64)?;
        let derivation_algorithm = get_label_val(entries, SerializedLabel::DerivationAlgorithm)
            .and_then(read_u64)
            .map(|a| {
                PackagingDerivationAlgorithm::from_algorithm(SerializedAlgorithm::from_u64(a))
            })?;
        let kdf_context =
            get_label_val(entries, SerializedLabel::KdfContext).and_then(read_bytes)?;
        let wrap_algorithm = get_label_val(entries, SerializedLabel::WrapAlgorithm)
            .and_then(read_u64)
            .map(|a| {
                PackagingEncryptionAlgorithm::from_algorithm(SerializedAlgorithm::from_u64(a))
            })?;
        let wrap_iv = get_label_val(entries, SerializedLabel::WrapIV)
            .and_then(read_bytes)
            .map(|b| PackagingIV::from_bytes(&b));
        let wrapped_key =
            get_label_val(entries, SerializedLabel::WrappedKey).and_then(read_bytes)?;
        let algorithm = get_label_val(entries, SerializedLabel::Algorithm)
            .and_then(read_u64)
            .map(|a| {
                PackagingEncryptionAlgorithm::from_algorithm(SerializedAlgorithm::from_u64(a))
            })?;

        Some(PackageKeySource {
            source_key_id,
            source_purpose,
            derivation_algorithm,
            kdf_context,
            wrap_algorithm,
            wrap_iv,
            wrapped_key,
            algorithm,
        })
    }

    pub fn parse_package(
        bytes: &[u8],
    ) -> Result<Package, Box<dyn std::error::Error + Send + Sync>> {
        let root: Value = ciborium::from_reader(bytes)?;
        let entries = get_map(&root).ok_or("expected root map")?;

        let file_format = get_label_val(entries, SerializedLabel::FileFormat)
            .and_then(parse_file_format)
            .ok_or("missing or invalid FileFormat")?;

        let content_id = get_label_val(entries, SerializedLabel::ContentId)
            .and_then(read_uuid)
            .ok_or("missing ContentId")?;

        let version = get_label_val(entries, SerializedLabel::Version)
            .and_then(parse_version)
            .ok_or("missing Version")?;

        let initial_iv = get_label_val(entries, SerializedLabel::InitialIV)
            .and_then(read_bytes)
            .map(|b| PackagingIV::from_bytes(&b));

        let mut keys = Vec::new();
        if let Some(Value::Array(keys_arr)) = get_label_val(entries, SerializedLabel::Keys) {
            for key_item in keys_arr {
                if let Value::Array(sources_arr) = key_item {
                    let mut sources = Vec::new();
                    for s in sources_arr {
                        if let Some(src) = parse_package_key_source(s) {
                            sources.push(src);
                        }
                    }
                    keys.push(PackageKey { sources });
                }
            }
        }

        let seg_val =
            get_label_val(entries, SerializedLabel::Segmentation).ok_or("missing Segmentation")?;
        let seg_map = get_map(seg_val).ok_or("invalid Segmentation map")?;
        let seg_alg = get_label_val(seg_map, SerializedLabel::Algorithm)
            .and_then(read_u64)
            .map(|a| SegmentationAlgorithm::from_algorithm(SerializedAlgorithm::from_u64(a)))
            .unwrap_or(SegmentationAlgorithm::None);
        let hash_algorithm = get_label_val(seg_map, SerializedLabel::HashAlgorithm)
            .and_then(read_u64)
            .unwrap_or(0x301) as u32;

        let mut options = HashMap::new();
        if let Some(Value::Map(opt_map)) = get_label_val(seg_map, SerializedLabel::Options) {
            for (k, v) in opt_map {
                if let Some(u) = read_u64(k) {
                    options.insert(u, v.clone());
                }
            }
        }

        let segmentation = Segmentation {
            algorithm: seg_alg,
            options: options.into_iter().collect(),
            hash_algorithm,
        };

        let mut boxes = Vec::new();
        if let Some(Value::Array(box_arr)) = get_label_val(entries, SerializedLabel::Boxes) {
            for b in box_arr {
                if let Some(box_map) = get_map(b)
                    && let Some(name) =
                        get_label_val(box_map, SerializedLabel::Name).and_then(read_str)
                {
                    boxes.push(BoxReference { name });
                }
            }
        }

        let mut chunks = Vec::new();
        let mut rolling_iv = initial_iv;
        if let Some(Value::Array(chunk_arr)) = get_label_val(entries, SerializedLabel::Chunks) {
            for c in chunk_arr {
                if let Some(chunk_map) = get_map(c) {
                    let id = get_label_val(chunk_map, SerializedLabel::Id)
                        .and_then(read_u64)
                        .unwrap_or(0) as u32;
                    let length = get_label_val(chunk_map, SerializedLabel::Length)
                        .and_then(read_u64)
                        .unwrap_or(0);
                    let on_demand = get_label_val(chunk_map, SerializedLabel::OnDemand)
                        .and_then(read_bool)
                        .unwrap_or(false);
                    let required_to_launch =
                        get_label_val(chunk_map, SerializedLabel::RequiredToLaunch)
                            .and_then(read_bool)
                            .unwrap_or(false);
                    let key_index = get_label_val(chunk_map, SerializedLabel::KeyIndex)
                        .and_then(read_u64)
                        .unwrap_or(0) as u32;
                    let box_length = get_label_val(chunk_map, SerializedLabel::BoxLength)
                        .and_then(read_u64)
                        .unwrap_or(0) as u32;
                    let secret_ref_val = get_label_val(chunk_map, SerializedLabel::SecretReference)
                        .ok_or("missing SecretReference")?;
                    let secret_reference = parse_segment_reference(secret_ref_val, &mut rolling_iv)
                        .ok_or("invalid SecretReference")?;

                    chunks.push(Chunk {
                        id,
                        length,
                        on_demand,
                        required_to_launch,
                        key_index,
                        box_length,
                        secret_reference,
                    });
                }
            }
        }

        let fulfillment_content_id = get_label_val(entries, SerializedLabel::FulfillmentContentId)
            .and_then(read_uuid)
            .unwrap_or(content_id);
        let product_id = get_label_val(entries, SerializedLabel::ProductId)
            .and_then(read_uuid)
            .unwrap_or_default();
        let minimum_system_version = get_label_val(entries, SerializedLabel::MinimumSystemVersion)
            .and_then(parse_version)
            .unwrap_or_else(|| version.clone());
        let store_id = get_label_val(entries, SerializedLabel::StoreId)
            .and_then(read_str)
            .unwrap_or_default();
        let supported_platforms = get_label_val(entries, SerializedLabel::SupportedPlatforms)
            .and_then(read_u64)
            .unwrap_or(1) as u32;

        Ok(Package {
            file_format,
            content_id,
            version,
            initial_iv,
            keys,
            segmentation,
            boxes,
            chunks,
            fulfillment_content_id,
            product_id,
            minimum_system_version,
            store_id,
            supported_platforms,
        })
    }

    pub fn parse_box(
        bytes: &[u8],
    ) -> Result<BoxManifest, Box<dyn std::error::Error + Send + Sync>> {
        let root: Value = ciborium::from_reader(bytes)?;
        let entries = get_map(&root).ok_or("expected box map")?;

        let file_format = get_label_val(entries, SerializedLabel::FileFormat)
            .and_then(parse_file_format)
            .ok_or("missing FileFormat in box")?;
        let name = get_label_val(entries, SerializedLabel::Name)
            .and_then(read_str)
            .ok_or("missing Name in box")?;

        let mut segments = Vec::new();
        let mut dummy_iv = None;
        if let Some(Value::Array(seg_arr)) = get_label_val(entries, SerializedLabel::Segments) {
            for s in seg_arr {
                if let Some(seg) = parse_segment_reference(s, &mut dummy_iv) {
                    segments.push(seg);
                }
            }
        }

        Ok(BoxManifest {
            file_format,
            name,
            segments,
        })
    }

    pub fn parse_chunk_details(
        bytes: &[u8],
    ) -> Result<ChunkDetails, Box<dyn std::error::Error + Send + Sync>> {
        let root: Value = ciborium::from_reader(bytes)?;
        let entries = get_map(&root).ok_or("expected chunk details map")?;

        let id = get_label_val(entries, SerializedLabel::Id)
            .and_then(read_u64)
            .unwrap_or(0) as u32;
        let iv = get_label_val(entries, SerializedLabel::InitialIV)
            .and_then(read_bytes)
            .map(|b| PackagingIV::from_bytes(&b));

        let mut rolling_iv = iv;
        let mut files = Vec::new();
        if let Some(Value::Array(file_arr)) = get_label_val(entries, SerializedLabel::Files) {
            for f in file_arr {
                if let Some(f_entries) = get_map(f) {
                    let file_id = get_label_val(f_entries, SerializedLabel::Id)
                        .and_then(read_u64)
                        .unwrap_or(0) as u32;
                    let chunk_id = get_label_val(f_entries, SerializedLabel::ChunkId)
                        .and_then(read_u64)
                        .unwrap_or(id as u64) as u32;
                    let file_iv = get_label_val(f_entries, SerializedLabel::InitialIV)
                        .and_then(read_bytes)
                        .map(|b| PackagingIV::from_bytes(&b))
                        .or(rolling_iv);
                    let length = get_label_val(f_entries, SerializedLabel::Length)
                        .and_then(read_u64)
                        .unwrap_or(0);
                    let hash = get_label_val(f_entries, SerializedLabel::Hash)
                        .and_then(read_hash)
                        .unwrap_or(PackagingHash {
                            algorithm: PackagingHashAlgorithm::None,
                            hash: vec![],
                        });
                    let read_protected = get_label_val(f_entries, SerializedLabel::ReadProtected)
                        .and_then(read_bool)
                        .unwrap_or(false);

                    let mut segments = Vec::new();
                    if let Some(Value::Array(seg_arr)) =
                        get_label_val(f_entries, SerializedLabel::Segments)
                    {
                        for s in seg_arr {
                            if let Some(seg) = parse_segment_reference(s, &mut rolling_iv) {
                                segments.push(seg);
                            }
                        }
                    }

                    files.push(FileEntry {
                        id: file_id,
                        chunk_id,
                        iv: file_iv,
                        length,
                        hash,
                        read_protected,
                        segments,
                    });
                }
            }
        }

        Ok(ChunkDetails { id, iv, files })
    }

    pub fn parse_chunk_secret(
        bytes: &[u8],
    ) -> Result<ChunkDetailsSecret, Box<dyn std::error::Error + Send + Sync>> {
        let root: Value = ciborium::from_reader(bytes)?;
        let entries = get_map(&root).ok_or("expected chunk secret map")?;

        let id = get_label_val(entries, SerializedLabel::Id)
            .and_then(read_u64)
            .unwrap_or(0) as u32;
        let mut files = Vec::new();

        if let Some(Value::Array(files_arr)) = get_label_val(entries, SerializedLabel::Files) {
            for f in files_arr {
                if let Some(f_entries) = get_map(f) {
                    let file_name = get_label_val(f_entries, SerializedLabel::Name)
                        .or_else(|| get_label_val(f_entries, SerializedLabel::FileName))
                        .and_then(read_str)
                        .unwrap_or_default();
                    files.push(FileSecret { file_name });
                }
            }
        }

        Ok(ChunkDetailsSecret { id, files })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_file_format() {
        let entries = vec![
            (
                ciborium::Value::Integer((SerializedLabel::MajorVersion as u64).into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer((SerializedLabel::MinorVersion as u64).into()),
                ciborium::Value::Integer(2.into()),
            ),
            (
                ciborium::Value::Integer((SerializedLabel::Build as u64).into()),
                ciborium::Value::Integer(3.into()),
            ),
            (
                ciborium::Value::Integer((SerializedLabel::WrittenBy as u64).into()),
                ciborium::Value::Array(vec![ciborium::Value::Text("XboxGDK".to_string())]),
            ),
        ];
        let val = ciborium::Value::Map(entries);
        let ff = parse::parse_file_format(&val).expect("parsed ok");
        assert_eq!(ff.major, 1);
        assert_eq!(ff.minor, 2);
        assert_eq!(ff.build, 3);
        assert_eq!(ff.written_by, vec!["XboxGDK"]);
    }

    #[test]
    fn test_packaging_iv_counter() {
        let mut iv = PackagingIV::from_bytes(&[0u8; 16]);
        assert_eq!(iv.to_bytes(), [0u8; 16]);
        iv.increment();
        let bytes = iv.to_bytes();
        assert_eq!(bytes[15], 1);
    }
}
