#![allow(dead_code)]

use ciborium::Value;
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum Xvc2Error {
    #[error("CBOR parse error: {0}")]
    Cbor(String),
    #[error("invalid CBOR tag: expected {expected}, got {actual}")]
    InvalidTag { expected: u64, actual: u64 },
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid label value: {0}")]
    InvalidLabel(i128),
    #[error("invalid enum value: {context}: {value}")]
    InvalidEnumValue { context: &'static str, value: i128 },
    #[error("ZIP error: {0}")]
    Zip(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("decompression error: {0}")]
    Decompression(String),
    #[error("hash validation failed")]
    HashValidation,
    #[error("invalid box header")]
    InvalidBoxHeader,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Label {
    Unknown = 0,
    Hash = 1,
    Length = 2,
    Compression = 3,
    CompressedLength = 4,
    EncryptionKey = 5,
    WrappedKey = 6,
    WrapIv = 7,
    BoxHash = 8,
    BoxIndex = 9,
    BoxOffset = 10,
    BoxLength = 11,
    Secondary = 12,
    Id = 24,
    Name = 25,
    SecretReference = 26,
    InitialIv = 27,
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

impl TryFrom<i128> for Label {
    type Error = Xvc2Error;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Label::Unknown),
            1 => Ok(Label::Hash),
            2 => Ok(Label::Length),
            3 => Ok(Label::Compression),
            4 => Ok(Label::CompressedLength),
            5 => Ok(Label::EncryptionKey),
            6 => Ok(Label::WrappedKey),
            7 => Ok(Label::WrapIv),
            8 => Ok(Label::BoxHash),
            9 => Ok(Label::BoxIndex),
            10 => Ok(Label::BoxOffset),
            11 => Ok(Label::BoxLength),
            12 => Ok(Label::Secondary),
            24 => Ok(Label::Id),
            25 => Ok(Label::Name),
            26 => Ok(Label::SecretReference),
            27 => Ok(Label::InitialIv),
            28 => Ok(Label::Files),
            29 => Ok(Label::Segments),
            30 => Ok(Label::Tags),
            31 => Ok(Label::Languages),
            32 => Ok(Label::Devices),
            33 => Ok(Label::RequiredToLaunch),
            34 => Ok(Label::KeyIndex),
            35 => Ok(Label::ChunkId),
            36 => Ok(Label::OnDemand),
            37 => Ok(Label::ReadProtected),
            256 => Ok(Label::FileFormat),
            257 => Ok(Label::MajorVersion),
            258 => Ok(Label::MinorVersion),
            259 => Ok(Label::Algorithm),
            260 => Ok(Label::ContentId),
            261 => Ok(Label::Version),
            262 => Ok(Label::Keys),
            263 => Ok(Label::Segmentation),
            264 => Ok(Label::Boxes),
            265 => Ok(Label::Chunks),
            266 => Ok(Label::Options),
            267 => Ok(Label::Build),
            268 => Ok(Label::Revision),
            269 => Ok(Label::BuildId),
            279 => Ok(Label::FulfillmentContentId),
            280 => Ok(Label::ProductId),
            281 => Ok(Label::MinimumSystemVersion),
            282 => Ok(Label::StoreId),
            283 => Ok(Label::SupportedPlatforms),
            284 => Ok(Label::DerivationAlgorithm),
            285 => Ok(Label::WrapAlgorithm),
            286 => Ok(Label::KdfContext),
            287 => Ok(Label::SourcePurpose),
            288 => Ok(Label::SourceKeyId),
            289 => Ok(Label::Target),
            290 => Ok(Label::WrittenBy),
            291 => Ok(Label::HashAlgorithm),
            292 => Ok(Label::OriginalBuildId),
            _ => Err(Xvc2Error::InvalidLabel(value)),
        }
    }
}

pub mod cbor_tag {
    pub const SELF_DESCRIBE: u64 = 55799;
    pub const SHA512: u64 = 18512;
    pub const SHA384: u64 = 18513;
    pub const SHA256: u64 = 18540;
    pub const XVC2: u64 = 1482048306;
    pub const XVCB: u64 = 1482048322;
    pub const XVCC: u64 = 1482048323;
    pub const XVCP: u64 = 1482048336;
    pub const XVCZ: u64 = 1482048346;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    None,
    Deflate,
    Brotli,
}

impl TryFrom<i128> for CompressionAlgorithm {
    type Error = Xvc2Error;
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CompressionAlgorithm::None),
            1 => Ok(CompressionAlgorithm::Deflate),
            2 => Ok(CompressionAlgorithm::Brotli),
            _ => Err(Xvc2Error::InvalidEnumValue {
                context: "CompressionAlgorithm",
                value,
            }),
        }
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    None,
    Sha256,
    Sha384,
    Sha512,
}

impl TryFrom<i128> for HashAlgorithm {
    type Error = Xvc2Error;
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HashAlgorithm::None),
            768 => Ok(HashAlgorithm::Sha256),
            769 => Ok(HashAlgorithm::Sha384),
            770 => Ok(HashAlgorithm::Sha512),
            _ => Err(Xvc2Error::InvalidEnumValue {
                context: "HashAlgorithm",
                value,
            }),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    None,
    Automatic,
    Aes256Cbc,
    Aes256Kw,
}

impl TryFrom<i128> for EncryptionAlgorithm {
    type Error = Xvc2Error;
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EncryptionAlgorithm::None),
            // Automatic mapping is not strictly defined in the integers provided, falling back
            256 => Ok(EncryptionAlgorithm::Aes256Cbc),
            257 => Ok(EncryptionAlgorithm::Aes256Kw),
            _ => Err(Xvc2Error::InvalidEnumValue {
                context: "EncryptionAlgorithm",
                value,
            }),
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationAlgorithm {
    None,
    Sp800108HmacSha256,
}

impl TryFrom<i128> for DerivationAlgorithm {
    type Error = Xvc2Error;
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DerivationAlgorithm::None),
            1024 => Ok(DerivationAlgorithm::Sp800108HmacSha256),
            _ => Err(Xvc2Error::InvalidEnumValue {
                context: "DerivationAlgorithm",
                value,
            }),
        }
    }
}

impl fmt::Display for DerivationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    Content,
    Version,
    PackageData,
}

impl TryFrom<i128> for KeyPurpose {
    type Error = Xvc2Error;
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyPurpose::Content),
            1 => Ok(KeyPurpose::Version),
            2 => Ok(KeyPurpose::PackageData),
            _ => Err(Xvc2Error::InvalidEnumValue {
                context: "KeyPurpose",
                value,
            }),
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentationAlgorithm {
    None,
    FastCdc,
    Fixed,
}

impl TryFrom<i128> for SegmentationAlgorithm {
    type Error = Xvc2Error;
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SegmentationAlgorithm::None),
            512 => Ok(SegmentationAlgorithm::FastCdc),
            513 => Ok(SegmentationAlgorithm::Fixed),
            _ => Err(Xvc2Error::InvalidEnumValue {
                context: "SegmentationAlgorithm",
                value,
            }),
        }
    }
}

impl fmt::Display for SegmentationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    None,
    Pc,
    ConsoleGen8,
    ConsoleGen9,
}

impl TryFrom<i128> for Platform {
    type Error = Xvc2Error;
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Platform::None),
            1 => Ok(Platform::Pc),
            2 => Ok(Platform::ConsoleGen8),
            3 => Ok(Platform::ConsoleGen9),
            _ => Err(Xvc2Error::InvalidEnumValue {
                context: "Platform",
                value,
            }),
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagingHash {
    pub algorithm: HashAlgorithm,
    pub hash: Vec<u8>,
}

impl Default for PackagingHash {
    fn default() -> Self {
        Self {
            algorithm: HashAlgorithm::None,
            hash: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackagingIv {
    pub counter0: u64,
    pub counter1: u64,
}

impl PackagingIv {
    pub const SIZE: usize = 16;

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut c1 = [0u8; 8];
        let mut c0 = [0u8; 8];
        if bytes.len() >= 16 {
            c1.copy_from_slice(&bytes[0..8]);
            c0.copy_from_slice(&bytes[8..16]);
        }
        Self {
            counter1: u64::from_be_bytes(c1),
            counter0: u64::from_be_bytes(c0),
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut res = [0u8; 16];
        res[0..8].copy_from_slice(&self.counter1.to_be_bytes());
        res[8..16].copy_from_slice(&self.counter0.to_be_bytes());
        res
    }

    pub fn increment(&self) -> Self {
        let (new_c0, carry) = self.counter0.overflowing_add(1);
        let new_c1 = if carry {
            self.counter1.wrapping_add(1)
        } else {
            self.counter1
        };
        Self {
            counter0: new_c0,
            counter1: new_c1,
        }
    }
}

impl Default for PackagingIv {
    fn default() -> Self {
        Self {
            counter0: 0,
            counter1: 0,
        }
    }
}

impl fmt::Display for PackagingIv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for b in bytes.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BoxIndex(pub i32);

impl fmt::Display for BoxIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct FileFormatInfo {
    pub written_by: Vec<String>,
    pub major_version: i32,
    pub minor_version: i32,
    pub build: i32,
}

#[derive(Debug, Clone)]
pub struct Xvc2Version {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub build_id: Uuid,
    pub original_build_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct Segmentation {
    pub algorithm: SegmentationAlgorithm,
    pub options: HashMap<i32, Value>,
    pub hash_algorithm: i32,
}

#[derive(Debug, Clone)]
pub struct SegmentReference {
    pub hash: PackagingHash,
    pub length: i32,
    pub compression: CompressionAlgorithm,
    pub compressed_length: i32,
    pub encryption_key: Option<Vec<u8>>,
    pub wrapped_key: Option<Vec<u8>>,
    pub wrap_iv: Option<PackagingIv>,
    pub box_hash: PackagingHash,
    pub box_index: BoxIndex,
    pub box_offset: i32,
    pub box_length: i32,
    pub secondary: bool,
}

#[derive(Debug, Clone)]
pub struct Xvc2File {
    pub id: i32,
    pub chunk_id: i32,
    pub iv: Option<PackagingIv>,
    pub length: i64,
    pub hash: PackagingHash,
    pub read_protected: bool,
    pub segments: Option<Vec<SegmentReference>>,
}

#[derive(Debug, Clone)]
pub struct FileSecret {
    pub file_name: String,
}

#[derive(Debug, Clone)]
pub struct ChunkDetails {
    pub files: Vec<Xvc2File>,
    pub id: i32,
    pub iv: Option<PackagingIv>,
}

#[derive(Debug, Clone)]
pub struct ChunkDetailsSecret {
    pub id: i32,
    pub files: Vec<FileSecret>,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub id: i32,
    pub on_demand: bool,
    pub required_to_launch: bool,
    pub key_index: i32,
    pub length: i64,
    pub box_length: i32,
    pub secret_reference: SegmentReference,
}

#[derive(Debug, Clone)]
pub struct BoxReference {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct BoxManifest {
    pub file_format: FileFormatInfo,
    pub name: String,
    pub segments: Vec<SegmentReference>,
}

#[derive(Debug, Clone)]
pub struct Seal {
    pub target: u64,
    pub hash: PackagingHash,
}

#[derive(Debug, Clone)]
pub struct PackageKeySource {
    pub source_key_id: Uuid,
    pub source_purpose: KeyPurpose,
    pub derivation_algorithm: DerivationAlgorithm,
    pub kdf_context: Vec<u8>,
    pub wrap_algorithm: EncryptionAlgorithm,
    pub wrap_iv: Option<PackagingIv>,
    pub wrapped_key: Vec<u8>,
    pub algorithm: EncryptionAlgorithm,
}

#[derive(Debug, Clone)]
pub struct PackageKey {
    pub sources: Vec<PackageKeySource>,
}

#[derive(Debug, Clone)]
pub struct Package {
    pub file_format: FileFormatInfo,
    pub content_id: Uuid,
    pub version: Xvc2Version,
    pub initial_iv: Option<PackagingIv>,
    pub keys: Vec<PackageKey>,
    pub segmentation: Segmentation,
    pub boxes: Vec<BoxReference>,
    pub chunks: Vec<Chunk>,
    pub fulfillment_content_id: Uuid,
    pub product_id: Uuid,
    pub minimum_system_version: Xvc2Version,
    pub store_id: String,
    pub supported_platforms: Platform,
}
