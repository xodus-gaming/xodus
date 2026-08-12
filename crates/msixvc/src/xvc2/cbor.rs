use super::models::*;
use ciborium::Value;
use std::collections::HashMap;
use uuid::Uuid;

pub fn parse_cbor_value(bytes: &[u8]) -> Result<Value, Xvc2Error> {
    ciborium::from_reader(bytes).map_err(|e| Xvc2Error::Cbor(e.to_string()))
}

fn unwrap_tag(val: &Value) -> Option<(u64, &Value)> {
    if let Value::Tag(tag, inner) = val {
        Some((*tag, inner.as_ref()))
    } else {
        None
    }
}

fn expect_tag(val: &Value, expected: u64) -> Result<&Value, Xvc2Error> {
    let mut current = val;

    // First unwrap self-describe if present
    if let Value::Tag(tag, inner) = current {
        if *tag == cbor_tag::SELF_DESCRIBE {
            current = inner.as_ref();
        }
    }

    if let Value::Tag(tag, inner) = current {
        if *tag == expected {
            return Ok(inner.as_ref());
        } else {
            return Err(Xvc2Error::InvalidTag {
                expected,
                actual: *tag,
            });
        }
    }

    Err(Xvc2Error::Cbor(format!(
        "Expected tag {}, found {:?}",
        expected, current
    )))
}

fn expect_map(val: &Value) -> Result<HashMap<Label, &Value>, Xvc2Error> {
    if let Value::Map(entries) = val {
        let mut map = HashMap::new();
        for (k, v) in entries {
            let key_int = expect_i128(k)?;
            let label = Label::try_from(key_int)?;
            map.insert(label, v);
        }
        Ok(map)
    } else {
        Err(Xvc2Error::Cbor("Expected map".to_string()))
    }
}

fn expect_text<'a>(val: &'a Value) -> Result<&'a str, Xvc2Error> {
    val.as_text()
        .ok_or_else(|| Xvc2Error::Cbor("Expected text".to_string()))
}

fn expect_bytes<'a>(val: &'a Value) -> Result<&'a [u8], Xvc2Error> {
    val.as_bytes()
        .ok_or_else(|| Xvc2Error::Cbor("Expected bytes".to_string()))
        .map(|v| v.as_slice())
}

fn expect_i128(val: &Value) -> Result<i128, Xvc2Error> {
    if let Value::Integer(i) = val {
        Ok((*i).into())
    } else {
        Err(Xvc2Error::Cbor("Expected integer".to_string()))
    }
}

fn expect_i64(val: &Value) -> Result<i64, Xvc2Error> {
    let i = expect_i128(val)?;
    i.try_into()
        .map_err(|_| Xvc2Error::Cbor("Integer out of bounds for i64".to_string()))
}

fn expect_i32(val: &Value) -> Result<i32, Xvc2Error> {
    let i = expect_i128(val)?;
    i.try_into()
        .map_err(|_| Xvc2Error::Cbor("Integer out of bounds for i32".to_string()))
}

#[allow(dead_code)]
fn expect_u32(val: &Value) -> Result<u32, Xvc2Error> {
    let i = expect_i128(val)?;
    i.try_into()
        .map_err(|_| Xvc2Error::Cbor("Integer out of bounds for u32".to_string()))
}

fn expect_u16(val: &Value) -> Result<u16, Xvc2Error> {
    let i = expect_i128(val)?;
    i.try_into()
        .map_err(|_| Xvc2Error::Cbor("Integer out of bounds for u16".to_string()))
}

fn expect_bool(val: &Value) -> Result<bool, Xvc2Error> {
    val.as_bool()
        .ok_or_else(|| Xvc2Error::Cbor("Expected bool".to_string()))
}

fn expect_guid(val: &Value) -> Result<uuid::Uuid, Xvc2Error> {
    let text = expect_text(val)?;
    Uuid::parse_str(text).map_err(|e| Xvc2Error::Cbor(format!("Invalid GUID: {}", e)))
}

fn expect_hash(val: &Value) -> Result<PackagingHash, Xvc2Error> {
    if let Some((tag, inner)) = unwrap_tag(val) {
        let algo = match tag {
            cbor_tag::SHA256 => HashAlgorithm::Sha256,
            cbor_tag::SHA384 => HashAlgorithm::Sha384,
            cbor_tag::SHA512 => HashAlgorithm::Sha512,
            _ => {
                return Err(Xvc2Error::InvalidTag {
                    expected: cbor_tag::SHA256,
                    actual: tag,
                });
            }
        };
        let bytes = expect_bytes(inner)?;
        Ok(PackagingHash {
            algorithm: algo,
            hash: bytes.to_vec(),
        })
    } else {
        Err(Xvc2Error::Cbor("Expected tagged hash".to_string()))
    }
}

fn expect_array<'a>(val: &'a Value) -> Result<&'a [Value], Xvc2Error> {
    val.as_array()
        .map(|v| v.as_slice())
        .ok_or_else(|| Xvc2Error::Cbor("Expected array".to_string()))
}

fn expect_iv(val: &Value) -> Result<PackagingIv, Xvc2Error> {
    let bytes = expect_bytes(val)?;
    Ok(PackagingIv::from_bytes(bytes))
}

fn parse_segment_reference(
    val: &Value,
    rolling_iv: &mut Option<PackagingIv>,
) -> Result<SegmentReference, Xvc2Error> {
    let map = expect_map(val)?;

    let hash = if let Some(h) = map.get(&Label::Hash) {
        expect_hash(h)?
    } else {
        PackagingHash::default()
    };

    let length = map
        .get(&Label::Length)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let compression = map
        .get(&Label::Compression)
        .map(|v| expect_i128(v))
        .transpose()?
        .map(|v| CompressionAlgorithm::try_from(v))
        .transpose()?
        .unwrap_or(CompressionAlgorithm::None);
    let compressed_length = map
        .get(&Label::CompressedLength)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let encryption_key = map
        .get(&Label::EncryptionKey)
        .map(|v| expect_bytes(v).map(|b| b.to_vec()))
        .transpose()?;
    let wrapped_key = map
        .get(&Label::WrappedKey)
        .map(|v| expect_bytes(v).map(|b| b.to_vec()))
        .transpose()?;
    let explicit_wrap_iv = map.get(&Label::WrapIv).map(|v| expect_iv(v)).transpose()?;

    let wrap_iv = if explicit_wrap_iv.is_some() {
        explicit_wrap_iv
    } else if wrapped_key.is_some() {
        if let Some(riv) = rolling_iv {
            let current = *riv;
            *riv = riv.increment();
            Some(current)
        } else {
            None
        }
    } else {
        None
    };

    let box_hash = if let Some(h) = map.get(&Label::BoxHash) {
        expect_hash(h)?
    } else {
        PackagingHash::default()
    };
    let box_index = map
        .get(&Label::BoxIndex)
        .map(|v| expect_i32(v).map(BoxIndex))
        .transpose()?
        .unwrap_or(BoxIndex(0));
    let box_offset = map
        .get(&Label::BoxOffset)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let box_length = map
        .get(&Label::BoxLength)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let secondary = map
        .get(&Label::Secondary)
        .map(|v| expect_bool(v))
        .transpose()?
        .unwrap_or(false);

    Ok(SegmentReference {
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

fn parse_chunk(val: &Value, rolling_iv: &mut Option<PackagingIv>) -> Result<Chunk, Xvc2Error> {
    let map = expect_map(val)?;

    let id = map
        .get(&Label::Id)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let on_demand = map
        .get(&Label::OnDemand)
        .map(|v| expect_bool(v))
        .transpose()?
        .unwrap_or(false);
    let required_to_launch = map
        .get(&Label::RequiredToLaunch)
        .map(|v| expect_bool(v))
        .transpose()?
        .unwrap_or(false);
    let key_index = map
        .get(&Label::KeyIndex)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let length = map
        .get(&Label::Length)
        .map(|v| expect_i64(v))
        .transpose()?
        .unwrap_or(0);
    let box_length = map
        .get(&Label::BoxLength)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);

    let secret_reference = if let Some(v) = map.get(&Label::SecretReference) {
        parse_segment_reference(v, rolling_iv)?
    } else {
        return Err(Xvc2Error::MissingField("SecretReference"));
    };

    Ok(Chunk {
        id,
        on_demand,
        required_to_launch,
        key_index,
        length,
        box_length,
        secret_reference,
    })
}

fn parse_package_key_source(val: &Value) -> Result<PackageKeySource, Xvc2Error> {
    let map = expect_map(val)?;
    let source_key_id = map
        .get(&Label::SourceKeyId)
        .map(|v| expect_guid(v))
        .transpose()?
        .unwrap_or_default();
    let source_purpose = map
        .get(&Label::SourcePurpose)
        .map(|v| expect_i128(v))
        .transpose()?
        .map(|v| KeyPurpose::try_from(v))
        .transpose()?
        .unwrap_or(KeyPurpose::Content);
    let derivation_algorithm = map
        .get(&Label::DerivationAlgorithm)
        .map(|v| expect_i128(v))
        .transpose()?
        .map(|v| DerivationAlgorithm::try_from(v))
        .transpose()?
        .unwrap_or(DerivationAlgorithm::None);
    let kdf_context = map
        .get(&Label::KdfContext)
        .map(|v| expect_bytes(v).map(|b| b.to_vec()))
        .transpose()?
        .unwrap_or_default();
    let wrap_algorithm = map
        .get(&Label::WrapAlgorithm)
        .map(|v| expect_i128(v))
        .transpose()?
        .map(|v| EncryptionAlgorithm::try_from(v))
        .transpose()?
        .unwrap_or(EncryptionAlgorithm::None);
    let wrap_iv = map.get(&Label::WrapIv).map(|v| expect_iv(v)).transpose()?;
    let wrapped_key = map
        .get(&Label::WrappedKey)
        .map(|v| expect_bytes(v).map(|b| b.to_vec()))
        .transpose()?
        .unwrap_or_default();
    let algorithm = map
        .get(&Label::Algorithm)
        .map(|v| expect_i128(v))
        .transpose()?
        .map(|v| EncryptionAlgorithm::try_from(v))
        .transpose()?
        .unwrap_or(EncryptionAlgorithm::None);

    Ok(PackageKeySource {
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

fn parse_package_key(val: &Value) -> Result<PackageKey, Xvc2Error> {
    let arr = expect_array(val)?;
    let mut sources = Vec::new();
    for v in arr {
        sources.push(parse_package_key_source(v)?);
    }
    Ok(PackageKey { sources })
}

fn parse_box_reference(val: &Value) -> Result<BoxReference, Xvc2Error> {
    let map = expect_map(val)?;
    let name = map
        .get(&Label::Name)
        .map(|v| expect_text(v).map(|s| s.to_string()))
        .transpose()?
        .unwrap_or_default();
    Ok(BoxReference { name })
}

fn parse_file_format_info(val: &Value) -> Result<FileFormatInfo, Xvc2Error> {
    let map = expect_map(val)?;

    let written_by = if let Some(v) = map.get(&Label::WrittenBy) {
        let arr = expect_array(v)?;
        let mut res = Vec::new();
        for item in arr {
            res.push(expect_text(item)?.to_string());
        }
        res
    } else {
        Vec::new()
    };

    let major_version = map
        .get(&Label::MajorVersion)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let minor_version = map
        .get(&Label::MinorVersion)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let build = map
        .get(&Label::Build)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);

    Ok(FileFormatInfo {
        written_by,
        major_version,
        minor_version,
        build,
    })
}

fn parse_xvc2_version(val: &Value) -> Result<Xvc2Version, Xvc2Error> {
    let map = expect_map(val)?;

    let major = map
        .get(&Label::MajorVersion)
        .map(|v| expect_u16(v))
        .transpose()?
        .unwrap_or(0);
    let minor = map
        .get(&Label::MinorVersion)
        .map(|v| expect_u16(v))
        .transpose()?
        .unwrap_or(0);
    let build = map
        .get(&Label::Build)
        .map(|v| expect_u16(v))
        .transpose()?
        .unwrap_or(0);
    let revision = map
        .get(&Label::Revision)
        .map(|v| expect_u16(v))
        .transpose()?
        .unwrap_or(0);

    let build_id = map
        .get(&Label::BuildId)
        .map(|v| expect_guid(v))
        .transpose()?
        .unwrap_or_default();
    let original_build_id = map
        .get(&Label::OriginalBuildId)
        .map(|v| expect_guid(v))
        .transpose()?;

    Ok(Xvc2Version {
        major,
        minor,
        build,
        revision,
        build_id,
        original_build_id,
    })
}

fn parse_segmentation(val: &Value) -> Result<Segmentation, Xvc2Error> {
    let map = expect_map(val)?;
    let algorithm = map
        .get(&Label::Algorithm)
        .map(|v| expect_i128(v))
        .transpose()?
        .map(|v| SegmentationAlgorithm::try_from(v))
        .transpose()?
        .unwrap_or(SegmentationAlgorithm::None);
    let hash_algorithm = map
        .get(&Label::HashAlgorithm)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let options = if let Some(opts) = map.get(&Label::Options) {
        if let Value::Map(m) = *opts {
            let mut hm = HashMap::new();
            for (k, v) in m {
                let key = expect_i32(k)?;
                hm.insert(key, v.clone());
            }
            hm
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    Ok(Segmentation {
        algorithm,
        hash_algorithm,
        options,
    })
}

pub fn deserialize_package(bytes: &[u8]) -> Result<Package, Xvc2Error> {
    let val = parse_cbor_value(bytes)?;
    let inner = expect_tag(&val, cbor_tag::XVCP)?;
    let map = expect_map(inner)?;

    let file_format = if let Some(v) = map.get(&Label::FileFormat) {
        parse_file_format_info(v)?
    } else {
        return Err(Xvc2Error::MissingField("FileFormat"));
    };

    let content_id = map
        .get(&Label::ContentId)
        .map(|v| expect_guid(v))
        .transpose()?
        .unwrap_or_default();

    let version = if let Some(v) = map.get(&Label::Version) {
        parse_xvc2_version(v)?
    } else {
        return Err(Xvc2Error::MissingField("Version"));
    };

    let initial_iv = map
        .get(&Label::InitialIv)
        .map(|v| expect_iv(v))
        .transpose()?;

    let keys = if let Some(v) = map.get(&Label::Keys) {
        let arr = expect_array(v)?;
        let mut keys_vec = Vec::new();
        for k in arr {
            keys_vec.push(parse_package_key(k)?);
        }
        keys_vec
    } else {
        Vec::new()
    };

    let segmentation = if let Some(v) = map.get(&Label::Segmentation) {
        parse_segmentation(v)?
    } else {
        return Err(Xvc2Error::MissingField("Segmentation"));
    };

    let boxes = if let Some(v) = map.get(&Label::Boxes) {
        let arr = expect_array(v)?;
        let mut b_vec = Vec::new();
        for b in arr {
            b_vec.push(parse_box_reference(b)?);
        }
        b_vec
    } else {
        Vec::new()
    };

    let chunks = if let Some(v) = map.get(&Label::Chunks) {
        let arr = expect_array(v)?;
        let mut c_vec = Vec::new();
        let mut rolling_iv = initial_iv;
        for c in arr {
            c_vec.push(parse_chunk(c, &mut rolling_iv)?);
        }
        c_vec
    } else {
        Vec::new()
    };

    let fulfillment_content_id = map
        .get(&Label::FulfillmentContentId)
        .map(|v| expect_guid(v))
        .transpose()?
        .unwrap_or_default();
    let product_id = map
        .get(&Label::ProductId)
        .map(|v| expect_guid(v))
        .transpose()?
        .unwrap_or_default();

    let minimum_system_version = if let Some(v) = map.get(&Label::MinimumSystemVersion) {
        parse_xvc2_version(v)?
    } else {
        return Err(Xvc2Error::MissingField("MinimumSystemVersion"));
    };

    let store_id = map
        .get(&Label::StoreId)
        .map(|v| expect_text(v).map(|s| s.to_string()))
        .transpose()?
        .unwrap_or_default();
    let supported_platforms = map
        .get(&Label::SupportedPlatforms)
        .map(|v| expect_i128(v))
        .transpose()?
        .map(|v| Platform::try_from(v))
        .transpose()?
        .unwrap_or(Platform::None);

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

fn parse_file(val: &Value, inherited_iv: &mut Option<PackagingIv>) -> Result<Xvc2File, Xvc2Error> {
    let map = expect_map(val)?;

    let id = map
        .get(&Label::Id)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let chunk_id = map
        .get(&Label::ChunkId)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let file_iv = map
        .get(&Label::InitialIv)
        .map(|v| expect_iv(v))
        .transpose()?;
    let length = map
        .get(&Label::Length)
        .map(|v| expect_i64(v))
        .transpose()?
        .unwrap_or(0);
    let hash = if let Some(h) = map.get(&Label::Hash) {
        expect_hash(h)?
    } else {
        PackagingHash::default()
    };
    let read_protected = map
        .get(&Label::ReadProtected)
        .map(|v| expect_bool(v))
        .transpose()?
        .unwrap_or(false);

    let mut current_iv = file_iv.or(*inherited_iv);

    let segments = if let Some(v) = map.get(&Label::Segments) {
        let arr = expect_array(v)?;
        let mut s_vec = Vec::new();
        for s in arr {
            s_vec.push(parse_segment_reference(s, &mut current_iv)?);
        }
        Some(s_vec)
    } else {
        None
    };

    *inherited_iv = current_iv;

    Ok(Xvc2File {
        id,
        chunk_id,
        iv: file_iv,
        length,
        hash,
        read_protected,
        segments,
    })
}

pub fn deserialize_chunk_details(bytes: &[u8]) -> Result<ChunkDetails, Xvc2Error> {
    let val = parse_cbor_value(bytes)?;
    let inner = expect_tag(&val, cbor_tag::XVCC)?;
    let map = expect_map(inner)?;

    let id = map
        .get(&Label::Id)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let iv = map
        .get(&Label::InitialIv)
        .map(|v| expect_iv(v))
        .transpose()?;

    let files = if let Some(v) = map.get(&Label::Files) {
        let arr = expect_array(v)?;
        let mut f_vec = Vec::new();
        let mut rolling_iv = iv;
        for f in arr {
            f_vec.push(parse_file(f, &mut rolling_iv)?);
        }
        f_vec
    } else {
        Vec::new()
    };

    Ok(ChunkDetails { id, iv, files })
}

fn parse_file_secret(val: &Value) -> Result<FileSecret, Xvc2Error> {
    let map = expect_map(val)?;
    let file_name = map
        .get(&Label::Name)
        .map(|v| expect_text(v).map(|s| s.to_string()))
        .transpose()?
        .unwrap_or_default();
    Ok(FileSecret { file_name })
}

pub fn deserialize_chunk_details_secret(bytes: &[u8]) -> Result<ChunkDetailsSecret, Xvc2Error> {
    let val = parse_cbor_value(bytes)?;
    let inner = expect_tag(&val, cbor_tag::XVCZ)?;
    let map = expect_map(inner)?;

    let id = map
        .get(&Label::Id)
        .map(|v| expect_i32(v))
        .transpose()?
        .unwrap_or(0);
    let files = if let Some(v) = map.get(&Label::Files) {
        let arr = expect_array(v)?;
        let mut f_vec = Vec::new();
        for f in arr {
            f_vec.push(parse_file_secret(f)?);
        }
        f_vec
    } else {
        Vec::new()
    };

    Ok(ChunkDetailsSecret { id, files })
}

pub fn deserialize_box_manifest(bytes: &[u8]) -> Result<BoxManifest, Xvc2Error> {
    let val = parse_cbor_value(bytes)?;
    let inner = expect_tag(&val, cbor_tag::XVCB)?;
    let map = expect_map(inner)?;

    let file_format = if let Some(v) = map.get(&Label::FileFormat) {
        parse_file_format_info(v)?
    } else {
        return Err(Xvc2Error::MissingField("FileFormat"));
    };

    let name = map
        .get(&Label::Name)
        .map(|v| expect_text(v).map(|s| s.to_string()))
        .transpose()?
        .unwrap_or_default();

    let segments = if let Some(v) = map.get(&Label::Segments) {
        let arr = expect_array(v)?;
        let mut s_vec = Vec::new();
        let mut rolling_iv = None;
        for s in arr {
            s_vec.push(parse_segment_reference(s, &mut rolling_iv)?);
        }
        s_vec
    } else {
        Vec::new()
    };

    Ok(BoxManifest {
        file_format,
        name,
        segments,
    })
}

pub fn deserialize_seal(bytes: &[u8]) -> Result<Seal, Xvc2Error> {
    let val = parse_cbor_value(bytes)?;
    let map_val = if let Ok(inner) = expect_tag(&val, cbor_tag::XVC2) {
        inner
    } else {
        &val
    };

    let map = expect_map(map_val)?;

    let target = map
        .get(&Label::Target)
        .map(|v| expect_i128(v))
        .transpose()?
        .unwrap_or(0) as u64;
    let hash = if let Some(h) = map.get(&Label::Hash) {
        expect_hash(h)?
    } else {
        PackagingHash::default()
    };

    Ok(Seal { target, hash })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packaging_iv_increment() {
        let mut bytes = [0u8; 16];
        bytes[15] = 255;
        let iv1 = PackagingIv::from_bytes(&bytes);

        let iv2 = iv1.increment();
        assert_eq!(iv2.to_bytes()[15], 0);
        assert_eq!(iv2.to_bytes()[14], 1);
        assert_eq!(iv2.to_bytes()[7], 0);
    }

    #[test]
    fn test_expect_guid() {
        let val = Value::Text("123e4567-e89b-12d3-a456-426614174000".to_string());
        let guid = expect_guid(&val).unwrap();
        assert_eq!(guid.to_string(), "123e4567-e89b-12d3-a456-426614174000");
    }

    #[test]
    fn test_expect_hash() {
        let inner = Value::Bytes(vec![1, 2, 3, 4]);
        let tagged = Value::Tag(cbor_tag::SHA256, Box::new(inner));

        let hash = expect_hash(&tagged).unwrap();
        assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
        assert_eq!(hash.hash, vec![1, 2, 3, 4]);
    }
}
