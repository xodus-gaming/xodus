use std::fmt::Debug;
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncSeekExt},
};

use crate::licensing::splicense::ContentKey;
use crate::xvd::crypt::SectionReader;
use crate::xvd::math::{
    bytes_to_pages, calculate_hash_block_num_for_block_num, offset_to_page_number,
};
use crate::{
    models::xvd::{
        XvcInfo, XvcRegionHeader, XvcRegionId, XvcRegionPresenceInfo, XvcRegionSpecifier,
        XvdHashEntry, XvdHeader, XvdStruct, XvdUpdateSegment,
    },
    xvd::math::page_number_to_offset,
};

// This is a macro because the compiler can't handle const generics
macro_rules! read_struct {
    ($t:ty, $reader:expr) => {{
        let mut buf = [0u8; <$t as XvdStruct>::RAW_SIZE];
        $reader.read_exact(&mut buf).await?;
        TryInto::<$t>::try_into(buf)
    }};
}

struct XvdEncryptionInfo {
    full_key: ContentKey,
    encrypted_sections: Vec<EncryptedSectionInfo>,
}

// The gpt crate requires the device to implement Debug,
// but the content key must not be debuged
impl Debug for XvdEncryptionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XvdEncryptionInfo")
            .field("encrypted_sections", &self.encrypted_sections)
            .finish_non_exhaustive() // prints ", .." to signal redacted fields
    }
}

#[derive(Debug)]
struct XvdStream {
    file: std::fs::File,
    offset: u64,
    end_offset: u64,

    encryption_info: Option<XvdEncryptionInfo>,
}

impl XvdStream {
    fn len(&self) -> u64 {
        self.end_offset - self.offset
    }

    fn current_relative_pos(&mut self) -> std::io::Result<u64> {
        let absolute = self.file.stream_position()?;
        absolute
            .checked_sub(self.offset)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "stream before virtual start"))
    }
}

impl Read for XvdStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let current = self.current_relative_pos()?;
        if current >= self.len() {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len() - current)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        if let Some(encryption_info) = &self.encryption_info {
            for s in &encryption_info.encrypted_sections {
                if self.offset + current >= s.section_offset
                    && self.offset + current < s.section_offset + s.section_length
                {
                    if s.section_offset + s.section_length < self.offset + current + to_read as u64
                    {
                        todo!("Reading outside of the encrypted section in one go is Unsupported");
                    }
                    let mut reader = SectionReader::new(
                        &self.file,
                        s.section_offset,
                        s.section_length,
                        s.header_id,
                        s.vduid,
                        encryption_info.full_key,
                        s.data_units.clone(),
                    );
                    return reader
                        .read_at(
                            self.offset + current - s.section_offset,
                            &mut buf[..to_read],
                        )
                        .map(|_| to_read);
                }
            }
        }

        self.file.read(&mut buf[..to_read])
    }
}

impl Seek for XvdStream {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_relative = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(delta) => {
                let current = self.current_relative_pos()?;
                if delta >= 0 {
                    current.checked_add(delta as u64)
                } else {
                    current.checked_sub(delta.unsigned_abs())
                }
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid relative seek"))?
            }
            SeekFrom::End(delta) => {
                let len = self.len();
                if delta >= 0 {
                    len.checked_add(delta as u64)
                } else {
                    len.checked_sub(delta.unsigned_abs())
                }
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid end-relative seek"))?
            }
        };

        if new_relative > self.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past virtual device end",
            ));
        }

        self.file
            .seek(SeekFrom::Start(self.offset + new_relative))?;
        Ok(new_relative)
    }
}

impl Write for XvdStream {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "XvdStream is read-only",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn extract_ntfs_file<T: Read + Seek>(
    fs: &mut T,
    file: &NtfsFile<'_>,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut output_file = std::fs::File::create(output_path)?;

    if let Some(data_item) = file.data(fs, "") {
        let data_item = data_item?;
        let data_attribute = data_item.to_attribute()?;
        let mut data_value = data_attribute.value(fs)?;
        let mut buf = [0u8; 8192];

        loop {
            let bytes_read = data_value.read(fs, &mut buf)?;
            if bytes_read == 0 {
                break;
            }

            output_file.write_all(&buf[..bytes_read])?;
        }
    }

    Ok(())
}

fn extract_ntfs_directory<T: Read + Seek>(
    ntfs: &Ntfs,
    fs: &mut T,
    directory: &NtfsFile<'_>,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(output_dir)?;

    let index = directory.directory_index(fs)?;
    let mut entries = index.entries();

    while let Some(entry) = entries.next(fs) {
        let entry = entry?;
        let Some(file_name) = entry.key() else {
            continue;
        };
        let file_name = file_name?;
        let name = file_name.name().to_string()?;

        if name == "." || name.starts_with('$') {
            continue;
        }

        let child = entry.to_file(ntfs, fs)?;
        let child_output_path = output_dir.join(&name);

        if file_name.is_directory() {
            extract_ntfs_directory(ntfs, fs, &child, &child_output_path)?;
        } else {
            extract_ntfs_file(fs, &child, &child_output_path)?;
        }
    }

    Ok(())
}

pub struct XvdFile {
    header: XvdHeader,
    drive_data_offset: u64,
    encrypted_section_infos: Vec<EncryptedSectionInfo>,
}

#[derive(Debug)]
pub struct EncryptedSectionInfo {
    section_offset: u64,
    section_length: u64,

    header_id: XvcRegionId,
    vduid: [u8; 8],

    // If integrity is enabled, this must contain one entry per page in the section.
    // If integrity is disabled, use page_in_section as the data unit instead.
    data_units: Option<Vec<u32>>,
}

impl XvdFile {
    pub fn content_id(&self) -> uuid::Uuid {
        self.header.vduid
    }

    pub async fn parse_file(path: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(path.clone())
            .await
            .expect("Unable to open file");

        let xvd_header = read_struct!(XvdHeader, file)?;

        let mdu_offset = xvd_header.mdu_offset();
        let (_hash_tree_levels, hash_tree_page_count) = xvd_header.hash_tree_info();
        let xvc_info_offset = xvd_header.xvc_info_offset(hash_tree_page_count);

        println!("Version: {}", xvd_header.format_version);
        println!("XvcLength: {}", xvd_header.xvc_data_length);
        println!("volume_flags: 0x{:X}", xvd_header.volume_flags);
        println!("is_encrypted: {}", xvd_header.volume_flags.is_encrypted());
        println!(
            "legacy_sector_size: {}",
            xvd_header.volume_flags.is_legacy_sector_size()
        );

        let mut region_headers: Vec<XvcRegionHeader> = Vec::new();
        let mut update_segments: Vec<XvdUpdateSegment> = Vec::new();
        let mut region_specifiers: Vec<XvcRegionSpecifier> = Vec::new();
        let mut region_presence_info: Vec<XvcRegionPresenceInfo> = Vec::new();

        // TODO: Check if we have proper content type
        if xvd_header.xvc_data_length > 0 {
            file.seek(std::io::SeekFrom::Start(xvc_info_offset))
                .await
                .expect("Unable to seek");
            let Ok(xvc_info) = read_struct!(XvcInfo, file);

            let region_count = xvc_info.region_count;
            let update_segment_count = xvc_info.update_segment_count;
            let region_specifier_count = xvc_info.region_specifier_count;

            if xvc_info.version >= 1 {
                for _ in 0..region_count {
                    let Ok(region_header) = read_struct!(XvcRegionHeader, file);
                    region_headers.push(region_header);
                }

                for _ in 0..update_segment_count {
                    let Ok(update_segment) = read_struct!(XvdUpdateSegment, file);
                    update_segments.push(update_segment);
                }
            }

            if xvc_info.version >= 2 {
                for _ in 0..region_specifier_count {
                    let Ok(region_specifier) = read_struct!(XvcRegionSpecifier, file);
                    region_specifiers.push(region_specifier);
                }

                if xvd_header.mutable_page_count > 0 {
                    file.seek(std::io::SeekFrom::Start(mdu_offset))
                        .await
                        .expect("Unable to seek");
                    for _ in 0..region_count {
                        let Ok(region_presence) = read_struct!(XvcRegionPresenceInfo, file);
                        region_presence_info.push(region_presence);
                    }
                }
            }
        }

        let hash_tree_offset = xvd_header.mutable_data_length() + mdu_offset;
        let user_data_offset = if xvd_header.volume_flags.is_data_integrity_enabled() {
            page_number_to_offset(xvd_header.hash_tree_info().1)
        } else {
            0
        } + hash_tree_offset;
        let xvc_info_offset =
            page_number_to_offset(xvd_header.user_data_page_count()) + user_data_offset;
        let dynamic_header_offset =
            page_number_to_offset(xvd_header.xvc_data_page_count()) + xvc_info_offset;
        let drive_data_offset =
            page_number_to_offset(xvd_header.dynamic_header_page_count()) + dynamic_header_offset;

        let mut enc_sections: Vec<EncryptedSectionInfo> = vec![];
        for h in region_headers {
            let key_id = h.key_id;
            let offset = h.offset;
            let length = h.length;
            println!(
                "key_id {:?} ({} + {} = {})",
                key_id,
                offset,
                length,
                offset + length
            );

            match key_id.get() {
                None => continue,
                Some(0) => (),
                Some(n) => todo!("KeyID other than 0 or unencrypted is not supported, found {n}"),
            }

            let mut data_units: Vec<u32> = vec![];
            let start_page = offset_to_page_number(h.offset - user_data_offset);
            let num_pages = bytes_to_pages(length);
            for page in 0..num_pages {
                let (hash_block, entry_num) = calculate_hash_block_num_for_block_num(
                    xvd_header.xvd_type as u32,
                    _hash_tree_levels,
                    xvd_header.number_of_hashed_pages(),
                    start_page + page,
                    0,
                    false,
                    false,
                );
                let read_offset = hash_tree_offset
                    + page_number_to_offset(hash_block)
                    + (entry_num * XvdHashEntry::RAW_SIZE as u64);

                file.seek(SeekFrom::Start(read_offset)).await?;

                let Ok(hash) = read_struct!(XvdHashEntry, file);
                data_units.push(hash.unit);
            }

            enc_sections.push(EncryptedSectionInfo {
                section_offset: h.offset,
                section_length: h.length,
                header_id: h.region_id,
                vduid: xvd_header.vduid.to_bytes_le()[..8].try_into().unwrap(),
                data_units: Some(data_units.clone()),
            });
        }
        Ok(XvdFile {
            header: xvd_header,
            drive_data_offset,
            encrypted_section_infos: enc_sections,
        })
    }
}

pub fn unpack_file(
    xvd: XvdFile,
    path: String,
    destination: String,
    full_key: ContentKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let sfile = std::fs::File::open(path)?;
    let block_size = 4096; //xvd.header.block_size;
    let gp = gpt::GptConfig::new()
        .writable(false)
        .logical_block_size(if block_size == 512 {
            gpt::disk::LogicalBlockSize::Lb512
        } else if block_size == 4096 {
            gpt::disk::LogicalBlockSize::Lb4096
        } else {
            todo!("unsupported block_size: {}", block_size)
        })
        .open_from_device(XvdStream {
            file: sfile.try_clone().unwrap(),
            offset: xvd.drive_data_offset,
            end_offset: xvd.drive_data_offset + xvd.header.drive_size,
            encryption_info: None,
        })
        .unwrap();

    let mut ntfs_partition = None;
    for (index, part) in gp.partitions() {
        if !part.is_used() {
            continue;
        }

        let part_start = part.bytes_start(*gp.logical_block_size()).unwrap();
        let part_len = part.bytes_len(*gp.logical_block_size()).unwrap();
        println!(
            "#{index}: '{}' start={} len={}",
            part.name, part_start, part_len,
        );

        if ntfs_partition.is_none() {
            ntfs_partition = Some((index, part.name.clone(), part_start, part_len));
        }
    }

    let (_, _, part_start, part_len) = ntfs_partition.expect("no used GPT partition found");
    let partition_offset = xvd.drive_data_offset + part_start;

    let mut fs = XvdStream {
        file: sfile.try_clone().unwrap(),
        offset: partition_offset,
        end_offset: partition_offset + part_len,
        encryption_info: Some(XvdEncryptionInfo {
            full_key,
            encrypted_sections: xvd.encrypted_section_infos,
        }),
    };
    fs.seek(SeekFrom::Start(0)).unwrap();
    let mut ntfs = Ntfs::new(&mut fs).unwrap();

    ntfs.read_upcase_table(&mut fs).unwrap();

    let root = ntfs.root_directory(&mut fs).unwrap();
    let extract_root = PathBuf::from(destination);
    println!("extracting data directory to {}", extract_root.display());
    extract_ntfs_directory(&ntfs, &mut fs, &root, &extract_root)?;
    Ok(())
}
