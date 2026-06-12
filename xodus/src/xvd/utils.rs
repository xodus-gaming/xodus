use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use tokio::{
    fs::{OpenOptions},
    io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt},
};
use zerocopy::transmute;

use crate::{models::xvd::{
    XvcInfo, XvcRegionHeader, XvcRegionSpecifier, XvdHeader, XvdUpdateSegment,
}, xvd::math::page_number_to_offset};

trait AsyncReadSeek: AsyncRead + AsyncSeek {}

#[derive(Debug)]
struct XvdStream {
    file: std::fs::File,
    offset: u64,
    end_offset: u64,
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

        self.file.seek(SeekFrom::Start(self.offset + new_relative))?;
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

        if name == "." {
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

pub async fn parse_file(path: String) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = PathBuf::from(&path);
    let mut file = OpenOptions::new()
        .read(true)
        .open(path.clone())
        .await
        .expect("Unable to open file");
    let mut header_buffer = [0u8; 4096];
    let mut info_buffer = [0u8; 0xDA8];

    file.read_exact(&mut header_buffer).await.unwrap();

    let xvd_header: XvdHeader = transmute!(header_buffer);

    // Extracts from header to avoid padding issues
    let format_version = xvd_header.format_version;
    let xvc_length = xvd_header.xvc_data_length;
    let volume_flags = xvd_header.volume_flags;
    let xvc_data_length = xvd_header.xvc_data_length;
    let is_encrypted = xvd_header.is_encrypted();
    let legacy_sector_size = xvd_header.is_legacy_sector_size();
    let _content_types = xvd_header.xvd_content_type;
    let _sector_size = xvd_header.sector_size();
    let _number_of_metadata_pages = xvd_header.number_of_metadata_pages();

    let mdu_offset = xvd_header.mdu_offset();
    let (_hash_tree_levels, hash_tree_page_count) = xvd_header.hash_tree_info();
    let xvc_info_offset = xvd_header.xvc_info_offset(hash_tree_page_count);

    println!("Version: {}", format_version);
    println!("XvcLength: {}", xvc_length);
    println!("volume_flags: 0x{:X}", volume_flags);
    println!("is_encrypted: {}", is_encrypted);
    println!("legacy_sector_size: {}", legacy_sector_size);
    println!("xvc_data_length: {}", xvc_data_length);


    let mut region_headers: Vec<XvcRegionHeader> = Vec::new();
    let mut update_segments: Vec<XvdUpdateSegment> = Vec::new();
    let mut region_specifiers: Vec<XvcRegionSpecifier> = Vec::new();
    let mut region_presence_info: Vec<u8> = Vec::new();

    // TODO: Check if we have proper content type
    if xvc_data_length > 0 {
        file.seek(std::io::SeekFrom::Start(xvc_info_offset))
            .await
            .expect("Unable to seek");
        file.read_exact(&mut info_buffer).await.unwrap();
        let xvc_info: XvcInfo = transmute!(info_buffer);

        let region_count = xvc_info.region_count;
        let update_segment_count = xvc_info.update_segment_count;
        let region_specifier_count = xvc_info.region_specifier_count;

        if xvc_info.version >= 1 {
            let mut region_header_buf = [0u8; 0x80];
            for _ in 0..region_count {
                file.read_exact(&mut region_header_buf).await.unwrap();
                let region_header: XvcRegionHeader = transmute!(region_header_buf);
                region_headers.push(region_header);
            }

            let mut update_segment_buf = [0u8; 0xC];
            for _ in 0..update_segment_count {
                file.read_exact(&mut update_segment_buf).await.unwrap();
                let update_segment: XvdUpdateSegment = transmute!(update_segment_buf);
                update_segments.push(update_segment);
            }

            if xvc_info.version >= 2 {
                let mut region_specifier_buf = [0u8; 0x188];
                for _ in 0..region_specifier_count {
                    file.read_exact(&mut region_specifier_buf).await.unwrap();
                    let region_specifier: XvcRegionSpecifier = transmute!(region_specifier_buf);
                    region_specifiers.push(region_specifier);
                }

                if xvd_header.mutable_page_count > 0 {
                    file.seek(std::io::SeekFrom::Start(mdu_offset))
                        .await
                        .expect("Unable to seek");
                    let mut byte = [0; 1];
                    for _ in 0..region_count {
                        file.read_exact(&mut byte).await.unwrap();
                        region_presence_info.push(byte[0]);
                    }
                }
            }
        }
    }

    let hash_tree_offset = xvd_header.mutable_data_length() + mdu_offset;
    let user_data_offset = if xvd_header.is_data_integrity_enabled() { page_number_to_offset(xvd_header.hash_tree_info().1) } else { 0 } + hash_tree_offset;
    let xvc_info_offset = page_number_to_offset(xvd_header.user_data_page_count()) + user_data_offset;
    let dynamic_header_offset = page_number_to_offset(xvd_header.xvc_data_page_count()) + xvc_info_offset;
    let drive_data_offset = page_number_to_offset(xvd_header.dynamic_header_page_count()) + dynamic_header_offset;
    let _dynamic_base_offset = xvc_info_offset;
    let _static_data_length = if xvd_header.xvd_type == 0 { 0 } else { panic!("Unsupported XvdType, TODO support Dynamic") };

    println!("drive_data_offset = {drive_data_offset:#x}");
    let mut sfile = std::fs::File::open(path).unwrap();
    sfile.seek(SeekFrom::Start(drive_data_offset)).unwrap();

    let gp = gpt::GptConfig::new()
        .writable(false)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb4096)
        .open_from_device(XvdStream {
            file: sfile.try_clone().unwrap(),
            offset: drive_data_offset,
            end_offset: drive_data_offset + xvd_header.drive_size,
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
            part.name,
            part_start,
            part_len,
        );

        if ntfs_partition.is_none() {
            ntfs_partition = Some((index, part.name.clone(), part_start, part_len));
        }
    }

    let (index, part_name, part_start, part_len) =
        ntfs_partition.expect("no used GPT partition found");
    let partition_offset = drive_data_offset + part_start;

    println!("probing partition #{index} '{part_name}' at {partition_offset:#x}");
    sfile.seek(SeekFrom::Start(partition_offset)).unwrap();
    let mut boot = [0u8; 512];
    sfile.read_exact(&mut boot).unwrap();
    println!("boot oem = {:?}", String::from_utf8_lossy(&boot[3..11]));
    println!(
        "boot bytes/sector = {}",
        u16::from_le_bytes([boot[11], boot[12]])
    );
    println!("boot sectors/cluster = {}", boot[13]);
    println!("boot sig = {:02x}{:02x}", boot[510], boot[511]);

    let mut fs = XvdStream {
        file: sfile.try_clone().unwrap(),
        offset: partition_offset,
        end_offset: partition_offset + part_len,
    };
    fs.seek(SeekFrom::Start(0)).unwrap();
    let mut ntfs = Ntfs::new(&mut fs).unwrap();
    
    ntfs.read_upcase_table(&mut fs).unwrap();

    let root = ntfs.root_directory(&mut fs).unwrap();
    let index = root.directory_index(&mut fs).unwrap();
    let mut entries = index.entries();

    while let Some(entry) = entries.next(&mut fs) {
        let entry = entry.unwrap();
        let Some(file_name) = entry.key() else {
            continue;
        };
        let file_name = file_name.unwrap();
        let name = file_name.name().to_string().unwrap();
        println!("{name}");

        // if name == "data" && file_name.is_directory() {
        //     data_directory = Some(entry.to_file(&ntfs, &mut fs).unwrap());
        // }
    }

    let package_name = input_path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("xvd");
    let extract_root = PathBuf::from("target")
        .join("xvd-extract")
        .join(package_name)
        .join("data");
    println!("extracting data directory to {}", extract_root.display());
    extract_ntfs_directory(&ntfs, &mut fs, &root, &extract_root)?;

    Ok(())
}

