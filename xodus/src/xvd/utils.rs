use std::io::{Read, Seek, Write};

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
struct XvdStream<'a> {
    file: &'a std::fs::File,
    offset: u64,
    end_offset: u64
}

impl Read for XvdStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let soff = self.file.seek(std::io::SeekFrom::Current(0)).unwrap();
        let r = self.file.read(buf);
        let roff = self.file.seek(std::io::SeekFrom::Current(0)).unwrap();
        println!("read {soff} -> {roff}");
        r
    }
}

impl Seek for XvdStream<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Current(_) => self.file.seek(pos).map(|o| o - self.offset),
            std::io::SeekFrom::Start(s) => self.file.seek(std::io::SeekFrom::Start(self.offset + s)).map(|o| o - self.offset),
            std::io::SeekFrom::End(e) => self.file.seek(std::io::SeekFrom::Start((self.end_offset as i64 + e) as u64)).map(|o| o - self.offset),
        }
    }
}

impl Write for XvdStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

pub async fn parse_file(path: String) -> Result<(), Box<dyn std::error::Error>> {
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
    let dynamic_base_offset = xvc_info_offset;
    let static_data_length = if xvd_header.xvd_type == 0 { 0 } else { panic!("Unsupported XvdType, TODO support Dynamic") };

    println!("drive_data_offset = {drive_data_offset}");
    println!("EFI_PART {}", 0x011df000);
    let mut sfile = std::fs::File::open(path).unwrap();
    sfile.seek(std::io::SeekFrom::Start(drive_data_offset));
    // let mut buf = [0u8; 4096];
    // sfile.read_exact(&mut buf).unwrap();
    // gpt::disk::read_disk(diskpath)
    let gp = gpt::GptConfig::new()
        .writable(false)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb4096)
        .open_from_device(XvdStream{
            file: &sfile,
            offset: drive_data_offset,
            end_offset: drive_data_offset + xvd_header.drive_size
        }).unwrap();

    for (index, part) in gp.partitions() {
        println!(
            "#{index}: {} start={} len={}",
            part.name,
            part.bytes_start(*gp.logical_block_size()).unwrap(),
            part.bytes_len(*gp.logical_block_size()).unwrap(),
        );
    }

    Ok(())
}
