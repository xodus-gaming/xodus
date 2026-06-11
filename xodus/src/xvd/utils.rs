use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncSeekExt},
};
use zerocopy::transmute;

use crate::{
    models::xvd::{
        XvcInfo, XvcRegionHeader, XvcRegionSpecifier, XvdHeader, XvdUpdateSegment,
    },
};

pub async fn parse_file(path: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
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

    Ok(())
}
