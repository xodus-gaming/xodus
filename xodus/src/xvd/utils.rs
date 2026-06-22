use aes::Aes128;
use aes::cipher::KeyInit;
use bytes::Bytes;
use futures_util::StreamExt;
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use reqwest::header::RANGE;
use tokio::time::timeout;
use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncSeekExt},
};
use zerocopy::IntoBytes;

use crate::licensing::splicense::ContentKey;
use crate::models::xvd::{
    PAGE_SIZE, PAGES_PER_BLOCK, XvdSegmentMetadataHeader, XvdSegmentMetadataSegment,
    XvdUserDataHeader, XvdUserDataPackageFileEntry,
    XvdUserDataPackageFilesHeader,
};
use async_trait::async_trait;

use crate::xvd::crypt::{SectionReader, Tweak, decrypt_page_xts};
use crate::xvd::math::{
    bytes_to_pages, calculate_hash_block_num_and_run_for_block_num, offset_to_page_number,
};
use crate::{
    models::xvd::{
        XvcInfo, XvcRegionHeader, XvcRegionId, XvcRegionPresenceInfo, XvcRegionSpecifier,
        XvdHashEntry, XvdHeader, XvdStruct, XvdUpdateSegment,
    },
    xvd::math::page_number_to_offset,
};


#[async_trait]
pub trait AsyncReadSeek {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()>;
    async fn seek(&mut self, pos: SeekFrom) -> io::Result<u64>;
}

#[async_trait]
impl<T> AsyncReadSeek for T
where
    T: AsyncRead + AsyncSeek + Unpin + Send,
{
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        AsyncReadExt::read_exact(self, buf).await?;
        Ok(())
    }

    async fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        AsyncSeekExt::seek(self, pos).await
    }
}

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
    user_data_offset: u64,
}

#[derive(Debug, Clone)]
pub struct FileSegment {
    file_name: String,
    data_offset: u64,
    data_length: u64,
    page_offset: u64,
    page_length: u64,
    keep_encrypted: bool,
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
    first_segment_index: u32,
    data_hashs: Vec<[u8; 20]>,
}

pub struct UserPackageFile {
    pub offset: u64,
    pub length: u64,
}

pub struct SegmentFile {
    pub offset: u64,
    pub length: u64,
    pub data_hashs: Vec<[u8; 20]>,
}

impl XvdFile {
    pub fn content_id(&self) -> uuid::Uuid {
        self.header.vduid
    }

    pub async fn parse_file(path: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(path.clone())
            .await?;
        Self::parse(&mut file).await
    }

    pub async fn parse<Reader>(file: &mut Reader) -> Result<Self, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let xvd_header = read_struct!(XvdHeader, file)?;

        let mdu_offset = xvd_header.mdu_offset();
        let (_hash_tree_levels, hash_tree_page_count) = xvd_header.hash_tree_info();
        let xvc_info_offset = xvd_header.xvc_info_offset(hash_tree_page_count);


        let mut region_headers: Vec<XvcRegionHeader> = Vec::new();
        // let mut update_segments: Vec<XvdUpdateSegment> = Vec::new();
        // let mut region_specifiers: Vec<XvcRegionSpecifier> = Vec::new();
        // let mut region_presence_info: Vec<XvcRegionPresenceInfo> = Vec::new();

        // TODO: Check if we have proper content type
        if xvd_header.xvc_data_length > 0 {
            file.seek(std::io::SeekFrom::Start(xvc_info_offset))
                .await
                .expect("Unable to seek");
            let Ok(xvc_info) = read_struct!(XvcInfo, file);

            let region_count = xvc_info.region_count;

            if xvc_info.version >= 1 {
                for _ in 0..region_count {
                    let Ok(region_header) = read_struct!(XvcRegionHeader, file);
                    region_headers.push(region_header);
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
        let mut reader =
            BufReader::with_capacity(PAGES_PER_BLOCK * XvdHashEntry::RAW_SIZE as usize, file);
        for h in region_headers {
            let key_id = h.key_id;
            let length = h.length;
            match key_id.get() {
                None => continue,
                Some(0) => (),
                Some(n) => todo!("KeyID other than 0 or unencrypted is not supported, found {n}"),
            }

            let mut data_units: Vec<u32> = vec![];
            let mut data_hashs = vec![];
            let start_page = offset_to_page_number(h.offset - user_data_offset);
            let num_pages = bytes_to_pages(length);

            let mut page = 0;
            loop {
                if page >= num_pages {
                    break;
                }
                let (hash_block, entry_start, run_length) =
                    calculate_hash_block_num_and_run_for_block_num(
                        xvd_header.xvd_type as u32,
                        _hash_tree_levels,
                        xvd_header.number_of_hashed_pages(),
                        start_page + page,
                        0,
                        false,
                        false,
                    );
                let run_length = min(run_length as u64, num_pages - page);
                page += run_length;
                let read_offset = hash_tree_offset
                    + page_number_to_offset(hash_block)
                    + (entry_start * XvdHashEntry::RAW_SIZE as u64);
                reader.seek(SeekFrom::Start(read_offset)).await?;
                for _ in 0..run_length {
                    let Ok(hash) = read_struct!(XvdHashEntry, reader);
                    data_units.push(hash.unit);
                    data_hashs.push(hash.block_hash);
                }
            }

            enc_sections.push(EncryptedSectionInfo {
                section_offset: h.offset,
                section_length: h.length,
                header_id: h.region_id,
                vduid: xvd_header.vduid.to_bytes_le()[..8].try_into().unwrap(),
                data_units: Some(data_units.clone()),
                first_segment_index: h.first_segment_index,
                data_hashs: data_hashs,
            });
        }
        Ok(XvdFile {
            header: xvd_header,
            drive_data_offset,
            encrypted_section_infos: enc_sections,
            user_data_offset: user_data_offset,
        })
    }

    pub async fn readUserPackageFiles<Reader>(
        &self,
        file: &mut Reader,
    ) -> Result<HashMap<String, UserPackageFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut files = HashMap::new();

        let user_data_offset = self.user_data_offset;
        file.seek(SeekFrom::Start(user_data_offset)).await?;
        let user_data_header = read_struct!(XvdUserDataHeader, file)?;
        if user_data_header.t == 0 {
            let mut off = user_data_offset + user_data_header.length as u64;
            file.seek(SeekFrom::Start(off)).await?;
            let user_data_package_files_header = read_struct!(XvdUserDataPackageFilesHeader, file)?;
            off += XvdUserDataPackageFilesHeader::RAW_SIZE as u64;
            for _ in 0..user_data_package_files_header.file_count {
                file.seek(SeekFrom::Start(off)).await?;
                let user_data_package_file_entry = read_struct!(XvdUserDataPackageFileEntry, file)?;
                off += XvdUserDataPackageFileEntry::RAW_SIZE as u64;
                let o = user_data_package_file_entry.offset;
                let s: u32 = user_data_package_file_entry.size;
                let fullname = user_data_package_file_entry.file_path;
                let end = fullname
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(fullname.len());
                let pfull_name: String = String::from_utf16(&fullname[..end]).unwrap();

                files.insert(
                    pfull_name,
                    UserPackageFile {
                        offset: user_data_offset + XvdUserDataHeader::RAW_SIZE as u64 + o as u64,
                        length: s as u64,
                    },
                );
            }
        }
        Ok(files)
    }

    pub async fn parse_segment_metadata<Reader>(
        &mut self,
        file: &mut Reader,
        segment_metadata: UserPackageFile,
    ) -> Result<HashMap<String, SegmentFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut file: BufReader<&mut Reader> =
            BufReader::with_capacity(segment_metadata.length as usize, file);
        file.seek(SeekFrom::Start(segment_metadata.offset)).await?;
        let segment_header: XvdSegmentMetadataHeader =
            read_struct!(XvdSegmentMetadataHeader, file)?;
        let paths_offset =
            segment_header.header_length as u64 + segment_header.segment_count as u64 * 0x10;

        let mut segments = vec![];
        for _ in 0..segment_header.segment_count {
            let segment = read_struct!(XvdSegmentMetadataSegment, file)?;
            segments.push(segment);
        }

        let mut files = HashMap::new();

        for section in &self.encrypted_section_infos {
            let segment_page_start = section.section_offset.div_ceil(PAGE_SIZE as u64);
            let mut page_offset = segment_page_start;
            for segment_no in section.first_segment_index..segment_header.segment_count {
                let segment = &segments[segment_no as usize];
                let s = segment.path_length;
                let mut buf = vec![0u16, 0];
                buf.resize(s as usize, 0);
                file.seek(SeekFrom::Start(
                    segment_metadata.offset as u64 + paths_offset + segment.path_offset as u64,
                ))
                .await?;
                file.read_exact(buf.as_mut_bytes()).await?;
                let file_name: String = String::from_utf16(buf.as_slice()).unwrap();
                let page_length = if segment.filesize == 0 {
                    1
                } else {
                    segment.filesize.div_ceil(PAGE_SIZE as u64)
                };
                if !(page_offset * (PAGE_SIZE as u64)
                    < section.section_offset + section.section_length)
                {
                    break;
                }
                let end = page_offset as usize - segment_page_start as usize
                    + segment.filesize.div_ceil(PAGE_SIZE as u64) as usize;
                let data_hashs: Vec<[u8; 20]> = section.data_hashs
                    [page_offset as usize - segment_page_start as usize..end]
                    .into();
                files.insert(
                    file_name,
                    SegmentFile {
                        offset: page_offset * PAGE_SIZE as u64,
                        length: segment.filesize,
                        data_hashs: data_hashs,
                    },
                );
                page_offset += page_length;
            }
        }
        Ok(files)
    }

    pub async fn download_file<Reader, Writer>(
        &self,
        file: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
        Writer: AsyncWrite + Unpin,
    {
        file.seek(SeekFrom::Start(sfile.offset)).await?;
        for s in &self.encrypted_section_infos {
            if sfile.offset >= s.section_offset
                && sfile.offset < s.section_offset + s.section_length
            {
                let mut tweak_key = [0u8; 16];
                let mut data_key = [0u8; 16];
                tweak_key.copy_from_slice(&full_key[..16]);
                data_key.copy_from_slice(&full_key[16..]);

                let mut tweak = Tweak::new(0, s.header_id, s.vduid);
                let tweak_cipher = Aes128::new((&tweak_key).into());
                let data_cipher = Aes128::new((&data_key).into());
                let file_offset_in_section = sfile.offset - s.section_offset;
                let page_start = file_offset_in_section / PAGE_SIZE as u64;
                let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);

                let mut page = [0u8; PAGE_SIZE];
                let mut remaining = sfile.length;
                for page_in_section in page_start..page_start + page_count {
                    tweak.update_data_unit(match &s.data_units {
                        Some(units) => *units.get(page_in_section as usize).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "{} units {} page_in_section {} ({}+{})",
                                    "missing data unit",
                                    (*units).len(),
                                    page_in_section,
                                    page_start,
                                    page_count
                                ),
                            )
                        })?,
                        None => page_in_section as u32,
                    });
                    file.read_exact(&mut page).await?;
                    page = decrypt_page_xts(page, tweak, &tweak_cipher, &data_cipher);
                    let to_write = remaining.min(PAGE_SIZE as u64) as usize;
                    out.write_all(&page[..to_write]).await?;
                    remaining -= to_write as u64;
                }
            }
        }
        Ok(())
    }

    pub async fn download_file_http<Writer, Progress>(
        &self,
        client: &reqwest::Client,
        url: String,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        mut progress: Progress,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64)
    {
        if sfile.length == 0 {
            return Ok(());
        }

        for s in &self.encrypted_section_infos {
            if sfile.offset >= s.section_offset
                && sfile.offset < s.section_offset + s.section_length
            {
                let mut tweak_key = [0u8; 16];
                let mut data_key = [0u8; 16];
                tweak_key.copy_from_slice(&full_key[..16]);
                data_key.copy_from_slice(&full_key[16..]);

                let mut tweak = Tweak::new(0, s.header_id, s.vduid);
                let tweak_cipher = Aes128::new((&tweak_key).into());
                let data_cipher = Aes128::new((&data_key).into());
                // let freader = SectionReader::new(file, sfile.offset, sfile.length, s.header_id, s.vduid, full_key, s.data_units);
                let file_offset_in_section = sfile.offset - s.section_offset;
                let page_start = file_offset_in_section / PAGE_SIZE as u64;
                let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);
                // let page_start = (sfile.offset - s.section_offset).div_ceil(PAGE_SIZE as u64);
                // let page_end = page_start + sfile.length.div_ceil(PAGE_SIZE as u64);

                let mut page = [0u8; PAGE_SIZE];
                let mut remaining = sfile.length;
                let mut page_in_section = page_start;
                let page_length = sfile.length.div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;
                let response = client
                    .get(url.clone())
                    .header(
                        RANGE,
                        format!("bytes={}-{}", sfile.offset, sfile.offset + page_length - 1),
                    )
                    .send()
                    .await?
                    .error_for_status()?;
                assert_eq!(response.status(), 206);
                let mut stream = response.bytes_stream();
                let mut pending = bytes::BytesMut::new();
                let mut v: u64 = 0;

                let stall_timeout = tokio::time::Duration::from_secs(5);
                // println!("ddd");
                loop {
                    if page_in_section >= page_start + page_count || remaining == 0 {
                        break;
                    }
                    let next = timeout(stall_timeout, stream.next()).await;
                    let data: Bytes;
                    match next {
                        Ok(Some(Ok(b))) => {
                            data = b;
                        }
                        Ok(Some(Err(_))) => {
                            // error
                            let response = client
                                .get(url.clone())
                                .header(
                                    RANGE,
                                    format!("bytes={}-{}", sfile.offset + v, sfile.offset + page_length - 1),
                                )
                                .send()
                                .await?
                                .error_for_status()?;
                            assert_eq!(response.status(), 206);
                            stream = response.bytes_stream();
                            continue;
                        }
                        Ok(None) => {
                            break;
                        }
                        Err(_) => {
                            // timed out: reopen from current byte offset
                            let response = client
                                .get(url.clone())
                                .header(
                                    RANGE,
                                    format!("bytes={}-{}", sfile.offset + v, sfile.offset + page_length - 1),
                                )
                                .send()
                                .await?
                                .error_for_status()?;
                            assert_eq!(response.status(), 206);
                            stream = response.bytes_stream();
                            continue;
                        }
                    }

                    v += data.len() as u64;
                    progress(min(v, sfile.length), sfile.length);

                    pending.extend_from_slice(&data);

                    while pending.len() >= 4096 {
                        if page_in_section >= page_start + page_count || remaining == 0 {
                            break;
                        }
                        let chunk = pending.split_to(4096);
                        page.copy_from_slice(&chunk);
                        tweak.update_data_unit(match &s.data_units {
                            Some(units) => {
                                *units.get(page_in_section as usize).ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        format!(
                                            "{} units {} page_in_section {} ({}+{})",
                                            "missing data unit",
                                            (*units).len(),
                                            page_in_section,
                                            page_start,
                                            page_count
                                        ),
                                    )
                                })?
                            }
                            None => page_in_section as u32,
                        });
                        page = decrypt_page_xts(page, tweak, &tweak_cipher, &data_cipher);
                        let to_write = remaining.min(PAGE_SIZE as u64) as usize;
                        out.write_all(&page[..to_write]).await?;
                        remaining -= to_write as u64;

                        page_in_section += 1;
                    }
                }
                if remaining > 0 {
                    return Err(Box::new(std::io::Error::new(ErrorKind::Other, format!("{} of {} missing", remaining, sfile.length))));
                }
                return Ok(());
            }
        }
        return Err(Box::new(std::io::Error::new(ErrorKind::NotFound, "File not found in encrypted section")));
    }

    pub async fn download_file_sync<Reader, Writer>(
        &self,
        file: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: Read + Seek,
        Writer: AsyncWrite + Unpin,
    {
        for s in &self.encrypted_section_infos {
            if sfile.offset >= s.section_offset
                && sfile.offset < s.section_offset + s.section_length
            {
                let mut freader = SectionReader::new(
                    &mut *file,
                    s.section_offset,
                    s.section_length,
                    s.header_id,
                    s.vduid,
                    full_key.into(),
                    s.data_units.clone(),
                );
                let file_offset_in_section = sfile.offset - s.section_offset;
                let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);

                let mut page = [0u8; PAGE_SIZE];
                let mut remaining = sfile.length;
                for page_index in 0..page_count {
                    let page_offset = file_offset_in_section + page_index * PAGE_SIZE as u64;
                    freader.read_at(page_offset, &mut page)?;

                    let to_write = remaining.min(PAGE_SIZE as u64) as usize;
                    out.write_all(&page[..to_write]).await?;
                    remaining -= to_write as u64;
                }
                return Ok(());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "segment file not in encrypted section",
        )
        .into())
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
