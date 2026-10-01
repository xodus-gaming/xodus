use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Div;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aes::cipher::KeyInit;
use aes::{Aes128Dec, Aes128Enc};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use msixvc_common::parse::{BinaryParse, BinaryTryParse};
use reqwest::Client;
use reqwest::header::RANGE;
use sha2::Digest;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zerocopy::IntoBytes;

use crate::crypt::{TweakGenerator, decrypt_page_xts};
use crate::layout::{PAGE_SIZE, Pages};
use crate::models::xvd::layout::{HASH_ENTRY_LENGTH, HashTreeLevel, XvdLayout};
use crate::models::xvd::{
    HASH_ENTRIES_IN_PAGE, XvcInfo, XvcRegionHeader, XvcRegionSpecifier, XvdHashEntry, XvdHeader,
    XvdSegmentMetadataHeader, XvdSegmentMetadataSegment, XvdUserDataHeader,
    XvdUserDataPackageFileEntry, XvdUserDataPackageFilesHeader,
};

async fn start_stream(
    client: &Client,
    url: &str,
    stall_timeout: Duration,
    start: usize,
    end: usize,
) -> Option<impl futures_core::Stream<Item = reqwest::Result<Bytes>>> {
    let mut req = client.get(url);
    let status_code = if end != 0 {
        req = req.header(RANGE, format!("bytes={start}-{end}"));
        206
    } else if start != 0 {
        req = req.header(RANGE, format!("bytes={start}-"));
        206
    } else {
        200
    };
    if let Ok(Ok(Ok(response))) = timeout(stall_timeout, req.send())
        .await
        .map(|o| o.map(|o| o.error_for_status()))
        && response.status() == status_code
    {
        Some(response.bytes_stream())
    } else {
        None
    }
}

fn http_reader(
    c2: Client,
    urls: Vec<String>,
    out_io: Sender<Bytes>,
    start: usize,
    end: usize,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let stall_timeout = Duration::from_secs(5);
        let mut v = start;
        let urls_len: usize = urls.len();
        let mut url_i = 0;
        let mut stream = start_stream(&c2, &urls[url_i], stall_timeout, v, end).await;
        url_i = (url_i + 1) % urls_len;
        loop {
            if v > end && end != 0 {
                return;
            }
            let next = if let Some(s) = stream.as_mut() {
                timeout(stall_timeout, s.next()).await
            } else {
                Ok(None)
            };
            let data;
            if let Ok(Some(Ok(b))) = next {
                data = b;
            } else {
                // error
                stream = start_stream(&c2, &urls[url_i], Duration::from_secs(5), v, end).await;
                url_i = (url_i + 1) % urls_len;
                continue;
            }

            v += data.len();

            if out_io.send(data).await.is_err() {
                return;
            }
        }
    })
}

fn file_reader(path: String, out_io: Sender<Bytes>, start: usize, end: usize) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut f = File::open(path).unwrap();
        f.seek(SeekFrom::Start(start as u64)).unwrap();
        let mut pos = start;
        assert!(start <= end || end == 0, "{start} {end}");
        let byte_len = 16 * 4096 * 4096;
        let mut buf = bytes::BytesMut::with_capacity(32 * byte_len);
        buf.resize(buf.capacity(), 0u8);
        let mut b = VecDeque::with_capacity(32);
        for _ in 0..32 {
            b.push_back(buf.split_to(byte_len).freeze());
        }

        loop {
            // Try to reclaim buffer from dequeue or reallocate
            let mut buf: BytesMut = b.pop_front().unwrap().into();
            let max_read = if end == 0 {
                buf.len()
            } else {
                min(end + 1 - pos, buf.len())
            };
            if max_read == 0 {
                // End of Substream
                break;
            }
            f.read_exact(&mut buf[..max_read]).unwrap();
            let m: Bytes = buf.freeze();
            b.push_back(m.clone());
            pos += max_read;
            if let Err(_) = out_io.blocking_send(m) {
                // channel closed is the only error
                break;
            }
        }
    })
}

pub trait RangeReaderFactory {
    fn new(&self, out_io: Sender<Bytes>, start: usize, end: usize) -> JoinHandle<()>;
}

pub struct FileReaderFactory {
    pub path: String,
}

impl RangeReaderFactory for FileReaderFactory {
    fn new(&self, out_io: Sender<Bytes>, start: usize, end: usize) -> JoinHandle<()> {
        file_reader(self.path.clone(), out_io, start, end)
    }
}

pub struct HttpReaderFactory {
    pub client: Client,
    pub urls: Vec<String>,
}

impl RangeReaderFactory for HttpReaderFactory {
    fn new(&self, out_io: Sender<Bytes>, start: usize, end: usize) -> JoinHandle<()> {
        http_reader(self.client.clone(), self.urls.clone(), out_io, start, end)
    }
}

fn fetch_and_verify_top_level<ReaderFactory>(
    reader: &ReaderFactory,
    layout: &XvdLayout,
    top_level_hash: &[u8; 32],
    top_level: &HashTreeLevel,
) -> Vec<u8>
where
    ReaderFactory: RangeReaderFactory,
{
    let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
    reader.new(
        out_io,
        (layout.hash_tree.start + top_level.page_range.start)
            .to_bytes()
            .0 as usize,
        (layout.hash_tree.start + top_level.page_range.end)
            .to_bytes()
            .0 as usize
            - 1,
    );
    let mut l3_hashs = vec![0u8; 4096];
    read_full(&mut in_prov_valid, &mut l3_hashs, None);
    let mut sha = sha2::Sha256::new();
    sha.update(&l3_hashs);
    if sha.finalize()[0..32] != *top_level_hash {
        panic!("TODO");
    }
    l3_hashs
}

fn fetch_and_verify_hash_level<ReaderFactory>(
    reader: &ReaderFactory,
    layout: &XvdLayout,
    upper_hashs: &[u8],
    lower_level: &HashTreeLevel,
) -> Vec<u8>
where
    ReaderFactory: RangeReaderFactory,
{
    let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
    reader.new(
        out_io,
        (layout.hash_tree.start + lower_level.page_range.start)
            .to_bytes()
            .0 as usize,
        (layout.hash_tree.start + lower_level.page_range.end)
            .to_bytes()
            .0 as usize
            - 1,
    );

    let mut l2_hashs = Vec::with_capacity(lower_level.num_pages().to_bytes().0 as usize);
    l2_hashs.resize(l2_hashs.capacity(), 0u8);
    read_full(&mut in_prov_valid, &mut l2_hashs, None);
    for (i, c) in upper_hashs
        .chunks_exact(4096)
        .flat_map(|p| p.chunks_exact(HASH_ENTRY_LENGTH))
        .take(lower_level.num_pages().0 as usize)
        .map(XvdHashEntry::from_slice)
        .enumerate()
    {
        let mut sha = sha2::Sha256::new();
        sha.update(&l2_hashs[i * 4096..(i + 1) * 4096]);
        if sha.finalize()[0..20] != c.block_hash {
            panic!("TODO");
        }
    }
    l2_hashs
}

pub struct Package {
    pub xvd_header: XvdHeader,
    pub hashes: Arc<Vec<u8>>,
    pub package_full_name: String,
    pub xvc_info: XvcInfo,
    pub sfiles: Vec<(String, u64, u64, u64)>,
    pub region_headers: Vec<XvcRegionHeader>,
    pub region_specs: Vec<XvcRegionSpecifier>,
    pub region_flags: Vec<u32>,
    pub package_files: HashMap<String, String>,
}

impl Package {
    pub fn dump(&self) {
        println!("package_full_name: {}", self.package_full_name);
        for (n, v) in &self.package_files {
            println!("{}\n{}", n, v);
        }
        for (r, f) in self.region_headers.iter().zip(&self.region_flags) {
            let c = r.description.iter().take_while(|c| **c != 0).count();

            println!(
                "Region: {:x} {} {:?} {:x}",
                u32::from_le_bytes(r.region_id.to_le_bytes()),
                String::from_utf16(&r.description[0..c]).unwrap_or_else(|_| "<error>".to_owned()),
                r.flags,
                f
            );
            for s in self
                .region_specs
                .iter()
                .filter(|s| r.region_id == s.region_id)
            {
                let kl = s.key.iter().take_while(|c| **c != 0).count();
                let vl = s.value.iter().take_while(|c| **c != 0).count();
                println!(
                    " {} {}",
                    String::from_utf16(&s.key[..kl]).unwrap_or_else(|_| "<error>".to_owned()),
                    String::from_utf16(&s.value[..vl]).unwrap_or_else(|_| "<error>".to_owned()),
                );
            }
        }
    }

    pub async fn download<ReaderFactory>(
        &self,
        reader: ReaderFactory,
        file_name: String,
        full_key: Option<[u8; 32]>,
    ) where
        ReaderFactory: RangeReaderFactory + Send + 'static,
    {
        let hashes = self.hashes.clone();
        let layout = self.xvd_header.layout();
        let header = self.xvd_header.clone();
        let mut region_headers: &[XvcRegionHeader] = &self.region_headers;
        let mut region_offset = 0;
        for (i, (entry, bs, _, ps)) in (&self.sfiles).iter().enumerate() {
            while region_headers.len() > 1 && region_headers[1].first_segment_index as usize <= i {
                region_headers = &region_headers[1..];
                region_offset = 0;
            }
            if *entry != file_name {
                region_offset += *ps;
                continue;
            }
            let o = region_offset as u64;
            let ps = *ps;
            let bs = *bs;
            let region = region_headers[0].clone();
            let _ = tokio::task::spawn_blocking(move || {
                let mut fout = File::create(&file_name).unwrap();
                let mut hr = HashedReader::new(
                    &reader,
                    &hashes,
                    &layout,
                    region.offset + Pages(o as u32),
                    Some(Pages(ps as u32)),
                );
                if region.key_id.is_encrypted() {
                    hr.decryption = full_key
                        .map(|full_key| DecryptionsRuntime::new(&header, &region, full_key));
                }
                let mut buf = [0u8; 4096];
                let mut written = 0;
                while written < ps {
                    hr.read_full(&mut buf);
                    fout.write_all(&buf).unwrap();
                    written += 1;
                }
                if !region.key_id.is_encrypted() || full_key.is_some() {
                    fout.set_len(bs).unwrap();
                }
                fout.sync_all().unwrap();
            })
            .await;
            return;
        }
    }

    pub async fn download_all<ReaderFactory>(
        &self,
        reader: ReaderFactory,
        destination: String,
        full_key: Option<[u8; 32]>,
    ) where
        ReaderFactory: RangeReaderFactory + Send + 'static,
    {
        let hashes = self.hashes.clone();
        let layout = self.xvd_header.layout();
        let header = self.xvd_header.clone();
        let mut region_headers: &[XvcRegionHeader] = &self.region_headers;
        let mut region_offset = region_headers[0].offset;
        let mut file_map = Vec::new();
        for (i, (entry, bs, _, ps)) in (&self.sfiles).iter().enumerate() {
            while region_headers.len() > 1 && region_headers[1].first_segment_index as usize <= i {
                region_headers = &region_headers[1..];
                region_offset = region_headers[0].offset;
            }
            let o = region_offset;
            let ps = *ps;
            let bs = *bs;
            let region = region_headers[0].clone();
            file_map.push((region, entry.to_string(), o, ps, bs));
            region_offset += Pages(ps as u32);
        }
        let offset = Pages(file_map.first().unwrap().0.offset.0 as u32);
        let length =
            Pages((file_map.last().unwrap().2.0 as u64 + file_map.last().unwrap().3) as u32) - offset;

        let _ = tokio::task::spawn_blocking(move || {
            let mut hr = HashedReader::new(&reader, &hashes, &layout, offset, Some(length));
            let byte_len = 256 * 4096 * 4096;
            let mut buf = bytes::BytesMut::with_capacity(byte_len);
            buf.resize(byte_len, 0);
            for (region, entry, o, ps, bs) in file_map {
                hr.read_full_discard(o.to_bytes().0 as usize - hr.stream_pos);
                hr.assert_position(o.to_bytes().0 as usize);
                let file_name = PathBuf::from(&destination).join(entry.replace("\\", "/"));
                std::fs::create_dir_all(file_name.parent().unwrap()).unwrap();
                let mut fout = File::create(file_name).unwrap();
                if region.key_id.is_encrypted() && hr.decryption.is_none() {
                    hr.decryption = full_key
                        .map(|full_key| DecryptionsRuntime::new(&header, &region, full_key));
                }
                let mut written = 0;
                while written < ps {
                    let bytes_to_copy = min(buf.len(), ((ps - written) * 4096) as usize);
                    hr.read_full(&mut buf[..bytes_to_copy]);
                    fout.write_all(&buf[..bytes_to_copy]).unwrap();
                    written += (bytes_to_copy / 4096) as u64;
                }
                if !region.key_id.is_encrypted() || full_key.is_some() {
                    fout.set_len(bs).unwrap();
                }
                fout.sync_all().unwrap();
            }
        })
        .await;
    }
}

pub async fn stream_fast<ReaderFactory>(
    reader: ReaderFactory,
) -> Result<Package, Box<dyn std::error::Error>>
where
    ReaderFactory: RangeReaderFactory + Send + 'static,
{
    let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
    reader.new(out_io, 0, 4096);
    let r = tokio::task::spawn_blocking(move || {
        (|| -> Result<Package, Box<dyn std::error::Error>> {
            let mut xvd_header_buf = XvdHeader::buffer();
            let _ = read_full(&mut in_prov_valid, &mut xvd_header_buf, None);
            let xvd_header = XvdHeader::try_from_array(&xvd_header_buf)?;
            let layout = xvd_header.layout();
            let target_offset = layout.user_data.start.to_bytes().0 as usize;
            let target_end = target_offset + layout.user_data.len.0 as usize;

            let top_level = layout.hash_tree_layout.level3;
            let second_level = layout.hash_tree_layout.level2;
            let third_level = layout.hash_tree_layout.level1;

            let l1_hashs = Arc::new({
                if top_level.is_top() {
                    let l3_hashs = fetch_and_verify_top_level(
                        &reader,
                        &layout,
                        &xvd_header.top_hash_block_hash,
                        &top_level,
                    );
                    let l2_hashs =
                        fetch_and_verify_hash_level(&reader, &layout, &l3_hashs, &second_level);
                    fetch_and_verify_hash_level(&reader, &layout, &l2_hashs, &third_level)
                } else if second_level.is_top() {
                    let l2_hashs = fetch_and_verify_top_level(
                        &reader,
                        &layout,
                        &xvd_header.top_hash_block_hash,
                        &second_level,
                    );
                    fetch_and_verify_hash_level(&reader, &layout, &l2_hashs, &third_level)
                } else if third_level.is_top() {
                    fetch_and_verify_top_level(
                        &reader,
                        &layout,
                        &xvd_header.top_hash_block_hash,
                        &third_level,
                    )
                } else {
                    panic!("No way unsupported");
                }
            });

            let mut hr = HashedReader::new(
                &reader,
                &l1_hashs,
                &layout,
                Pages(target_offset.div(4096) as u32),
                Some(Pages(target_end.div_ceil(4096) as u32)),
            );

            let mut xvc_info_reader = HashedReader::new(
                &reader,
                &l1_hashs,
                &layout,
                layout.xvc_info.start,
                Some(layout.xvc_info.len.to_page_count()),
            );

            let mut buf = XvdUserDataHeader::buffer();
            hr.read_full(&mut buf);
            let user_data_header = XvdUserDataHeader::from_array(&buf);
            if user_data_header.t != 0 {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "error",
                )));
            }
            let mut sfiles = Vec::new();
            let mut package_files = HashMap::<String, String>::new();
            let package_full_name = {
                hr.read_full_discard(user_data_header.length as usize - XvdUserDataHeader::SIZE);
                let mut buf = XvdUserDataPackageFilesHeader::buffer();
                hr.read_full(&mut buf);
                let user_data_package_files_header =
                    XvdUserDataPackageFilesHeader::from_array(&buf);
                let package_full_name = String::from_utf16(
                    &user_data_package_files_header.package_full_name[0
                        ..user_data_package_files_header
                            .package_full_name
                            .iter()
                            .enumerate()
                            .find_map(|(i, c)| if *c == 0 { Some(i) } else { None })
                            .unwrap_or(0)],
                )?;
                let mut buf = XvdUserDataPackageFileEntry::buffer();
                let mut files = Vec::new();
                for _ in 0..user_data_package_files_header.file_count {
                    hr.read_full(&mut buf);
                    let user_data_package_file_entry =
                        XvdUserDataPackageFileEntry::from_array(&buf);
                    let o = user_data_package_file_entry.offset;
                    let s: u32 = user_data_package_file_entry.size;
                    let fullname = user_data_package_file_entry.file_path;
                    let end = fullname
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(fullname.len());
                    let pfull_name: String = String::from_utf16(&fullname[..end])?;
                    files.push((pfull_name, o, s));
                }
                for (file, o, s) in files {
                    let data_offset =
                        layout.user_data.start.to_bytes().0 as usize + XvdUserDataHeader::SIZE;
                    hr.assert_position(data_offset + o as usize);
                    if file.ends_with("SegmentMetadata.bin") {
                        let segment_header = {
                            let mut buf = XvdSegmentMetadataHeader::buffer();
                            hr.read_full(&mut buf);
                            XvdSegmentMetadataHeader::try_from_array(&buf)?
                        };

                        let mut segments =
                            Vec::with_capacity(segment_header.segment_count as usize);
                        let mut buf = XvdSegmentMetadataSegment::buffer();
                        for _ in 0..segment_header.segment_count {
                            hr.read_full(&mut buf);
                            let segment = XvdSegmentMetadataSegment::from_array(&buf);
                            segments.push(segment);
                        }

                        let mut page_offset = 0;

                        for segment in segments {
                            let s = segment.path_length;
                            let mut buf = vec![0u16, 0];
                            buf.resize(s as usize, 0);
                            hr.read_full(buf.as_mut_bytes());
                            // null u16, actually pretty useless waste of space
                            hr.read_full_discard(2);
                            let file_name: String = String::from_utf16(buf.as_slice())?;
                            let page_length = if segment.filesize == 0 {
                                1
                            } else {
                                segment.filesize.div_ceil(PAGE_SIZE as u64)
                            };
                            sfiles.push((file_name, segment.filesize, page_offset, page_length));
                            page_offset += page_length;
                        }
                    } else if file.ends_with(".config") || file.ends_with(".json") {
                        let mut data = Vec::with_capacity(s as usize);
                        data.resize(data.capacity(), 0);
                        hr.read_full(&mut data);
                        package_files.insert(file, String::from_utf8(data)?);
                    } else {
                        hr.read_full_discard(s as usize);
                    }
                    hr.assert_position(data_offset + (o + s) as usize);
                }
                package_full_name
            };

            if layout.xvc_info.len.0 == 0 {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "error",
                )));
            }
            let (xvc_info, region_headers, region_specs, region_flags) = {
                let xvc_info = {
                    let mut buf = XvcInfo::buffer();
                    xvc_info_reader.read_full(&mut buf);
                    XvcInfo::from_array(&buf)
                };
                let region_count = xvc_info.region_count;
                let mut region_headers: Vec<XvcRegionHeader> =
                    Vec::with_capacity(region_count as usize);
                let mut region_specs: Vec<XvcRegionSpecifier> =
                    Vec::with_capacity(xvc_info.region_specifier_count as usize);
                let mut region_flags: Vec<u32> = Vec::with_capacity(region_count as usize);
                if xvc_info.version >= 1 {
                    let mut buf = XvcRegionHeader::buffer();
                    for _ in 0..region_count {
                        xvc_info_reader.read_full(&mut buf);
                        let region_header = XvcRegionHeader::try_from_array(&buf)?;
                        region_headers.push(region_header);
                    }
                    xvc_info_reader
                        .read_full_discard((xvc_info.update_segment_count * 12) as usize);
                    let mut buf = XvcRegionSpecifier::buffer();
                    for _ in 0..xvc_info.region_specifier_count {
                        xvc_info_reader.read_full(&mut buf);
                        let region_spec = XvcRegionSpecifier::from_array(&buf);
                        region_specs.push(region_spec);
                    }
                    if layout.mutable_data.len.0 > 0 {
                        let mut buf = [0u8; 1];
                        for _ in 0..region_count {
                            xvc_info_reader.read_full(&mut buf);
                            region_flags.push(buf[0] as u32);
                        }
                    }
                }
                (xvc_info, region_headers, region_specs, region_flags)
            };
            Ok(Package {
                xvd_header,
                hashes: l1_hashs,
                package_full_name,
                sfiles,
                xvc_info,
                region_headers,
                region_specs,
                region_flags,
                package_files,
            })
        })()
        .unwrap()
    })
    .await?;
    Ok(r)
}

#[tokio::test]
async fn test_read_fast2() -> Result<(), Box<dyn std::error::Error>> {
    let c = reqwest::Client::new();
    let url1 = "http://assets1.xboxlive.com/14/aa14a80d-58ae-492a-8a48-b9e5ae421187/1d4dfd7a-d46b-4eaa-b2d2-d855c95bbbd1/1.75.0.0.119fa092-373a-4e87-a067-e3c4f7efa433/RawFury.StarTrucker_1.75.0.0_x64__9s0pnehqffj7t.msixvc";
    let url2 = "http://assets2.xboxlive.com/14/aa14a80d-58ae-492a-8a48-b9e5ae421187/1d4dfd7a-d46b-4eaa-b2d2-d855c95bbbd1/1.75.0.0.119fa092-373a-4e87-a067-e3c4f7efa433/RawFury.StarTrucker_1.75.0.0_x64__9s0pnehqffj7t.msixvc";

    stream_fast(HttpReaderFactory {
        client: c,
        urls: vec![url1.to_owned(), url2.to_owned()],
    })
    .await?
    .dump();
    Ok(())
}

#[tokio::test]
#[ignore = "needs local file"]
async fn test_read_fast3() -> Result<(), Box<dyn std::error::Error>> {
    stream_fast(FileReaderFactory {
        path: "StarTrucker.msixvc".to_owned(),
    })
    .await?
    .dump();
    Ok(())
}

fn read_full(
    in_prov_valid: &mut Receiver<Bytes>,
    data: &mut [u8],
    mut remaining_b: Option<Bytes>,
) -> Option<Bytes> {
    let mut offset = 0;
    while let Some(mut b) = remaining_b.take().or_else(|| in_prov_valid.blocking_recv()) {
        let m = min(offset + b.len(), data.len());
        data[offset..m].copy_from_slice(&b.split_to(m - offset));
        offset = m;
        if m == data.len() {
            return Some(b);
        }
    }
    None
}

struct ChannelReader {
    in_prov_valid: Receiver<Bytes>,
    remaining_b: Option<Bytes>,
}

impl ChannelReader {
    fn read_full(&mut self, b: &mut [u8]) {
        self.remaining_b = read_full(&mut self.in_prov_valid, b, self.remaining_b.take());
        let Some(_) = &self.remaining_b else {
            panic!("No data!");
        };
    }
}

struct DecryptionsRuntime {
    tweak: TweakGenerator,
    tweak_cipher: Aes128Enc,
    data_cipher: Aes128Dec,
}

impl DecryptionsRuntime {
    pub fn new(header: &XvdHeader, region_header: &XvcRegionHeader, full_key: [u8; 32]) -> Self {
        let mut tweak_key = [0u8; 16];
        let mut data_key = [0u8; 16];
        tweak_key.copy_from_slice(&full_key[..16]);
        data_key.copy_from_slice(&full_key[16..]);
        Self {
            tweak: TweakGenerator::new(region_header.region_id, header.vduid),
            tweak_cipher: Aes128Enc::new((&tweak_key).into()),
            data_cipher: Aes128Dec::new((&data_key).into()),
        }
    }

    pub fn decrypt(&self, page: &mut [u8; 4096], data_unit: u32) {
        let tweak = self.tweak.with_data_unit(data_unit);
        decrypt_page_xts(page, tweak, &self.tweak_cipher, &self.data_cipher);
    }
}

struct HashedReader<'t> {
    buffer: [u8; 4096],
    buffered_len: usize,
    data_reader: ChannelReader,
    hash_reader: ChannelReader,
    hash_buffer: [u8; 4096],
    hash_offset: usize,
    l1_hashs: &'t [u8],
    l1_hash_offset: usize,
    stream_pos: usize,
    decryption: Option<DecryptionsRuntime>,
}

impl<'t> HashedReader<'t> {
    fn new<ReaderFactory>(
        reader: &ReaderFactory,
        l1_hashs: &'t [u8],
        layout: &XvdLayout,
        data_start: Pages,
        data_length: Option<Pages>,
    ) -> Self
    where
        ReaderFactory: RangeReaderFactory,
    {
        let xvc_info_reader = {
            let (out_io, in_prov_valid) = mpsc::channel::<Bytes>(10);
            reader.new(
                out_io,
                data_start.to_bytes().0 as usize,
                data_length.map_or(0, |v| (data_start + v).to_bytes().0 as usize - 1),
            );
            ChannelReader {
                in_prov_valid: in_prov_valid,
                remaining_b: None,
            }
        };
        // absolute file page position where we load data
        let data_region_start = data_start;
        // page offset relative to hashed region of l0
        let hash_region_loc = data_region_start - layout.user_data.start;
        // page offset relative to hashed region of l0
        let hash_region_loc_pages = hash_region_loc.0 as usize;
        // page offset in l0 hash level
        let hash_pages = hash_region_loc_pages.div(HASH_ENTRIES_IN_PAGE);
        // hash index of l0 hash level
        let hash_pages_index = hash_region_loc_pages % HASH_ENTRIES_IN_PAGE;
        // page offset in l1 hash level
        let hash_pages_l1 = hash_pages.div(HASH_ENTRIES_IN_PAGE);
        // hash index of l1 hash level
        let hash_pages_l1_index = hash_pages % HASH_ENTRIES_IN_PAGE;
        let hash_bytes_start = (layout.hash_tree.start
            + layout.hash_tree_layout.level0.page_range.start
            + Pages(hash_pages as u32))
        .to_bytes()
        .0 as usize;
        let hash_reader = {
            let (hash_io, in_hash) = mpsc::channel::<Bytes>(10);
            reader.new(
                hash_io,
                hash_bytes_start,
                // Check correctness
                data_length.map_or(0, |v| {
                    hash_bytes_start + (v.0 as usize).div_ceil(HASH_ENTRIES_IN_PAGE) * 4096 - 1
                }),
            );
            ChannelReader {
                in_prov_valid: in_hash,
                remaining_b: None,
            }
        };
        let mut xvc_info_reader = Self {
            buffer: [0u8; 4096],
            hash_buffer: [0u8; 4096],
            hash_offset: hash_pages_index,
            buffered_len: 0,
            data_reader: xvc_info_reader,
            hash_reader: hash_reader,
            l1_hashs: &l1_hashs[4096 * hash_pages_l1..],
            l1_hash_offset: hash_pages_l1_index,
            stream_pos: data_start.to_bytes().0 as usize,
            decryption: None,
        };
        xvc_info_reader.fetch_next_l0_hash();

        xvc_info_reader
    }

    fn read_full(&mut self, b: &mut [u8]) {
        // we need to read ahead here by 4096 bytes
        let max_len = b.len();
        let buffered_len = self.buffered_len;
        let buffered_end = min(max_len, buffered_len);
        if buffered_end > 0 {
            b[0..buffered_end].copy_from_slice(
                &self.buffer[4096 - buffered_len..4096 - buffered_len + buffered_end],
            );
            self.buffered_len -= buffered_end;
        }
        if buffered_end < max_len {
            self.data_reader.read_full(&mut b[buffered_end..max_len]);
            // buffer to 4096 blocks
            let d_l = max_len - buffered_end;
            let hash_cnt = d_l.div_ceil(4096);
            self.buffered_len = (4096 - (d_l % 4096)) % 4096;
            self.data_reader
                .read_full(&mut self.buffer[4096 - self.buffered_len..4096]);

            for i in 0..hash_cnt {
                let c = XvdHashEntry::from_slice(if self.hash_offset < HASH_ENTRIES_IN_PAGE {
                    let item = &self.hash_buffer[self.hash_offset * HASH_ENTRY_LENGTH
                        ..(self.hash_offset + 1) * HASH_ENTRY_LENGTH];
                    self.hash_offset += 1;
                    item
                } else {
                    self.fetch_next_l0_hash();
                    let item = &self.hash_buffer[0..HASH_ENTRY_LENGTH];
                    self.hash_offset = 1;
                    item
                });
                // verify
                let mut sha = sha2::Sha256::new();
                if i + 1 < hash_cnt {
                    let sl = &mut b[buffered_end + i * 4096..buffered_end + (i + 1) * 4096];
                    sha.update(&sl);
                    self.decryption.as_mut().map(|d| {
                        let mut page = [0u8; 4096];
                        page.copy_from_slice(&sl);
                        d.decrypt(&mut page, c.unit);
                        sl.copy_from_slice(&page);
                    });
                } else {
                    assert!(
                        ((max_len - (buffered_end + i * 4096) + self.buffered_len) == 4096),
                        "BUG! we need a 4096 block"
                    );
                    let l = &mut b[buffered_end + i * 4096..max_len];
                    let r = &mut self.buffer[4096 - self.buffered_len..4096];
                    sha.update(&l);
                    sha.update(&r);
                    self.decryption.as_mut().map(|d| {
                        let mut page = [0u8; 4096];
                        page[..l.len()].copy_from_slice(&l);
                        page[l.len()..].copy_from_slice(&r);
                        d.decrypt(&mut page, c.unit);
                        l.copy_from_slice(&page[..l.len()]);
                        r.copy_from_slice(&page[l.len()..]);
                    });
                }
                if sha.finalize()[0..20] != c.block_hash {
                    panic!("SHA Mismatch!");
                }
            }
        }
        self.stream_pos += b.len();
    }
    fn read_full_discard(&mut self, l: usize) {
        let mut discard_buf = [0u8; 4096 * 8];
        let bz = discard_buf.len();
        let end = l.div(bz);
        for _ in 0..end {
            self.read_full(&mut discard_buf);
        }
        self.read_full(&mut discard_buf[0..l % bz]);
    }
    fn fetch_next_l0_hash(&mut self) {
        self.hash_reader.read_full(&mut self.hash_buffer);
        // check this hash
        if self.l1_hash_offset >= HASH_ENTRIES_IN_PAGE {
            self.l1_hash_offset = 0;
            self.l1_hashs = &self.l1_hashs[4096..];
        }
        let c = XvdHashEntry::from_slice({
            let item = &self.l1_hashs[self.l1_hash_offset * HASH_ENTRY_LENGTH
                ..(self.l1_hash_offset + 1) * HASH_ENTRY_LENGTH];
            self.l1_hash_offset += 1;
            item
        });
        let mut sha = sha2::Sha256::new();
        sha.update(&self.hash_buffer);
        if sha.finalize()[0..20] != c.block_hash {
            panic!("SHA Mismatch HT!");
        }
    }
    fn assert_position(&self, pos: usize) {
        assert!(self.stream_pos == pos, "{} vs {}", self.stream_pos, pos);
    }
}
