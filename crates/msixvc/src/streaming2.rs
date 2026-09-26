use std::cmp::{max, min};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Div;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use msixvc_common::parse::{BinaryParse, BinaryTryParse};
use reqwest::Client;
use reqwest::header::RANGE;
use sha2::Digest;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinHandle;
use zerocopy::IntoBytes;

use crate::layout::{PAGE_SIZE, Pages};
use crate::models::xvd::layout::{HASH_ENTRY_LENGTH, MAX_HASHED_PAGES};
use crate::models::xvd::{HASH_ENTRIES_IN_PAGE, XvcRegionHeader, XvdHashEntry, XvdHeader, XvdSegmentMetadataHeader, XvdSegmentMetadataSegment, XvdUserDataHeader, XvdUserDataPackageFileEntry, XvdUserDataPackageFilesHeader};
use crate::xvd::UserPackageFile;

pub async fn download() -> Result<(), Box<dyn std::error::Error>> {
    let input_io = tokio::runtime::Builder::new_multi_thread().enable_io().max_blocking_threads(0).worker_threads(1).build()?;
    let c =  reqwest::Client::new();

    let xvd_header = {
        let mut buf = XvdHeader::buffer();
        
        // file.read_exact(&mut buf).await?;
        XvdHeader::try_from_array(&buf)?
    };
    // XvdHeader::SIZE

    // let layout = xvd_header.layout();

    // let mut region_headers: Vec<XvcRegionHeader> = Vec::new();

    // // TODO: Check if we have proper content type
    // if layout.xvc_info.len > Bytes(0) {
    //     file.seek(std::io::SeekFrom::Start(layout.xvc_info.start.to_bytes().0))
    //         .await
    //         .expect("Unable to seek");

    //     let xvc_info = {
    //         let mut buf = XvcInfo::buffer();
    //         file.read_exact(&mut buf).await?;
    //         XvcInfo::from_array(&buf)
    //     };

    //     let region_count = xvc_info.region_count;

    //     if xvc_info.version >= 1 {
    //         let mut buf = XvcRegionHeader::buffer();
    //         for _ in 0..region_count {
    //             file.read_exact(&mut buf).await?;
    //             let region_header = XvcRegionHeader::try_from_array(&buf)?;
    //             region_headers.push(region_header);
    //         }
        // }
    // }

    let mut tasks = Vec::new();
    // also send offset?
    let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
    let c2 = c.clone();
    tasks.push(input_io.spawn(async move {
        // reconnect and also track offset
        let ex = c2.get("").send().await.unwrap();
        let mut s = ex.bytes_stream();
        // handle connection timeout
        while let Some(s) = s.next().await {
            if let Ok(r) = s {
                // handle error?
                out_io.send(r).await;
            }
        }
    }));
    tasks.push(input_io.spawn_blocking(move || {
        let mut buffer = Vec::with_capacity(10);
        let cap = buffer.capacity();
        // reopen once next file range entered
        let mut file = std::fs::File::create("out.txt").unwrap();
        let mut page_buf = [0u8; 4096];
        let page_fill = 0;
        loop {
            buffer.clear();
            let size = in_prov_valid.blocking_recv_many(&mut buffer, cap);
            // this method blocks only returns 0 if the channel has been closed.
            if size == 0 {
                // metric shutdown
                break;
            }
            for i in 0..size {
                // decrypt
                let b = &mut buffer[i];
                let mut remaining = 4096 - page_fill;
                let cont = if b.remaining() >= remaining {
                    true
                } else {
                    remaining = b.remaining();
                    false
                };
                let x = b.split_off(remaining);

                // rechunk in 4096 blocks
                page_buf[page_fill..page_fill + remaining].copy_from_slice(&x);
                if !cont {
                    continue;
                }
                // where to get the hashtable data?
                // do sha
                // do decrypt
                // do write
                // TODO handle error
                file.write_all(&page_buf).unwrap();
            }
        }
    }));
    for l in tasks {
        l.await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_read_fast() -> Result<(), Box<dyn std::error::Error>>{
    let c =  reqwest::Client::new();

    let mut tasks = Vec::new();
    {
        let c2 = c.clone();
        let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
        tasks.push(tokio::spawn(async move {
            // let ex = c2.get("http://assets1.xboxlive.com/3/ce84470e-d9d8-48a7-a6b7-938f963cd8b4/b59198cb-4811-42c1-95d3-655f48da1b43/1.0.8.0.23eee6bd-8f9d-4e98-9ca9-3ab0e076fff1/Fictions.ProjectAibou_1.0.8.0_x64__qj8vnfjar8dk2.msixvc").send().await.unwrap();
            // let mut s = ex.bytes_stream();
            // // handle connection timeout
            // while let Some(s) = s.next().await {
            //     if let Ok(r) = s {
            //         // handle error?
            //         out_io.send(r).await;
            //     }
            // }
            let mut f = File::open("BeastofReincarnation.msixvc").unwrap();
            // f.metadata().
            let mut buf = bytes::BytesMut::with_capacity(64*4096*8);
            buf.resize(buf.capacity(), 0u8);
            let mut b = VecDeque::with_capacity(64);
            for _ in 0..64 {
                b.push_back(buf.split_to(4096*8).freeze());
            }
            
            loop {
                // Try to reclaim buffer from dequeue or reallocate
                let mut buf: BytesMut = b.pop_front().unwrap().into();
                f.read_exact(&mut buf).unwrap();
                let m: Bytes = buf.freeze();
                b.push_back(m.clone());
                if let Err(err) = out_io.send(m).await {
                    println!("{err}");
                    break;
                }
            }
        }));
        tasks.push(tokio::task::spawn_blocking(move ||{
            (|| -> Result<(), Box<dyn std::error::Error>> {
                let mut xvd_header_buf = XvdHeader::buffer();
                let data : &mut [u8] = &mut xvd_header_buf;
                let mut offset = 0;
                let mut remaining_b = None;
                while let Some(mut b) = in_prov_valid.blocking_recv() {
                    let m = min(offset + b.len(), data.len());
                    data[offset..m].copy_from_slice(&b.split_to(m - offset));
                    offset = m;
                    if m == data.len() {
                        remaining_b = Some(b);
                        break;
                    }
                }
                let xvd_header = XvdHeader::try_from_array(&xvd_header_buf)?;

                let target_offset = xvd_header.layout().user_data.start.to_bytes().0 as usize;
                offset += remaining_b.take().map_or_else(||0, |v|v.len());
                while let Some(mut b) = in_prov_valid.blocking_recv() {
                    let m = min(offset + b.len(), target_offset);
                    let _ = b.split_to(m - offset);
                    offset = m;
                    if m == target_offset {
                        remaining_b = Some(b);
                        break;
                    }
                }

                
                let mut buf = XvdUserDataHeader::buffer();
                remaining_b = read_full(&mut in_prov_valid, &mut buf, remaining_b);
                let user_data_header = XvdUserDataHeader::from_array(&buf);
                if user_data_header.t == 0 {
                    remaining_b = read_full_discard(&mut in_prov_valid, user_data_header.length as usize - XvdUserDataHeader::SIZE, remaining_b);
                    let mut buf = XvdUserDataPackageFilesHeader::buffer();
                    remaining_b = read_full(&mut in_prov_valid, &mut buf, remaining_b);
                    let user_data_package_files_header = XvdUserDataPackageFilesHeader::from_array(&buf);
                    let full_package_name = String::from_utf16(&user_data_package_files_header.package_full_name).unwrap();
                    println!("full_package_name={full_package_name}");
                    let mut buf = XvdUserDataPackageFileEntry::buffer();
                    for _ in 0..user_data_package_files_header.file_count {
                        remaining_b = read_full(&mut in_prov_valid, &mut buf, remaining_b);
                        let user_data_package_file_entry = XvdUserDataPackageFileEntry::from_array(&buf);
                        let o = user_data_package_file_entry.offset;
                        let s: u32 = user_data_package_file_entry.size;
                        let fullname = user_data_package_file_entry.file_path;
                        let end = fullname
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(fullname.len());
                        let pfull_name: String = String::from_utf16(&fullname[..end]).unwrap();

                        // files.insert(
                        //     pfull_name,
                        //     UserPackageFile {
                        //         offset: user_data_offset + XvdUserDataHeader::SIZE as u64 + o as u64,
                        //         length: s as u64,
                        //     },
                        // );
                        // println!("{} {:?}", pfull_name, UserPackageFile {
                        //     offset: user_data_offset + XvdUserDataHeader::SIZE as u64 + o as u64,
                        //     length: s as u64,
                        // });
                        println!("{}", pfull_name);
                        //     offset: user_data_offset + XvdUserDataHeader::SIZE as u64 + o as u64,
                        //     length: s as u64,
                        // });
                    }
                }

                Ok(())
            })().unwrap();
        }));
    };
    for l in tasks {
        l.await?;
    }
    Ok(())
}

fn http_reader(c2: Client, url: String, out_io: Sender<Bytes>, start: usize, end: usize) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut req = c2.get(url);
        if end != 0 {
            req = req.header(RANGE, format!("bytes={start}-{end}"))
        } else if start != 0 {
            req = req.header(RANGE, format!("bytes={start}-"))
        }
        let ex = req.send().await.unwrap();
        let mut s = ex.bytes_stream();
        // handle connection timeout
        while let Some(s) = s.next().await {
            if let Ok(r) = s {
                // handle error?
                out_io.send(r).await.unwrap();
            }
        }
    })
}

fn file_reader(path: String, out_io: Sender<Bytes>, start: usize, end: usize) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut f = File::open(path).unwrap();
        let mut buf = bytes::BytesMut::with_capacity(64*4096*8);
        buf.resize(buf.capacity(), 0u8);
        let mut b = VecDeque::with_capacity(64);
        for _ in 0..64 {
            b.push_back(buf.split_to(4096*8).freeze());
        }
        
        loop {
            // Try to reclaim buffer from dequeue or reallocate
            let mut buf: BytesMut = b.pop_front().unwrap().into();
            let r = f.read(&mut buf).unwrap();
            let m: Bytes = buf.freeze();
            b.push_back(m.clone().split_to(r));
            if let Err(err) = out_io.send(m).await {
                println!("{err}");
                break;
            }
        }
    })
}

#[tokio::test]
async fn test_read_fast2() -> Result<(), Box<dyn std::error::Error>>{
    let c =  reqwest::Client::new();
    let url = "http://assets1.xboxlive.com/11/a4d76fdf-087a-47a2-99a7-76a621eb4170/ab03f40c-e85d-467b-8c67-3870b89bd2d1/3.420.696.0.882e46cd-2099-4bee-a1df-052310b86c7a/Microsoft.ForteBaseGame_3.420.696.0_x64__8wekyb3d8bbwe.msixvc";

    let mut tasks = Vec::new();
    {
        let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
        tasks.push(http_reader(c.clone(), url.to_owned(), out_io.clone(), 0, 4096));
        let c2 = c.clone();
        tasks.push(tokio::task::spawn_blocking(move ||{
            (|| -> Result<(), Box<dyn std::error::Error>> {
                let mut xvd_header_buf = XvdHeader::buffer();
                let mut remaining_b = read_full(&mut in_prov_valid, &mut xvd_header_buf, None);
                let _ = remaining_b;
                let xvd_header = XvdHeader::try_from_array(&xvd_header_buf)?;
                if xvd_header.number_of_hashed_pages() < Pages(1) || xvd_header.number_of_hashed_pages() > MAX_HASHED_PAGES {
                    // actually an error, but ensure this to not cause panic in xvd_header.layout()
                    return Ok(());
                }
                let layout = xvd_header.layout();
                let target_offset = layout.user_data.start.to_bytes().0 as usize;
                let target_end = target_offset + layout.user_data.len.0 as usize;

                println!("{:?}", layout);

                let top_level = layout.hash_tree_layout.level3;
                let second_level = layout.hash_tree_layout.level2;
                let third_level = layout.hash_tree_layout.level1;
                let forth_level = layout.hash_tree_layout.level0;

                let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
                http_reader(c2.clone(), url.to_owned(), out_io.clone(), layout.hash_tree.start.to_bytes().0 as usize + top_level.page_range.start.to_bytes().0 as usize, layout.hash_tree.start.to_bytes().0 as usize + top_level.page_range.end.to_bytes().0 as usize - 1);
                let mut l2_hashs = [0u8; 4096];
                remaining_b = read_full(&mut in_prov_valid, &mut l2_hashs, None);
                let mut sha = sha2::Sha256::new();
                sha.update(l2_hashs);
                if sha.finalize()[0..32] != xvd_header.top_hash_block_hash {
                    panic!("TODO");
                }

                let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
                http_reader(c2.clone(), url.to_owned(), out_io.clone(), layout.hash_tree.start.to_bytes().0 as usize + second_level.page_range.start.to_bytes().0 as usize, layout.hash_tree.start.to_bytes().0 as usize + second_level.page_range.end.to_bytes().0 as usize - 1);

                let mut l1_hashs = Vec::with_capacity(second_level.num_pages().to_bytes().0 as usize);
                l1_hashs.resize(l1_hashs.capacity(), 0u8);
                remaining_b = read_full(&mut in_prov_valid, &mut l1_hashs, None);
                for (i, c) in l2_hashs.chunks_exact(HASH_ENTRY_LENGTH).take(second_level.num_pages().0 as usize).map(XvdHashEntry::from_slice).enumerate() {
                    let mut sha = sha2::Sha256::new();
                    sha.update(&l1_hashs[i * 4096..(i + 1) * 4096]);
                    if sha.finalize()[0..20] != c.block_hash {
                        panic!("TODO");
                    }
                }

                let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
                http_reader(c2.clone(), url.to_owned(), out_io.clone(), layout.hash_tree.start.to_bytes().0 as usize + third_level.page_range.start.to_bytes().0 as usize, layout.hash_tree.start.to_bytes().0 as usize + third_level.page_range.end.to_bytes().0 as usize - 1);

                let mut l0_hashs = Vec::with_capacity(second_level.num_pages().to_bytes().0 as usize);
                l0_hashs.resize(l0_hashs.capacity(), 0u8);
                remaining_b = read_full(&mut in_prov_valid, &mut l0_hashs, None);
                for (i, c) in l1_hashs.chunks_exact(4096).flat_map(|p| p.chunks_exact(HASH_ENTRY_LENGTH)).take(second_level.num_pages().0 as usize).map(XvdHashEntry::from_slice).enumerate() {
                    let mut sha = sha2::Sha256::new();
                    sha.update(&l0_hashs[i * 4096..(i + 1) * 4096]);
                    if sha.finalize()[0..20] != c.block_hash {
                        panic!("TODO");
                    }
                }

                let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
                http_reader(c2.clone(), url.to_owned(), out_io.clone(), layout.hash_tree.start.to_bytes().0 as usize + third_level.page_range.start.to_bytes().0 as usize, layout.hash_tree.start.to_bytes().0 as usize + third_level.page_range.end.to_bytes().0 as usize - 1);

                let mut l0_hashs = Vec::with_capacity(second_level.num_pages().to_bytes().0 as usize);
                l0_hashs.resize(l0_hashs.capacity(), 0u8);
                remaining_b = read_full(&mut in_prov_valid, &mut l0_hashs, None);
                for (i, c) in l1_hashs.chunks_exact(4096).flat_map(|p| p.chunks_exact(HASH_ENTRY_LENGTH)).take(second_level.num_pages().0 as usize).map(XvdHashEntry::from_slice).enumerate() {
                    let mut sha = sha2::Sha256::new();
                    sha.update(&l0_hashs[i * 4096..(i + 1) * 4096]);
                    if sha.finalize()[0..20] != c.block_hash {
                        panic!("TODO");
                    }
                }

                let data_len = layout.user_data.len.0 as usize;
                let pages_len = data_len.div_ceil(4096);
                // div_ceil, since we need to validate the hash block and that works only by having them fully.
                let hash_len_l0 = pages_len.div_ceil(HASH_ENTRIES_IN_PAGE) * 4096;
                let (out_hash, mut in_hash) = mpsc::channel::<Bytes>(100);
                http_reader(c2.clone(), url.to_owned(), out_hash, layout.hash_tree.start.to_bytes().0 as usize + third_level.page_range.start.to_bytes().0 as usize, layout.hash_tree.start.to_bytes().0 as usize + hash_len_l0 as usize - 1);

                let (out_io, mut in_prov_valid) = mpsc::channel::<Bytes>(100);
                http_reader(c2.clone(), url.to_owned(), out_io.clone(), target_offset, target_end);
                
                let mut buf = XvdUserDataHeader::buffer();
                remaining_b = read_full(&mut in_prov_valid, &mut buf, None);
                let user_data_header = XvdUserDataHeader::from_array(&buf);
                if user_data_header.t == 0 {
                    remaining_b = read_full_discard(&mut in_prov_valid, user_data_header.length as usize - XvdUserDataHeader::SIZE, remaining_b);
                    let mut buf = XvdUserDataPackageFilesHeader::buffer();
                    remaining_b = read_full(&mut in_prov_valid, &mut buf, remaining_b);
                    let user_data_package_files_header = XvdUserDataPackageFilesHeader::from_array(&buf);
                    let full_package_name = String::from_utf16(&user_data_package_files_header.package_full_name[0..user_data_package_files_header.package_full_name.iter().enumerate().find_map(|(i, c)| if *c == 0 { Some(i) } else { None }).unwrap_or(0)]).unwrap();
                    println!("full_package_name={full_package_name}");
                    let mut buf = XvdUserDataPackageFileEntry::buffer();
                    let mut files = Vec::new();
                    let mut sfiles = Vec::new();
                    for _ in 0..user_data_package_files_header.file_count {
                        remaining_b = read_full(&mut in_prov_valid, &mut buf, remaining_b);
                        let user_data_package_file_entry = XvdUserDataPackageFileEntry::from_array(&buf);
                        let o = user_data_package_file_entry.offset;
                        let s: u32 = user_data_package_file_entry.size;
                        let fullname = user_data_package_file_entry.file_path;
                        let end = fullname
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(fullname.len());
                        let pfull_name: String = String::from_utf16(&fullname[..end]).unwrap();
                        println!("{} | {} + {}", pfull_name, o, s);
                        files.push((pfull_name, o, s));
                    }
                    for (file, o, s) in files {
                        if file.ends_with("SegmentMetadata.bin") {
                            // let mut data =  Vec::with_capacity(s as usize);
                            // data.resize(data.capacity(), 0);
                            let segment_header = {
                                let mut buf = XvdSegmentMetadataHeader::buffer();
                                remaining_b = read_full(&mut in_prov_valid, &mut buf, remaining_b);
                                XvdSegmentMetadataHeader::try_from_array(&buf)?
                            };
                            let paths_offset =
                                segment_header.header_length as u64 + segment_header.segment_count as u64 * 0x10;

                            let mut segments = Vec::with_capacity(segment_header.segment_count as usize);
                            let mut buf = XvdSegmentMetadataSegment::buffer();
                            for _ in 0..segment_header.segment_count {
                                remaining_b = read_full(&mut in_prov_valid, &mut buf, remaining_b);
                                let segment = XvdSegmentMetadataSegment::from_array(&buf);
                                segments.push(segment);
                            }

                            let mut page_offset = 0;

                            for segment in segments {
                                let s = segment.path_length;
                                let mut buf = vec![0u16, 0];
                                buf.resize(s as usize, 0);
                                remaining_b = read_full(&mut in_prov_valid, buf.as_mut_bytes(), remaining_b);
                                remaining_b = read_full_discard(&mut in_prov_valid, 2, remaining_b);
                                let file_name: String = String::from_utf16(buf.as_slice()).unwrap();
                                let page_length = if segment.filesize == 0 {
                                    1
                                } else {
                                    segment.filesize.div_ceil(PAGE_SIZE as u64)
                                };
                                sfiles.push((file_name, segment.filesize, page_offset, page_length));
                                page_offset += page_length;
                            } 
                        } else if file.ends_with(".config") || file.ends_with(".json") {
                            let mut data =  Vec::with_capacity(s as usize);
                            data.resize(data.capacity(), 0);
                            remaining_b = read_full(&mut in_prov_valid, &mut data, remaining_b);
                            println!("{}\n{}", file, String::from_utf8_lossy(&data));
                        } else {
                            remaining_b = read_full_discard(&mut in_prov_valid, s as usize, remaining_b);
                        }
                    }
                    println!("done {}", sfiles.len());
                    for (name, l, po, ps) in sfiles {
                        println!("{name} {l}, {po}, {ps}")
                    }
                }
                Ok(())
            })().unwrap();
        }));
    };
    for l in tasks {
        l.await?;
    }
    Ok(())
}


fn read_full(in_prov_valid: &mut Receiver<Bytes>, data : &mut [u8], mut remaining_b: Option<Bytes>) -> Option<Bytes> {
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

fn read_full_discard(in_prov_valid: &mut Receiver<Bytes>, l: usize, mut remaining_b: Option<Bytes>) -> Option<Bytes> {
    let mut offset = 0;
    while let Some(mut b) = remaining_b.take().or_else(|| in_prov_valid.blocking_recv()) {
        let m = min(offset + b.len(), l);
        let _ = b.split_to(m - offset);
        offset = m;
        if m == l {
            return Some(b);
        }
    }
    None
}