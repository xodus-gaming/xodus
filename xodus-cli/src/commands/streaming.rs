use std::{collections::HashMap, path::Path, vec};

use fs2::available_space;
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::{
    models::xvd::PAGE_SIZE,
    streaming,
    xvd::{SegmentFile, XvdFile},
};
use tokio::fs::OpenOptions;
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::{
    license::get_license,
    package::{get_content_id, get_packages},
};

struct Job {
    name: String,
    content: SegmentFile,
}

enum ProgressEvent {
    Started { id: usize, name: String, total: u64 },
    Advanced { id: usize, delta: u64 },
    Finished { id: usize },
    UpdateRemaining { name: String, total: u64 },
    UpdateStatus { name: String },
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
) {
    let vurl = if source.starts_with("http://") || source.starts_with("https://") {
        source
    } else {
        let content_id = if Uuid::try_parse(&source).is_err() {
            let content_id_task = get_content_id(client, source, market.clone()).await;
            let Ok(content_id) = content_id_task else {
                let Err(err) = content_id_task else {
                    eprintln!("Unknown Error");
                    return;
                };
                eprintln!("{}", err);
                return;
            };
            content_id
        } else {
            source
        };
        let package_result = get_packages(client, tokens, content_id.clone()).await;
        let Ok(package) = package_result else {
            let Err(err) = package_result else {
                eprintln!("Unknown Error");
                return;
            };
            eprintln!("{}", err);
            return;
        };
        let Some(file) = package
            .package_files
            .iter()
            .find(|p| p.file_name.ends_with(".msixvc"))
        else {
            eprintln!("No .msixvc file found");
            return;
        };
        format!(
            "{}{}",
            file.cdn_root_paths.first().unwrap(),
            file.relative_url
        )
    };
    let url = &vurl;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    let mut pos = 0;
    let http_file = streaming::HttpRead::open(
        client.clone(),
        url,
        Some(|c, _| {
            if tx
                .try_send(ProgressEvent::Advanced {
                    id: usize::MAX,
                    delta: c - pos,
                })
                .is_ok()
            {
                pos = c;
            }
        }),
    )
    .await
    .expect("ok");
    let l = http_file.len();
    tokio::spawn(async move {
        let multi_progress = MultiProgress::new();
        let total_progess = multi_progress.add(ProgressBar::new(l as u64).with_style(
            ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
            .progress_chars("#>-")
        ));

        total_progess.set_message("Initializing");
        let mut bars: HashMap<usize, ProgressBar> = HashMap::new();

        while let Some(event) = rx.recv().await {
            match event {
                ProgressEvent::Started { id, name, total } => {
                    let cur_progess = multi_progress.add(ProgressBar::new(total).with_style(
                        ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
                        .progress_chars("#>-")
                    ));
                    cur_progess.set_message(name);
                    bars.insert(id, cur_progess);
                }
                ProgressEvent::Advanced { id, delta } => {
                    if let Some(bar) = bars.get(&id) {
                        bar.inc(delta);
                    }
                    total_progess.inc(delta);
                }
                ProgressEvent::Finished { id } => {
                    if let Some(bar) = bars.remove(&id) {
                        bar.finish_and_clear();
                    }
                }
                ProgressEvent::UpdateRemaining { name, total } => {
                    total_progess.set_message(name);
                    total_progess.set_length(total_progess.position() + total);
                }
                ProgressEvent::UpdateStatus { name } => {
                    total_progess.set_message(name);
                }
            }
        }

        total_progess.finish();
    });

    let out = Path::new(&destination);

    std::fs::create_dir_all(out).expect("ok");

    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = streaming::PrefixCacheFile::new(http_file, l, cache_path.clone())
        .await
        .expect("no err");
    let remote_xvd = XvdFile::parse(&mut remote_file).await.expect("no err");
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    if try_skip_ntfs {
        let files = remote_xvd
            .parse_user_package_files(&mut remote_file)
            .await
            .expect("ok");
        for (k, v) in &files {
            if k == "SegmentMetadata.bin" {
                let sfiles = remote_xvd
                    .parse_segment_metadata(&mut remote_file, v)
                    .await
                    .expect("ok");
                for (n, sfile) in &sfiles {
                    if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                        println!("{}: {} {}", n, sfile.offset, sfile.length);
                    }
                }
                rfiles = sfiles;
                // add unencrypted files of parse_user_package_files
                for (k, v) in &files {
                    rfiles.insert(
                        k.clone(),
                        SegmentFile {
                            offset: v.offset,
                            length: v.length,
                            data_hashs: vec![],
                        },
                    );
                }
            }
        }
    }

    if rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file)
            .await
            .expect("ok");
        for (n, sfile) in &sfiles {
            if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        rfiles = sfiles;
    }

    let file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .ok();

    if let Some(mut file) = file {
        let xvd = XvdFile::parse(&mut file).await.expect("no err");

        if try_skip_ntfs {
            let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
            for (k, v) in &files {
                if k == "SegmentMetadata.bin" {
                    let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
                    for (n, sfile) in &sfiles {
                        if sfile.length.div_ceil(PAGE_SIZE as u64) as usize
                            != sfile.data_hashs.len()
                        {
                            println!("{}: {} {}", n, sfile.offset, sfile.length);
                        }
                    }
                    lfiles = sfiles;
                    // add unencrypted files of parse_user_package_files
                    for (k, v) in &files {
                        lfiles.insert(
                            k.clone(),
                            SegmentFile {
                                offset: v.offset,
                                length: v.length,
                                data_hashs: vec![],
                            },
                        );
                    }
                }
            }
        }

        if lfiles.is_empty() {
            let sfiles = xvd
                .parse_ntfs_segment_metadata(&mut file)
                .await
                .expect("ok");
            for (n, sfile) in &sfiles {
                if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                    println!("{}: {} {}", n, sfile.offset, sfile.length);
                }
            }
            lfiles = sfiles;
        }
    }

    let license = get_license(
        client,
        tokens,
        remote_xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let total_size = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(_, v)| v.length)
        .reduce(|old, c| old + c)
        .map_or(0, |x| x);

    let remaining_cache_size = l.saturating_sub(remote_file.cached_len());
    let required_free_space = remaining_cache_size.saturating_add(total_size);
    let available_free_space = match available_space(out) {
        Ok(space) => space,
        Err(err) => {
            eprintln!(
                "failed to determine available space for {}: {}",
                out.display(),
                err
            );
            return;
        }
    };

    if available_free_space < required_free_space {
        eprintln!(
            "not enough free disk space on {}: need {} bytes, have {} bytes (remaining cache: {}, files: {})",
            out.display(),
            required_free_space,
            available_free_space,
            remaining_cache_size,
            total_size
        );
        return;
    }

    tx.send(ProgressEvent::UpdateRemaining {
        name: "Downloading".to_owned(),
        total: total_size,
    })
    .await
    .ok();

    let remote_xvd_ref = &remote_xvd;
    stream::iter(
        rfiles
            .iter()
            .filter(|(k, v1)| {
                if let Some(v2) = lfiles.get(*k) {
                    v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
                } else {
                    true
                }
            })
            .map(|(n, v)| Job {
                name: n.clone(),
                content: SegmentFile {
                    offset: v.offset,
                    length: v.length,
                    data_hashs: vec![],
                },
            })
            .enumerate(),
    )
    .for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
        let tx = tx.clone();
        async move {
            let client = reqwest::Client::new();
            let target_file = out.join(job.name.replace("\\", "/"));
            if let Some(folder) = target_file.parent() {
                std::fs::create_dir_all(folder).expect("ok");
            }
            let mut fout = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(target_file)
                .await
                .expect("ok");
            let mut lp = 0;

            let progress = |pos, _| {
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id,
                        delta: pos - lp,
                    })
                    .is_ok()
                {
                    lp = pos;
                }
            };
            let path = job.name.to_owned();
            let shown = if path.len() > 30 {
                format!("...{}", &path[path.len() - 27..])
            } else {
                path.clone()
            };
            tx.send(ProgressEvent::Started {
                id,
                name: shown,
                total: job.content.length,
            })
            .await
            .ok();

            remote_xvd_ref
                .download_file_http(
                    &client,
                    url.to_owned(),
                    &mut fout,
                    &job.content,
                    *full_key,
                    progress,
                )
                .await
                .expect("msg");
            tx.send(ProgressEvent::Finished { id }).await.ok();
        }
    })
    .await;

    std::fs::remove_file(&final_path).ok();
    std::fs::rename(&cache_path, &final_path).expect("ok");
}
