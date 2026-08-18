use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;
use std::vec;

use fs2::available_space;
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::streaming;
use msixvc::xvd::{SegmentFile, XvdFile};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::{get_content_id, get_packages};

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
) -> ExitCode {
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    // Only a network source can be resumed; a local file is already on disk.
    let mut resume_from = 0u64;
    if source.starts_with("file://") {
        let fsrc = source.strip_prefix("file://").unwrap_or_default();
        let f = match File::open(fsrc).await {
            Ok(f) => f,
            Err(err) => {
                eprintln!("could not open {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let l = match f.metadata().await {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                eprintln!("could not read metadata for {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        return run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            f,
            l,
            &source,
            &tx,
            rx,
            0,
        )
        .await;
    } else {
        let vurl = if source.starts_with("http://") || source.starts_with("https://") {
            source
        } else {
            let content_id = if Uuid::try_parse(&source).is_err() {
                let content_id_task = get_content_id(client, source, market.clone()).await;
                let Ok(content_id) = content_id_task else {
                    let Err(err) = content_id_task else {
                        eprintln!("Unknown Error");
                        return ExitCode::FAILURE;
                    };
                    eprintln!("{}", err);
                    return ExitCode::FAILURE;
                };
                content_id
            } else {
                source
            };
            let package_result = get_packages(client, tokens, content_id.clone()).await;
            let Ok(package) = package_result else {
                let Err(err) = package_result else {
                    eprintln!("Unknown Error");
                    return ExitCode::FAILURE;
                };
                eprintln!("{}", err);
                return ExitCode::FAILURE;
            };
            let Some(file) = package
                .package_files
                .iter()
                .find(|p| p.file_name.ends_with(".msixvc"))
            else {
                eprintln!("No .msixvc file found");
                return ExitCode::FAILURE;
            };
            format!(
                "{}{}",
                file.cdn_root_paths.first().unwrap(),
                file.relative_url
            )
        };
        let url = &vurl;

        // An interrupted download leaves its cache behind. Continue from there
        // rather than starting over: these packages run to tens of gigabytes,
        // and losing all of it to a closed lid or an unplugged drive is the
        // difference between an inconvenience and an unusable installer.
        std::fs::create_dir_all(&destination).ok();
        let cache_path = Path::new(&destination).join(".xodus-streaming-tmp.msixvc");
        resume_from = streaming::PrefixCacheFile::<File>::resumable_prefix(&cache_path).await;
        if resume_from > 0 {
            eprintln!(
                "Continuing from {:.1} GB already downloaded",
                resume_from as f64 / 1e9
            );
        }

        let mut pos = resume_from;
        let http_file = streaming::HttpRead::open_at(
            client.clone(),
            url,
            resume_from,
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

        return run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            http_file,
            l,
            url,
            &tx,
            rx,
            resume_from,
        )
        .await;
    }
}

async fn run_cli_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
    mut rx: Receiver<ProgressEvent>,
    resume_from: u64,
) -> ExitCode
where
    Reader: AsyncRead + Unpin,
{
    tokio::spawn(async move {
        let multi_progress = MultiProgress::new();
        let total_progess = multi_progress.add(ProgressBar::new(l).with_style(
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

        total_progess.abandon();
    });
    run_reader(
        client,
        tokens,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        reader,
        l,
        url,
        tx,
        resume_from,
    )
    .await
}

async fn run_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
    resume_from: u64,
) -> ExitCode
where
    Reader: AsyncRead + Unpin,
{
    let out: &Path = Path::new(&destination);

    std::fs::create_dir_all(out).expect("ok");

    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file =
        streaming::PrefixCacheFile::open(reader, l, cache_path.clone(), resume_from)
            .await
            .expect("no err");
    let remote_xvd = XvdFile::parse(&mut remote_file).await.expect("no err");
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

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
            rfiles = sfiles;
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
        return ExitCode::FAILURE;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return ExitCode::FAILURE;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return ExitCode::FAILURE;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file, !rfiles.is_empty(), Some(&full_key))
            .await
            .expect("ok");
        rfiles.extend(sfiles);
    }

    let file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .ok();

    if let Some(mut file) = file {
        let xvd = XvdFile::parse(&mut file).await.expect("no err");

        let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
        for (k, v) in &files {
            if k == "SegmentMetadata.bin" {
                let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
                lfiles = sfiles;
            }
        }

        if let Ok(sfiles) = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty(), Some(&full_key))
            .await
        {
            lfiles.extend(sfiles);
        }
    }


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

    let required_free_space = total_size;
    let available_free_space = match available_space(out) {
        Ok(space) => space,
        Err(err) => {
            eprintln!(
                "failed to determine available space for {}: {}",
                out.display(),
                err
            );
            return ExitCode::FAILURE;
        }
    };

    if available_free_space < required_free_space {
        eprintln!(
            "not enough free disk space on {}: need {} bytes, have {} bytes (files: {})",
            out.display(),
            required_free_space,
            available_free_space,
            total_size
        );
        return ExitCode::FAILURE;
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
                    keep_encrypted: v.keep_encrypted,
                },
            })
            .enumerate(),
    )
    .for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
        let tx = tx.clone();
        let client = client.clone();
        async move {
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

            if let Some(fpath) = url.strip_prefix("file://") {
                let mut i = File::open(&fpath).await.unwrap();
                remote_xvd_ref
                    .extract_file(&mut i, &mut fout, &job.content, *full_key, progress)
                    .await
                    .expect("msg");
                tx.send(ProgressEvent::Finished { id }).await.ok();
            } else {
                remote_xvd_ref
                    .download_file_http(&client, url, &mut fout, &job.content, *full_key, progress)
                    .await
                    .expect("msg");
                tx.send(ProgressEvent::Finished { id }).await.ok();
            }
        }
    })
    .await;

    std::fs::remove_file(&final_path).ok();
    std::fs::rename(&cache_path, &final_path).expect("ok");
    reclaim_package_payload(&final_path);
    ExitCode::SUCCESS
}

/// Hand back the part of the installed package that nothing reads again.
///
/// The package is kept beside the extracted game because launching needs it:
/// it carries the XVD header, the segment metadata and the content id the
/// licence is fetched against. It does not carry anything else worth keeping.
/// The ciphertext that gets decrypted at launch is read from the extracted
/// files, so the payload sitting in the package is never touched again -- and
/// it is what makes an install twice the size of the download. Hogwarts Legacy
/// asks for 190GB where Steam asks for 90.
///
/// Measured across every package here, a launch reads one contiguous run from
/// the start and stops: 7MB of 3.3GB for Deep Rock Galactic Survivor, 90MB of
/// 44GB for Expedition 33, 19MB of 9.5GB for Asphalt Legends -- 0.2% in each
/// case, through both the SegmentMetadata and the classic NTFS-metadata paths.
///
/// Punching the rest out rather than truncating keeps every offset in the file
/// valid, so nothing above needs to learn a new layout: the file still reports
/// its full length and reads back zeroes where the payload was. What is kept is
/// 1% or 64MB, whichever is larger -- five times the most any package has
/// needed, leaving room for one whose metadata runs longer than these.
///
/// A filesystem that cannot punch holes says so and keeps its blocks; that is
/// worth a word to the caller but not a failed install.
fn reclaim_package_payload(path: &Path) {
    use rustix::fs::{FallocateFlags, fallocate};

    let file = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("could not open the package to reclaim its payload: {err}");
            return;
        }
    };
    let size = match file.metadata() {
        Ok(meta) => meta.len(),
        Err(err) => {
            eprintln!("could not size the package: {err}");
            return;
        }
    };

    let keep = std::cmp::max(size / 100, 64 * 1024 * 1024);
    if keep >= size {
        return;
    }

    match fallocate(
        &file,
        FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
        keep,
        size - keep,
    ) {
        Ok(()) => println!(
            "reclaimed {} MiB from the package; {} MiB kept for launching",
            (size - keep) / (1024 * 1024),
            keep / (1024 * 1024)
        ),
        Err(err) => eprintln!("could not reclaim the package payload: {err}"),
    }
}
