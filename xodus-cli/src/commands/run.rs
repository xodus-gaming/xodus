use std::os::fd::{IntoRawFd, OwnedFd};
use std::{collections::HashMap, path::Path};

use msixvc::{
    models::xvd::PAGE_SIZE,
    xvd::{SegmentFile, XvdFile},
};
use rustix::path::Arg;
use tokio::fs::{File, OpenOptions};
use xodus::tokens::TokenManager;

use crate::license::get_license;

#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
#[cfg(not(target_os = "linux"))]
use tempfile::tempfile;

#[cfg(target_os = "linux")]
fn make_temp_file() -> std::io::Result<std::fs::File> {
    let fd = memfd_create("xodus", MemfdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn make_temp_file() -> std::io::Result<std::fs::File> {
    tempfile()
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    market: Option<String>,
) {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .unwrap();

    let xvd = XvdFile::parse(&mut file).await.expect("no err");

    let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
            for (n, sfile) in &sfiles {
                if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                    println!("{}: {} {}", n, sfile.offset, sfile.length);
                }
            }
            lfiles = sfiles;
        }
    }

    let sfiles = xvd
        .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
        .await
        .expect("ok");
    for (n, sfile) in &sfiles {
        if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
            println!("{}: {} {}", n, sfile.offset, sfile.length);
        }
    }
    lfiles.extend(sfiles);

    let license = get_license(
        client,
        tokens,
        xvd.content_id().to_string(),
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

    let mut fds = vec![];

    for file in lfiles {
        let mut game_exe = File::from_std(make_temp_file().unwrap());

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        xvd.mount_mem_fd(&mut i, &mut game_exe, &file.1, *full_key, |_, _| {})
            .await
            .unwrap();

        fds.push((source_path, game_exe.into_std().await.into_raw_fd()));
    }

    for fd in fds {
        println!("{}|{}", fd.1, fd.0.as_str().unwrap())
    }

    todo!("Implement this")
}
