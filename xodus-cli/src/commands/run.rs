use std::os::fd::{AsFd, AsRawFd, IntoRawFd};
use std::{collections::HashMap, path::Path};

use msixvc::{
    models::xvd::PAGE_SIZE,
    xvd::{SegmentFile, XvdFile},
};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use tokio::fs::{File, OpenOptions};
use tokio::process::Command;
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
    wine: String,
    exe: Option<String>,
    market: Option<String>,
) {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let out_absolute = std::fs::canonicalize(out).unwrap();
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

    // Classic files
    if lfiles.is_empty() {
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
    }

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
        if !file.1.keep_encrypted {
            continue;
        }
        let mut game_exe = File::from_std(make_temp_file().unwrap());

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        xvd.mount_mem_fd(&mut i, &mut game_exe, &file.1, *full_key, |_, _| {})
            .await
            .unwrap();

        let stdf = game_exe.into_std().await;

        let mut flags = fcntl_getfd(stdf.as_fd()).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(stdf.as_fd(), flags).unwrap();

        fds.push((file.0, stdf.into_raw_fd()));
    }

    let mut env_value = String::new();
    let nt_prefix = out_absolute.to_string_lossy().replace("/", "\\");
    let nt_prefix = nt_prefix.trim_end_matches('\\');

    let mut nt_entry = None;

    for fd in fds {
        if !env_value.is_empty() {
            env_value.push('|');
        }

        let nt_suffix = fd.0.trim_start_matches('\\');
        let nt_path = format!("\\??\\Z:{}\\{}", nt_prefix, nt_suffix);
        if let Some(exe) = &exe {
            if *exe == fd.0 {
                nt_entry = Some(nt_path)
            }
        } else if nt_entry.is_none() {
            nt_entry = Some(nt_path)
        }

        env_value.push_str(&format!("{}:\\??\\Z:{}\\{}", fd.1, nt_prefix, nt_suffix))
    }

    let Some(nt_entry) = nt_entry else {
        eprintln!("Could not find .exe");
        return;
    };

    Command::new(wine)
        .arg(nt_entry)
        .env("WINE_DLL_FILE_MAP", env_value)
        .status()
        .await
        .unwrap();
}
