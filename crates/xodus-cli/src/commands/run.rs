use std::collections::HashMap;
use std::os::fd::{AsFd, IntoRawFd};
use std::path::Path;
use std::process::ExitCode;

use msixvc::models::xvd::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::{File, OpenOptions};
use tokio::process::Command;
use xodus::tokens::TokenManager;

use crate::license::get_license;

#[cfg(target_os = "linux")]
fn make_temp_file(_folder: &str) -> std::io::Result<std::fs::File> {
    let fd = memfd_create("xodus", MemfdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn make_temp_file(folder: &str) -> std::io::Result<std::fs::File> {
    if folder.is_empty() {
        tempfile()
    } else {
        tempfile_in(folder)
    }
}

#[cfg(target_os = "macos")]
async fn prepare(lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    let disk_size: u64 = lfiles
        .iter()
        .filter(|f| f.1.keep_encrypted)
        .map(|f| f.1.length + 4 * PAGE_SIZE as u64)
        .reduce(|o, s| o + s)
        .unwrap();

    let device_s = String::from_utf8(
        Command::new("/usr/bin/hdiutil")
            .arg("attach")
            .arg("-nomount")
            .arg(format!("ram://{}", disk_size.div_ceil(256)))
            .output()
            .await
            .unwrap()
            .stdout,
    )
    .unwrap();

    let device = device_s.trim();

    let vol = uuid::Uuid::new_v4().to_string();

    let fmt = Command::new("/sbin/newfs_hfs")
        .arg("-v")
        .arg(vol)
        .arg(device)
        .status()
        .await
        .unwrap();
    assert!(fmt.success());

    let mount_dir_obj = tempdir().unwrap();
    let mount_dir = mount_dir_obj.path().to_str().unwrap();

    let mnt = Command::new("/sbin/mount")
        .arg("-t")
        .arg("hfs")
        .arg("-o")
        .arg("nobrowse")
        .arg("-v")
        .arg(device)
        .arg(mount_dir)
        .status()
        .await
        .unwrap();
    assert!(mnt.success());
    let mount_dir_cl = mount_dir.to_string();
    let device_cl = device.to_string();
    (
        async move || {
            let mnt = Command::new("/sbin/umount")
                .arg("-f")
                .arg(mount_dir_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());

            let mnt = Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg("-force")
                .arg(&device_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());
        },
        mount_dir.to_owned(),
    )
}

#[cfg(not(target_os = "macos"))]
async fn prepare(_lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    (async || {}, "".to_owned())
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    wine: String,
    exe: Option<String>,
    market: Option<String>,
) -> ExitCode {
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

    let mut fds = vec![];

    let (cleanup, mount_dir) = prepare(&lfiles).await;

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let mut game_exe = File::from_std(make_temp_file(&mount_dir).unwrap());

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        xvd.mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
            .await
            .unwrap();

        let stdf = game_exe.into_std().await;

        let mut flags = fcntl_getfd(stdf.as_fd()).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(stdf.as_fd(), flags).unwrap();

        fds.push((file.0, stdf.into_raw_fd()));
    }

    // Sort fds deterministically by path
    fds.sort_by(|a, b| a.0.cmp(b.0));

    let mut env_value = String::new();
    let nt_prefix = out_absolute.to_string_lossy().replace("/", "\\");
    let nt_prefix = nt_prefix.trim_end_matches('\\');

    let mut nt_entry = None;

    let target_exe = match &exe {
        Some(user_exe) => Some(user_exe.clone()),
        None => {
            let paths: Vec<&str> = fds.iter().map(|(p, _)| p.as_str()).collect();
            select_default_exe(&paths)
        }
    };

    for fd in &fds {
        if !env_value.is_empty() {
            env_value.push('|');
        }

        let nt_suffix = fd.0.trim_start_matches('\\');
        let nt_path = format!("\\??\\Z:{}\\{}", nt_prefix, nt_suffix);
        if let Some(target) = &target_exe {
            let target_clean = target.trim_start_matches('\\');
            if target == fd.0 || target_clean == nt_suffix {
                nt_entry = Some(nt_path);
            }
        }

        env_value.push_str(&format!("{}:\\??\\Z:{}\\{}", fd.1, nt_prefix, nt_suffix));
    }

    let Some(nt_entry) = nt_entry else {
        eprintln!("Could not find .exe");
        return ExitCode::FAILURE;
    };

    let mut wn = Command::new(wine)
        .arg(nt_entry)
        .env("WINE_DLL_FILE_MAP", env_value)
        .spawn()
        .unwrap();

    let pid = wn.id().unwrap();

    ctrlc::set_handler(move || {
        if pid > 0 {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
        }
    })
    .expect("failed to install Ctrl+C handler");

    let status = wn.wait().await.unwrap();

    cleanup().await;

    ExitCode::from(status.code().map(|c| c as u8).unwrap_or(0))
}

/// Helper to select the default executable from candidate relative paths.
/// Evaluates executables deterministically:
/// 1. Filters paths ending with `.exe` (case-insensitive).
/// 2. Penalizes common helper/diagnostic/uninstaller binaries.
/// 3. Prefers shallower directory depths and shorter file names.
/// 4. Sorts by (score DESC, path ASC) to ensure 100% deterministic selection.
pub fn select_default_exe(paths: &[&str]) -> Option<String> {
    let mut exe_candidates: Vec<(&str, i32)> = paths
        .iter()
        .copied()
        .filter(|p| p.to_lowercase().ends_with(".exe"))
        .map(|p| {
            let p_lower = p.to_lowercase();
            let mut score = 100;

            let helper_keywords = [
                "crash",
                "reporter",
                "unins",
                "setup",
                "redist",
                "helper",
                "installer",
                "update",
                "tool",
                "diagnostics",
            ];
            for kw in helper_keywords {
                if p_lower.contains(kw) {
                    score -= 1000;
                }
            }

            let depth = p.chars().filter(|&c| c == '/' || c == '\\').count() as i32;
            score -= depth * 10;

            let filename = p.rsplit(&['/', '\\'][..]).next().unwrap_or(p);
            score -= filename.len() as i32;

            (p, score)
        })
        .collect();

    if exe_candidates.is_empty() {
        return None;
    }

    exe_candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));

    Some(exe_candidates[0].0.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_default_exe_picks_main_game_over_crash_reporter() {
        let paths = vec![
            "\\Engine\\Binaries\\Win64\\CrashReportClient.exe",
            "\\Asphalt9_x64.exe",
        ];
        let selected = select_default_exe(&paths);
        assert_eq!(selected, Some("\\Asphalt9_x64.exe".to_string()));
    }

    #[test]
    fn test_select_default_exe_deterministic_tie_breaking() {
        let paths = vec![
            "\\GameB.exe",
            "\\GameA.exe",
        ];
        let selected1 = select_default_exe(&paths);
        let selected2 = select_default_exe(&paths);
        assert_eq!(selected1, Some("\\GameA.exe".to_string()));
        assert_eq!(selected1, selected2);
    }

    #[test]
    fn test_select_default_exe_returns_none_when_no_exes() {
        let paths = vec!["\\data.bin", "\\texture.pak"];
        assert_eq!(select_default_exe(&paths), None);
    }
}

