use std::collections::HashMap;
use std::os::fd::{AsFd, IntoRawFd};
use std::path::{Path, PathBuf};
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
use tokio::io::{AsyncReadExt, AsyncSeekExt};
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
    mut exe: Option<String>,
    market: Option<String>,
    game_args: Vec<String>,
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

    // Classic files
    if lfiles.is_empty() {
        let sfiles = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty(), None)
            .await
            .expect("ok");
        for (n, sfile) in &sfiles {
            if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        lfiles.extend(sfiles);
    }


    let mut fds: Vec<(&String, std::os::fd::RawFd)> = vec![];

    let (cleanup, mount_dir) = prepare(&lfiles).await;

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let mut game_exe = File::from_std(make_temp_file(&mount_dir).unwrap());

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        // Which packages hand back an already-decrypted executable is decided by
        // how their metadata described it, not by anything we can see here, so
        // let the file itself say: a classic (NTFS-metadata) package extracts a
        // plain PE image at its true length, while a SegmentMetadata package
        // keeps page-aligned ciphertext. Decrypting an image that is already a
        // PE turns it into garbage, which is how Asphalt Legends ended up
        // failing with "invalid name" out of ShellExecuteEx.
        let mut magic = [0u8; 2];
        let plaintext = i.read_exact(&mut magic).await.is_ok() && &magic == b"MZ";
        i.seek(std::io::SeekFrom::Start(0)).await.unwrap();

        if plaintext {
            println!("{} is already decrypted; mapping it as-is", file.0);
            tokio::io::copy(&mut i, &mut game_exe).await.unwrap();
        } else {
            xvd.mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
                .await
                .unwrap();
        }

        let stdf = game_exe.into_std().await;

        let mut flags = fcntl_getfd(stdf.as_fd()).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(stdf.as_fd(), flags).unwrap();

        fds.push((file.0, stdf.into_raw_fd()));
    }

    let mut env_value = String::new();

    // The drive letter must be the one wine itself derives for these files.
    // The launched executable is fine either way because we hand wine its NT
    // path directly, but a title that spawns a helper of its own -- Asphalt
    // starts Crashpad's handler -- resolves the path through wine's drive
    // mappings. On a secondary drive that yields e.g. F:\..., which never
    // matches a map keyed on Z:\mnt\..., so the child is loaded from the
    // still-encrypted file on disk and fails ("crash server failed to launch").
    // Mirror wine's rule: the longest matching dosdevices target wins.
    let (nt_drive, nt_prefix) = wine_dos_path(&out_absolute);
    let nt_prefix = nt_prefix.trim_end_matches('\\').to_owned();

    let mut nt_entry = None;
    let mut nt_entry_fd = None;

    // `lfiles` is a HashMap and Rust seeds its hasher afresh every process, so
    // iteration order changed on every launch. With no --exe the first entry
    // won, which meant a package with several executables started a *different*
    // one each time: Subnautica 2 has four, so roughly one launch in four
    // started the game and the rest opened crashpad_handler ("--initial-client-
    // data or --pipe-name is required") or the prerequisite shim (which reports
    // "Microsoft Visual C++ 2015-2022 Redistributable is required"). That is the
    // whole of the "launches work on the second or third try" behaviour.
    fds.sort_by(|a, b| a.0.cmp(b.0));

    if exe.is_none() {
        if let Some(chosen) = auto_entry( &fds ) {
            eprintln!("XODUS_AUTO_EXE {chosen}");
            exe = Some(chosen);
        }
    }

    for fd in fds {
        if !env_value.is_empty() {
            env_value.push('|');
        }

        let nt_suffix = fd.0.trim_start_matches('\\');
        let nt_path = format!("\\??\\{}:{}\\{}", nt_drive, nt_prefix, nt_suffix);
        if let Some(exe) = &exe {
            if exe == fd.0 {
                nt_entry = Some(nt_path);
                nt_entry_fd = Some(fd.1);
            }
        } else if nt_entry.is_none() {
            nt_entry = Some(nt_path);
            nt_entry_fd = Some(fd.1);
        }

        env_value.push_str(&format!(
            "{}:\\??\\{}:{}\\{}",
            fd.1, nt_drive, nt_prefix, nt_suffix
        ))
    }

    eprintln!("XODUS_MAP drive={} prefix={}", nt_drive, nt_prefix);
    for e in env_value.split('|').take(4) { eprintln!("XODUS_MAP entry: {e}"); }

    let Some(mut nt_entry) = nt_entry else {
        eprintln!("Could not find .exe");
        return ExitCode::FAILURE;
    };

    // EXPERIMENT (XODUS_EXE_VIA_PROC=1): name the memfd by path instead of
    // handing wine an fd through WINE_DLL_FILE_MAP.
    //
    // /proc/self/fd/N is an ordinary openable path, and the fd is inherited, so
    // any wine -- including a stock Proton -- could map the image from it with
    // no patch at all. The plaintext still only ever exists in the memfd, so
    // nothing reaches the filesystem either way.
    if std::env::var("XODUS_EXE_VIA_PROC").is_ok() {
        if let Some(fd) = nt_entry_fd {
            nt_entry = format!("\\??\\Z:\\proc\\self\\fd\\{fd}");
            eprintln!("XODUS_EXE_VIA_PROC: launching {nt_entry}");
        }
    }

    let mut wn = Command::new(wine)
        .arg(nt_entry)
        .args(&game_args)
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

/// Which executable to start when the caller did not name one.
///
/// A game package ships more than the game: a crash handler, a crash reporter,
/// sometimes a prerequisite installer that only knows how to say what is
/// missing. Any of those will start, and none of them is the game, so the
/// choice is made on what the file is rather than on whichever one the
/// filesystem happened to yield first.
fn auto_entry(fds: &[(&String, std::os::fd::RawFd)]) -> Option<String> {
    let mut best: Option<(u8, &String)> = None;

    for (path, _) in fds {
        let name = path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(path)
            .to_ascii_lowercase();

        // Helpers a title spawns for itself. Starting one directly does
        // nothing useful and looks like a failed launch.
        if name.contains("crashpad")
            || name.contains("crashreport")
            || name.contains("crashhandler")
            || name.contains("prereqsetup")
            || name.contains("webhelper")
            || name.contains("subprocess")
        {
            continue;
        }

        // Unreal names its real binary <Project>-<Platform>-Shipping.exe; the
        // bare <Project>.exe beside it is a launcher shim, which on Subnautica 2
        // is the one that reports a missing redistributable.
        let rank = if name.ends_with("-shipping.exe") { 0 } else { 1 };

        if best.as_ref().is_none_or(|(best_rank, best_path)| {
            rank < *best_rank || (rank == *best_rank && path < best_path)
        }) {
            best = Some((rank, path));
        }
    }

    best.map(|(_, path)| path.clone())
}

/// Resolves a unix path to the DOS drive letter and path wine would use for it.
///
/// Wine maps drives with symlinks under `$WINEPREFIX/dosdevices` and resolves a
/// unix path through the *most specific* mapping covering it. Z: is normally the
/// root mapping, so it wins only when nothing more specific matches.
fn wine_dos_path(path: &Path) -> (char, String) {
    let prefix = std::env::var("WINEPREFIX")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".wine")
        });

    let mut best: Option<(char, PathBuf)> = None;
    if let Ok(entries) = std::fs::read_dir(prefix.join("dosdevices")) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Drive links are exactly "c:"; "c::" is the matching device link.
            let mut chars = name.chars();
            let (Some(letter), Some(':'), None) = (chars.next(), chars.next(), chars.next()) else {
                continue;
            };
            let Ok(target) = std::fs::canonicalize(entry.path()) else {
                continue;
            };
            if !path.starts_with(&target) {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|(_, t)| target.as_os_str().len() > t.as_os_str().len())
            {
                best = Some((letter, target));
            }
        }
    }

    let Some((letter, target)) = best else {
        return ('Z', path.to_string_lossy().replace("/", "\\"));
    };

    let rest = path.strip_prefix(&target).unwrap_or(path);
    let rest = rest.to_string_lossy().replace("/", "\\");
    let rest = if rest.is_empty() {
        String::new()
    } else {
        format!("\\{}", rest.trim_start_matches('\\'))
    };
    (letter.to_ascii_uppercase(), rest)
}

#[cfg(test)]
mod test {
    use super::auto_entry;

    fn pick(names: &[&str]) -> Option<String> {
        let owned: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let fds: Vec<(&String, std::os::fd::RawFd)> =
            owned.iter().enumerate().map(|(i, n)| (n, i as i32)).collect();
        auto_entry(&fds)
    }

    #[test]
    fn the_game_is_chosen_over_its_helpers() {
        // Subnautica 2's four executables. Picking by hash order started the
        // crash handler or the prerequisite shim most of the time.
        let chosen = pick(&[
            "\\Subnautica2.exe",
            "\\Subnautica2\\Binaries\\WinGDK\\Subnautica2-WinGDK-Shipping.exe",
            "\\Subnautica2\\Plugins\\Sentry\\Binaries\\Win64\\crashpad_handler.exe",
            "\\Engine\\Binaries\\Win64\\CrashReportClient.exe",
        ]);
        assert_eq!(
            chosen.as_deref(),
            Some("\\Subnautica2\\Binaries\\WinGDK\\Subnautica2-WinGDK-Shipping.exe")
        );
    }

    #[test]
    fn the_choice_does_not_depend_on_ordering() {
        let forwards = pick(&[
            "\\SandFall.exe",
            "\\Sandfall\\Binaries\\WinGDK\\SandFall-WinGDK-Shipping.exe",
            "\\Engine\\Binaries\\Win64\\CrashReportClient.exe",
        ]);
        let backwards = pick(&[
            "\\Engine\\Binaries\\Win64\\CrashReportClient.exe",
            "\\Sandfall\\Binaries\\WinGDK\\SandFall-WinGDK-Shipping.exe",
            "\\SandFall.exe",
        ]);
        assert_eq!(forwards, backwards);
        assert_eq!(
            forwards.as_deref(),
            Some("\\Sandfall\\Binaries\\WinGDK\\SandFall-WinGDK-Shipping.exe")
        );
    }

    #[test]
    fn unitys_crash_handler_is_a_helper_too() {
        // Deep Rock Galactic Survivor ships exactly these two. The game only
        // won the pick alphabetically, which is luck rather than a rule.
        let chosen = pick(&["\\UnityCrashHandler64.exe", "\\DRG Survivor.exe"]);
        assert_eq!(chosen.as_deref(), Some("\\DRG Survivor.exe"));
    }

    #[test]
    fn a_title_without_a_shipping_binary_still_gets_the_game() {
        // Minecraft ships one executable and a crash handler.
        let chosen = pick(&["\\Minecraft.Windows.exe", "\\crashpad_handler.exe"]);
        assert_eq!(chosen.as_deref(), Some("\\Minecraft.Windows.exe"));
    }

    #[test]
    fn helpers_alone_are_better_than_nothing() {
        // Nothing but helpers means there is no good answer; returning None
        // leaves the old first-entry behaviour rather than refusing to start.
        assert_eq!(pick(&["\\crashpad_handler.exe"]), None);
    }
}
