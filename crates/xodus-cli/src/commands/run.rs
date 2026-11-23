use std::collections::HashMap;
use std::os::fd::{AsFd, IntoRawFd};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use msixvc::layout::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use xodus::tokens::TokenManager;

use crate::license::get_license;

fn private_launch_dir(prefix: &str) -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .prefix(prefix)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

fn staged_path(root: &Path, package_path: &str) -> std::io::Result<PathBuf> {
    let relative = package_path
        .strip_prefix('\\')
        .unwrap_or(package_path)
        .replace('\\', "/");
    let path = Path::new(&relative);
    if relative.is_empty()
        || relative.contains(':')
        || relative.contains('\0')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid package path",
        ));
    }
    Ok(root.join(path))
}

// Materialize encrypted files first; only then link the remaining assets.
// Never follow destination symlinks while decrypting or modifying settings.
fn mirror_assets(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(".xodus-") {
            continue;
        }
        let src = entry.path();
        let dst = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            mirror_assets(&src, &dst)?;
        } else if dst.symlink_metadata().is_err() {
            if src.extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("dll") || ext.eq_ignore_ascii_case("exe")
            }) {
                // Native module mapping requires an actual file at its launch
                // path. Copy modules; large game data can remain linked.
                std::fs::copy(&src, &dst)?;
            } else {
                std::os::unix::fs::symlink(&src, &dst)?;
            }
        }
    }
    Ok(())
}

fn stage_eac_settings(source: &Path, destination: &Path) -> std::io::Result<()> {
    let relative = "easyanticheat/settings.json";
    let src = source.join(relative);
    if !src.is_file() {
        return Ok(());
    }
    // EAC validates this file against its signed catalog. Preserve every byte.
    let dst = destination.join(relative);
    std::fs::create_dir_all(dst.parent().unwrap())?;
    std::fs::copy(src, dst).map(|_| ())
}

#[cfg(target_os = "linux")]
fn wait_for_launch_children(group: u32) -> Result<Option<i32>, nix::errno::Errno> {
    use nix::sys::wait::{WaitStatus, waitpid};
    let mut failure = None;
    loop {
        match waitpid(Pid::from_raw(-(group as i32)), None) {
            Ok(WaitStatus::Exited(_, code)) if code != 0 => failure = Some(code),
            Ok(WaitStatus::Signaled(pid, signal, _)) => {
                eprintln!("Launch descendant {pid} exited on {signal}");
                failure = Some(128 + signal as i32);
            }
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => return Ok(failure),
            Err(error) => return Err(error),
        }
    }
}

// Subreaper state is process-wide; restore it after this single CLI launch.
#[cfg(target_os = "linux")]
struct SubreaperGuard(bool);

#[cfg(target_os = "linux")]
impl SubreaperGuard {
    fn enable() -> Result<Self, nix::errno::Errno> {
        let previous = nix::sys::prctl::get_child_subreaper()?;
        nix::sys::prctl::set_child_subreaper(true)?;
        Ok(Self(previous))
    }
}

#[cfg(target_os = "linux")]
impl Drop for SubreaperGuard {
    fn drop(&mut self) {
        if let Err(error) = nix::sys::prctl::set_child_subreaper(self.0) {
            eprintln!("could not restore child subreaper state: {error}");
        }
    }
}

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
    materialize: bool,
) -> ExitCode {
    if materialize && !cfg!(target_os = "linux") {
        eprintln!("materialized launch is currently supported on Linux only");
        return ExitCode::FAILURE;
    }
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

    let staged = if materialize {
        match private_launch_dir("xodus-launch-") {
            Ok(directory) => Some(directory),
            Err(error) => {
                eprintln!("could not create launch directory: {error}");
                cleanup().await;
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let mut game_exe = if let Some(staged) = &staged {
            let path = match staged_path(staged.path(), file.0) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("could not stage executable: {error}");
                    cleanup().await;
                    return ExitCode::FAILURE;
                }
            };
            std::fs::create_dir_all(path.parent().unwrap()).expect("create launch directory");
            use std::os::unix::fs::OpenOptionsExt;
            File::from_std(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .expect("create staged executable"),
            )
        } else {
            File::from_std(make_temp_file(&mount_dir).unwrap())
        };

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        xvd.mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
            .await
            .unwrap();

        if staged.is_some() {
            game_exe.flush().await.expect("flush staged executable");
            drop(game_exe);
            fds.push((file.0, None));
            continue;
        }
        let stdf = game_exe.into_std().await;

        let mut flags = fcntl_getfd(stdf.as_fd()).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(stdf.as_fd(), flags).unwrap();

        fds.push((file.0, Some(stdf.into_raw_fd())));
    }

    let mut env_value = String::new();
    let launch_root = staged
        .as_ref()
        .map_or(out_absolute.as_path(), |dir| dir.path());
    if staged.is_some()
        && let Err(error) = stage_eac_settings(&out_absolute, launch_root)
            .and_then(|()| mirror_assets(&out_absolute, launch_root))
    {
        eprintln!("could not stage launch assets: {error}");
        cleanup().await;
        return ExitCode::FAILURE;
    }
    let nt_prefix = launch_root.to_string_lossy().replace("/", "\\");
    let nt_prefix = nt_prefix.trim_end_matches('\\');

    let mut nt_entry = None;

    for fd in fds {
        let nt_suffix = fd.0.trim_start_matches('\\');
        let nt_path = format!("\\??\\Z:{}\\{}", nt_prefix, nt_suffix);
        if let Some(exe) = &exe {
            if exe == fd.0 {
                nt_entry = Some(nt_path)
            }
        } else if nt_entry.is_none() {
            nt_entry = Some(nt_path)
        }

        if let Some(raw_fd) = fd.1 {
            if !env_value.is_empty() {
                env_value.push('|');
            }
            env_value.push_str(&format!("{}:\\??\\Z:{}\\{}", raw_fd, nt_prefix, nt_suffix));
        }
    }

    let Some(nt_entry) = nt_entry else {
        eprintln!("Could not find .exe");
        cleanup().await;
        return ExitCode::FAILURE;
    };

    let mut command = Command::new(wine);
    if materialize {
        command
            .arg(nt_entry.trim_start_matches("\\??\\"))
            .env_remove("WINE_DLL_FILE_MAP")
            .current_dir(launch_root);
    } else {
        command.arg(nt_entry).env("WINE_DLL_FILE_MAP", env_value);
    }
    #[cfg(target_os = "linux")]
    let _subreaper = if materialize {
        match SubreaperGuard::enable() {
            Ok(guard) => {
                command.process_group(0);
                Some(guard)
            }
            Err(error) => {
                eprintln!("could not track launch descendants: {error}");
                cleanup().await;
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    let mut wn = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("could not launch Wine: {error}");
            cleanup().await;
            return ExitCode::FAILURE;
        }
    };
    let pid = wn.id().unwrap();
    ctrlc::set_handler(move || {
        if pid > 0 {
            let target = if materialize {
                -(pid as i32)
            } else {
                pid as i32
            };
            let _ = kill(Pid::from_raw(target), Signal::SIGINT);
        }
    })
    .expect("failed to install Ctrl+C handler");
    let status = wn.wait().await.unwrap();
    use std::os::unix::process::ExitStatusExt;
    let mut exit_code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    #[cfg(target_os = "linux")]
    if materialize {
        match tokio::task::spawn_blocking(move || wait_for_launch_children(pid))
            .await
            .unwrap()
        {
            Ok(Some(code)) if exit_code == 0 => exit_code = code,
            Ok(_) => {}
            Err(error) => {
                eprintln!("could not wait for launch descendants: {error}");
                if exit_code == 0 {
                    exit_code = 1;
                }
            }
        }
    }
    cleanup().await;
    ExitCode::from(exit_code as u8)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    static LIFETIME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn runtime_directories_are_private_even_with_a_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_launch_dir("xodus-private-test-").unwrap();
        assert_eq!(
            dir.path().metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn staged_paths_stay_inside_launch_root() {
        let root = Path::new("/tmp/launch");
        assert_eq!(
            staged_path(root, r"MCC\Binaries\game.exe").unwrap(),
            root.join("MCC/Binaries/game.exe")
        );
        assert_eq!(
            staged_path(root, r"\game.exe").unwrap(),
            root.join("game.exe")
        );
        for invalid in [
            "",
            "../game.exe",
            r"MCC\..\game.exe",
            "/game.exe",
            r"Z:\game.exe",
            r"\\server\share\game.exe",
            "dir//game.exe",
            "dir/./game.exe",
            "game.exe\0",
        ] {
            assert!(staged_path(root, invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn assets_merge_into_decrypted_directories_without_overwriting_files() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let relative = "MCC/Binaries/Win64";
        std::fs::create_dir_all(source.path().join(relative)).unwrap();
        std::fs::create_dir_all(destination.path().join(relative)).unwrap();
        std::fs::write(source.path().join(relative).join("game.exe"), b"encrypted").unwrap();
        std::fs::write(
            destination.path().join(relative).join("game.exe"),
            b"decrypted",
        )
        .unwrap();
        std::fs::write(source.path().join(relative).join("asset.dll"), b"asset").unwrap();
        std::fs::write(source.path().join(relative).join("data.pak"), b"data").unwrap();
        std::fs::write(source.path().join(".xodus-streaming.msixvc"), b"package").unwrap();
        mirror_assets(source.path(), destination.path()).unwrap();
        assert_eq!(
            std::fs::read(destination.path().join(relative).join("game.exe")).unwrap(),
            b"decrypted"
        );
        assert_eq!(
            std::fs::read(source.path().join(relative).join("game.exe")).unwrap(),
            b"encrypted"
        );
        assert!(
            !destination
                .path()
                .join(relative)
                .join("asset.dll")
                .is_symlink()
        );
        assert_eq!(
            std::fs::read(destination.path().join(relative).join("asset.dll")).unwrap(),
            b"asset"
        );
        assert!(
            destination
                .path()
                .join(relative)
                .join("data.pak")
                .is_symlink()
        );
        assert!(!destination.path().join(".xodus-streaming.msixvc").exists());
    }

    #[test]
    fn eac_settings_copy_preserves_signed_bytes_after_asset_merge() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        std::fs::create_dir(source.path().join("easyanticheat")).unwrap();
        let relative = "easyanticheat/settings.json";
        let original = br#"{"wait_for_game_process_exit":"false","executable":"game.exe"}"#;
        std::fs::write(source.path().join(relative), original).unwrap();
        stage_eac_settings(source.path(), destination.path()).unwrap();
        mirror_assets(source.path(), destination.path()).unwrap();
        let copied: serde_json::Value =
            serde_json::from_slice(&std::fs::read(destination.path().join(relative)).unwrap())
                .unwrap();
        assert_eq!(copied["wait_for_game_process_exit"], "false");
        assert_eq!(copied["executable"], "game.exe");
        assert!(!destination.path().join(relative).is_symlink());
        assert_eq!(
            std::fs::read(destination.path().join(relative)).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read(source.path().join(relative)).unwrap(),
            original
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn early_bootstrapper_exit_keeps_staged_files_until_game_exit() {
        let _lock = LIFETIME_TEST_LOCK.lock().unwrap();
        use std::os::unix::process::CommandExt;
        let previous = nix::sys::prctl::get_child_subreaper().unwrap();
        let guard = SubreaperGuard::enable().unwrap();
        let staged = private_launch_dir("xodus-lifecycle-test-").unwrap();
        std::fs::write(staged.path().join("game.exe"), b"synthetic decrypted bytes").unwrap();
        let marker = staged.path().join("game-finished");
        let mut launcher = std::process::Command::new("sh");
        launcher
            .args([
                "-c",
                "(sleep 0.2; cat game.exe > \"$1\"; exit 7) & exit 0",
                "launcher",
            ])
            .arg(&marker)
            .current_dir(staged.path())
            .process_group(0);
        let mut child = launcher.spawn().unwrap();
        let group = child.id();
        assert!(child.wait().unwrap().success());
        assert_eq!(wait_for_launch_children(group).unwrap(), Some(7));
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"synthetic decrypted bytes"
        );
        let root = staged.path().to_owned();
        drop(staged);
        assert!(!root.exists());
        drop(guard);
        assert_eq!(nix::sys::prctl::get_child_subreaper().unwrap(), previous);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn launch_group_signal_reaches_orphaned_child_and_reports_failure() {
        let _lock = LIFETIME_TEST_LOCK.lock().unwrap();
        use std::os::unix::process::CommandExt;
        let guard = SubreaperGuard::enable().unwrap();
        let work = tempfile::tempdir().unwrap();
        let marker = work.path().join("ready");
        let mut command = std::process::Command::new("sh");
        command
            .args([
                "-c",
                "(printf ready > \"$1\"; exec sleep 30) & exit 0",
                "bootstrapper",
            ])
            .arg(&marker)
            .process_group(0);
        let mut bootstrapper = command.spawn().unwrap();
        let group = bootstrapper.id();
        assert!(bootstrapper.wait().unwrap().success());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !marker.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let ready = marker.exists();
        kill(Pid::from_raw(-(group as i32)), Signal::SIGTERM).unwrap();
        assert_eq!(wait_for_launch_children(group).unwrap(), Some(143));
        assert!(ready, "child did not start before timeout");
        drop(guard);
    }
}
