use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use msixvc::xvd::{SegmentFile, XvdFile};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use xodus::tokens::TokenManager;

use crate::license::get_license;

const TMP_SUFFIX: &str = ".xodus-decrypting";

fn tmp_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(TMP_SUFFIX);
    PathBuf::from(os)
}

fn rename_failure(path: &Path, err: &std::io::Error) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{name}: decrypted copy kept as {name}{TMP_SUFFIX}; rerun to complete ({err})")
}

/// Maps a segment name to a path under `source`. Every component must be a
/// normal path component and the name must contain no line break.
fn target_path(source: &Path, name: &str) -> Result<PathBuf, String> {
    if name.contains('\n') || name.contains('\r') {
        return Err(format!("rejected segment name {name:?}: contains a line break"));
    }
    let rel = PathBuf::from(name.replace('\\', "/"));
    let mut any = false;
    for c in rel.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(format!("rejected segment name {name:?}: not a plain relative path"));
        }
        any = true;
    }
    if !any {
        return Err(format!("rejected segment name {name:?}: empty path"));
    }
    Ok(source.join(rel))
}

/// Atomically replaces `path`: `write(src, tmp)` fills `<path>.xodus-decrypting`,
/// which is synced, then `record()` runs, then the temp file is renamed over `path`.
async fn replace_with<F, Fut, R, RFut>(path: &Path, write: F, record: R) -> Result<(), String>
where
    F: FnOnce(File, File) -> Fut,
    Fut: Future<Output = Result<(), String>>,
    R: FnOnce() -> RFut,
    RFut: Future<Output = Result<(), String>>,
{
    let tmp = tmp_path(path);
    let src = File::open(path)
        .await
        .map_err(|e| format!("could not open {}: {e}", path.display()))?;
    let out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)
        .await
        .map_err(|e| format!("could not create {}: {e}", tmp.display()))?;
    let out_clone = match out.try_clone().await {
        Ok(f) => f,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(format!("could not clone {}: {e}", tmp.display()));
        }
    };

    let written = match write(src, out_clone).await {
        Ok(()) => out
            .sync_all()
            .await
            .map_err(|e| format!("could not sync {}: {e}", tmp.display())),
        Err(e) => Err(e),
    };
    drop(out);
    if let Err(e) = written {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }

    record().await?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| rename_failure(path, &e))
}

const MARKER: &str = ".xodus-decrypted";

/// Reads the per-file completion list. Missing => empty; a final line lacking
/// `\n` is ignored; any other I/O error fails closed.
async fn read_done(dir: &Path) -> Result<HashSet<String>, String> {
    let path = dir.join(MARKER);
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
    };
    let complete = match bytes.iter().rposition(|b| *b == b'\n') {
        Some(i) => &bytes[..=i],
        None => &bytes[..0],
    };
    let text = std::str::from_utf8(complete)
        .map_err(|e| format!("{} is not valid UTF-8: {e}", path.display()))?;
    Ok(text.lines().filter(|l| !l.is_empty()).map(str::to_string).collect())
}

/// Opens (creating if absent) the marker for appending, truncating a partial
/// last line, and syncs it.
async fn open_marker(dir: &Path) -> Result<File, String> {
    let path = dir.join(MARKER);
    let err = |e: std::io::Error| format!("could not prepare {}: {e}", path.display());
    let mut f = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&path)
        .await
        .map_err(err)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).await.map_err(err)?;
    let keep = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    if keep != bytes.len() {
        f.set_len(keep as u64).await.map_err(err)?;
    }
    f.sync_all().await.map_err(err)?;
    f.seek(std::io::SeekFrom::End(0)).await.map_err(err)?;
    Ok(f)
}

/// Appends `<name>\n` to the marker and syncs it.
async fn record(marker: &mut File, name: &str) -> Result<(), String> {
    let err = |e: std::io::Error| format!("could not record {name}: {e}");
    marker.write_all(format!("{name}\n").as_bytes()).await.map_err(err)?;
    marker.flush().await.map_err(err)?;
    marker.sync_all().await.map_err(err)
}

fn pending(encrypted: &[String], done: &HashSet<String>) -> Vec<String> {
    encrypted.iter().filter(|n| !done.contains(*n)).cloned().collect()
}

/// Maps every name through `target_path`, rejecting names that resolve to the
/// same path ignoring case.
fn resolve_pending(source: &Path, names: &[String]) -> Result<Vec<(String, PathBuf)>, String> {
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let path = target_path(source, name)?;
        let key = path.to_string_lossy().to_lowercase();
        if let Some(prev) = seen.insert(key, name.clone()) {
            return Err(format!("segment names {prev:?} and {name:?} resolve to the same path"));
        }
        out.push((name.clone(), path));
    }
    Ok(out)
}

/// Completes interrupted replacements: a listed name with a leftover temp file
/// gets it renamed into place; an unlisted name's stale temp file is deleted.
async fn recover(done: &HashSet<String>, resolved: &[(String, PathBuf)]) -> Result<(), String> {
    for (name, path) in resolved {
        let tmp = tmp_path(path);
        if !tokio::fs::try_exists(&tmp)
            .await
            .map_err(|e| format!("could not check {}: {e}", tmp.display()))?
        {
            continue;
        }
        if done.contains(name) {
            tokio::fs::rename(&tmp, path)
                .await
                .map_err(|e| rename_failure(path, &e))?;
        } else {
            tokio::fs::remove_file(&tmp)
                .await
                .map_err(|e| format!("could not remove {}: {e}", tmp.display()))?;
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    NoEncryptedFiles,
    AlreadyDecrypted,
    Decrypted(usize),
}

/// No-op outcomes that are decided before any license fetch; `None` when work remains.
fn outcome_before_license(encrypted: &[String], done: &HashSet<String>) -> Option<Outcome> {
    if encrypted.is_empty() {
        Some(Outcome::NoEncryptedFiles)
    } else if pending(encrypted, done).is_empty() {
        Some(Outcome::AlreadyDecrypted)
    } else {
        None
    }
}

/// The license must carry exactly one content key.
fn single_content_key<T>(keys: impl IntoIterator<Item = T>) -> Result<T, String> {
    let mut it = keys.into_iter();
    match (it.next(), it.next()) {
        (Some(k), None) => Ok(k),
        (None, _) => Err("license has no content key".to_string()),
        _ => Err("unexpected number of content keys: more than one".to_string()),
    }
}

/// Decrypts every `keep_encrypted` file of a previously downloaded/extracted
/// msixvc package in place using a real license, so the result can run on an
/// unmodified Wine build. Reports every error and exits with failure.
pub async fn run(client: &reqwest::Client, tokens: &TokenManager, source: String, market: Option<String>) -> ExitCode {
    match decrypt(client, tokens, Path::new(&source), market).await {
        Ok(Outcome::NoEncryptedFiles) => println!("no keep_encrypted files found, nothing to do"),
        Ok(Outcome::AlreadyDecrypted) => println!("already decrypted, nothing to do"),
        Ok(Outcome::Decrypted(n)) => println!("decrypted {n} file(s)"),
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

async fn decrypt(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: &Path,
    market: Option<String>,
) -> Result<Outcome, String> {
    let final_path = source.join(".xodus-streaming.msixvc");
    let mut file = OpenOptions::new()
        .read(true)
        .open(&final_path)
        .await
        .map_err(|e| format!("could not open {}: {e}", final_path.display()))?;
    let perr = |e: Box<dyn std::error::Error>| format!("could not parse {}: {e}", final_path.display());

    let xvd = XvdFile::parse(&mut file).await.map_err(perr)?;

    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();
    let files = xvd.parse_user_package_files(&mut file).await.map_err(perr)?;
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            lfiles = xvd.parse_segment_metadata(&mut file, v).await.map_err(perr)?;
        }
    }
    if lfiles.is_empty() {
        let sfiles = xvd
            .parse_ntfs_segment_metadata(&mut file, false)
            .await
            .map_err(perr)?;
        lfiles.extend(sfiles);
    }

    let mut encrypted: Vec<String> = lfiles
        .iter()
        .filter(|(_, v)| v.keep_encrypted)
        .map(|(k, _)| k.clone())
        .collect();
    encrypted.sort();

    let done = read_done(source).await?;
    let mut marker = open_marker(source).await?;
    let resolved = resolve_pending(source, &encrypted)?;
    recover(&done, &resolved).await?;
    let todo: HashSet<String> = pending(&encrypted, &done).into_iter().collect();
    if let Some(outcome) = outcome_before_license(&encrypted, &done) {
        return Ok(outcome);
    }

    let (key, game_splicense) =
        get_license(client, tokens, xvd.content_id().to_string(), market.unwrap_or_else(|| "neutral".to_string())).await?;
    let (_, content_key) = single_content_key(game_splicense.content_keys)?;
    let full_key = content_key
        .unpack(&key)
        .map_err(|e| format!("failed to unpack content key: {e:?}"))?;

    let (xvd, key32) = (&xvd, *full_key);
    let mut count = 0;
    for (name, path) in resolved.iter().filter(|(n, _)| todo.contains(n)) {
        let Some(sfile) = lfiles.get(name) else {
            return Err(format!("missing segment metadata for {name}"));
        };
        let marker = &mut marker;
        replace_with(
            path,
            |mut src, mut tmp| async move {
                xvd.mount_mem_fd(&mut src, &mut tmp, sfile, key32, |_, _| {})
                    .await
                    .map_err(|e| format!("could not decrypt {name}: {e}"))?;
                tmp.flush().await.map_err(|e| format!("could not flush {name}: {e}"))
            },
            || record(marker, name),
        )
        .await?;
        count += 1;
    }
    Ok(Outcome::Decrypted(count))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn copy_writer(mut src: File, mut out: File) -> Result<(), String> {
        let mut buf = Vec::new();
        src.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
        buf.reverse();
        out.write_all(&buf).await.map_err(|e| e.to_string())?;
        out.flush().await.map_err(|e| e.to_string())
    }

    async fn ok_record() -> Result<(), String> {
        Ok(())
    }

    #[tokio::test]
    async fn replace_with_success() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        std::fs::write(&p, b"abc").unwrap();
        replace_with(&p, copy_writer, ok_record).await.unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"cba");
        assert!(!tmp_path(&p).exists());
    }

    #[tokio::test]
    async fn replace_with_failing_writer() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        std::fs::write(&p, b"abc").unwrap();
        let r = replace_with(&p, |_s, _o| async { Err("boom".to_string()) }, ok_record).await;
        assert!(r.is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"abc");
        assert!(!tmp_path(&p).exists());
    }

    #[tokio::test]
    async fn replace_with_failing_record() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        std::fs::write(&p, b"abc").unwrap();
        let r = replace_with(&p, copy_writer, || async { Err("rec".to_string()) }).await;
        assert!(r.is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"abc");
        assert_eq!(std::fs::read(tmp_path(&p)).unwrap(), b"cba");
    }

    #[tokio::test]
    async fn replace_with_missing_source() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("nope");
        assert!(replace_with(&p, copy_writer, ok_record).await.is_err());
        assert!(!tmp_path(&p).exists());
    }

    #[tokio::test]
    async fn replace_with_rename_failure_dir_destination() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        // The original is a non-empty directory: open succeeds on unix, rename onto it fails.
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("child"), b"x").unwrap();
        let r = replace_with(&p, |_s, mut o| async move {
            o.write_all(b"dec").await.map_err(|e| e.to_string())?;
            o.flush().await.map_err(|e| e.to_string())
        }, ok_record)
        .await;
        let e = r.unwrap_err();
        assert!(e.contains("a: decrypted copy kept as a.xodus-decrypting"), "{e}");
        assert!(tmp_path(&p).exists());
        assert!(p.join("child").exists());
    }

    #[test]
    fn target_path_cases() {
        let s = Path::new("/src");
        assert!(target_path(s, "../x").is_err());
        assert!(target_path(s, "a\\..\\x").is_err());
        assert!(target_path(s, "/etc/passwd").is_err());
        assert!(target_path(s, "a\nb").is_err());
        assert!(target_path(s, "a\rb").is_err());
        assert!(target_path(s, "").is_err());
        assert_eq!(target_path(s, "a\\b\\c").unwrap(), Path::new("/src/a/b/c"));
        assert_eq!(target_path(s, "a\\nb").unwrap(), Path::new("/src/a/nb"));
    }
    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn read_done_cases() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_done(d.path()).await.unwrap().is_empty());
        std::fs::write(d.path().join(MARKER), "a\nb\\c\npart").unwrap();
        let got = read_done(d.path()).await.unwrap();
        assert_eq!(got, ["a", "b\\c"].iter().map(|s| s.to_string()).collect());
        let d2 = tempfile::tempdir().unwrap();
        std::fs::create_dir(d2.path().join(MARKER)).unwrap();
        assert!(read_done(d2.path()).await.is_err());
    }

    #[test]
    fn pending_cases() {
        let done: HashSet<String> = ["a".to_string()].into();
        assert_eq!(pending(&names(&["a", "b"]), &done), names(&["b"]));
        assert!(pending(&names(&["a"]), &done).is_empty());
    }

    #[tokio::test]
    async fn open_marker_truncates_partial_and_appends() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(MARKER), "a\nGame\\fo").unwrap();
        let mut m = open_marker(d.path()).await.unwrap();
        record(&mut m, "Game\\foo").await.unwrap();
        let got = read_done(d.path()).await.unwrap();
        assert_eq!(got, ["a", "Game\\foo"].iter().map(|s| s.to_string()).collect());
        assert_eq!(std::fs::read_to_string(d.path().join(MARKER)).unwrap(), "a\nGame\\foo\n");
    }

    #[tokio::test]
    async fn open_marker_creates_missing() {
        let d = tempfile::tempdir().unwrap();
        open_marker(d.path()).await.unwrap();
        assert!(d.path().join(MARKER).exists());
    }
    #[tokio::test]
    async fn recover_listed_and_unlisted() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::write(&a, b"enc").unwrap();
        std::fs::write(tmp_path(&a), b"dec").unwrap();
        std::fs::write(&b, b"enc").unwrap();
        std::fs::write(tmp_path(&b), b"stale").unwrap();
        let done: HashSet<String> = ["a".to_string()].into();
        let resolved = resolve_pending(d.path(), &names(&["a", "b"])).unwrap();
        recover(&done, &resolved).await.unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"dec");
        assert!(!tmp_path(&a).exists());
        assert_eq!(std::fs::read(&b).unwrap(), b"enc");
        assert!(!tmp_path(&b).exists());
    }

    #[tokio::test]
    async fn recover_retries_after_rename_failure() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        // Blocked state: destination is a non-empty directory, decrypted copy is prepared.
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("child"), b"x").unwrap();
        std::fs::write(tmp_path(&p), b"dec").unwrap();
        let done: HashSet<String> = ["a".to_string()].into();
        let resolved = resolve_pending(d.path(), &names(&["a"])).unwrap();
        // Still blocked by the directory: retried and fails with the same message.
        let e = recover(&done, &resolved).await.unwrap_err();
        assert!(e.contains("a: decrypted copy kept as a.xodus-decrypting"), "{e}");
        assert!(tmp_path(&p).exists());
        // Unblock and retry.
        std::fs::remove_dir_all(&p).unwrap();
        std::fs::write(&p, b"enc").unwrap();
        recover(&done, &resolved).await.unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"dec");
        assert!(!tmp_path(&p).exists());
    }

    #[test]
    fn resolve_pending_cases() {
        let d = Path::new("/src");
        let ok = resolve_pending(d, &names(&["a\\b", "c"])).unwrap();
        assert_eq!(ok[0].1, Path::new("/src/a/b"));
        assert!(resolve_pending(d, &names(&["ok", "..\\x"])).is_err());
        assert!(resolve_pending(d, &names(&["a\\b", "a/b"])).is_err());
        assert!(resolve_pending(d, &names(&["A\\b", "a\\b"])).is_err());
        assert!(resolve_pending(d, &names(&["Ä\\b", "ä\\b"])).is_err());
    }

    #[test]
    fn single_content_key_cases() {
        assert!(single_content_key(Vec::<u8>::new()).is_err());
        assert_eq!(single_content_key([7u8]), Ok(7));
        assert!(single_content_key([1u8, 2]).is_err());
    }

    #[test]
    fn outcome_before_license_cases() {
        let none: HashSet<String> = HashSet::new();
        let done: HashSet<String> = ["a".to_string()].into();
        assert_eq!(outcome_before_license(&[], &none), Some(Outcome::NoEncryptedFiles));
        assert_eq!(outcome_before_license(&names(&["a"]), &done), Some(Outcome::AlreadyDecrypted));
        assert_eq!(outcome_before_license(&names(&["a", "b"]), &done), None);
    }

    fn fake_tokens() -> TokenManager {
        TokenManager::with_memory()
    }

    #[tokio::test]
    async fn decrypt_empty_dir_errs() {
        let d = tempfile::tempdir().unwrap();
        let r = decrypt(&reqwest::Client::new(), &fake_tokens(), d.path(), None).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn decrypt_garbage_msixvc_errs() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".xodus-streaming.msixvc"), vec![0xAB; 4096]).unwrap();
        let r = decrypt(&reqwest::Client::new(), &fake_tokens(), d.path(), None).await;
        assert!(r.is_err());
    }
}
