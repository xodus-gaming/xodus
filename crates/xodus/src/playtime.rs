use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Error, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlayTimeEntry {
    pub content_id: String,
    pub total_seconds: u64,
    pub last_played_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PlayTimeStore {
    pub entries: HashMap<String, PlayTimeEntry>,
}

impl PlayTimeStore {
    /// Returns the platform data path used for playtime storage.
    pub fn get_storage_path() -> Result<PathBuf, std::io::Error> {
        storage_path_for(
            std::env::var_os("XDG_DATA_HOME"),
            std::env::var_os("HOME"),
            cfg!(target_os = "macos"),
        )
    }

    /// Loads the default store. A missing file is treated as an empty store.
    pub fn load() -> Result<Self, std::io::Error> {
        Self::load_from_path(&Self::get_storage_path()?)
    }

    /// Loads a store from a specific path. A missing file is treated as empty.
    pub fn load_from_path(path: &Path) -> Result<Self, std::io::Error> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content).map_err(|error| Error::new(ErrorKind::InvalidData, error))
    }

    /// Saves the store to the default path.
    pub fn save(&self) -> Result<(), std::io::Error> {
        self.save_to_path(&Self::get_storage_path()?)
    }

    /// Saves the store atomically to a specific path.
    pub fn save_to_path(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self).map_err(Error::other)?;
        atomic_write(path, content.as_bytes())
    }

    /// Adds played seconds for a content ID.
    pub fn add_session(&mut self, content_id: &str, duration_seconds: u64) {
        let entry = self
            .entries
            .entry(content_id.to_string())
            .or_insert_with(|| PlayTimeEntry {
                content_id: content_id.to_string(),
                total_seconds: 0,
                last_played_at: None,
            });

        entry.total_seconds += duration_seconds;
        entry.last_played_at = Some(Utc::now());
    }

    /// Returns accumulated seconds for a content ID.
    pub fn get_playtime(&self, content_id: &str) -> u64 {
        self.entries
            .get(content_id)
            .map(|entry| entry.total_seconds)
            .unwrap_or(0)
    }

    /// Formats seconds as a human-readable duration.
    pub fn format_duration(seconds: u64) -> String {
        if seconds < 60 {
            return format!("{seconds}s");
        }
        let minutes = seconds / 60;
        let hours = minutes / 60;
        let remaining_minutes = minutes % 60;

        if hours > 0 {
            if remaining_minutes > 0 {
                format!("{hours}h {remaining_minutes}m")
            } else {
                format!("{hours}h")
            }
        } else {
            format!("{minutes}m")
        }
    }
}

fn storage_path_for(
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
    macos: bool,
) -> Result<PathBuf, std::io::Error> {
    let home = home
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .filter(|home| home.is_absolute());
    let base_dir = if macos {
        home.ok_or_else(|| Error::new(ErrorKind::NotFound, "HOME is not an absolute path"))?
            .join("Library/Application Support")
    } else {
        xdg_data_home
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| home.map(|home| home.join(".local/share")))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::NotFound,
                    "XDG_DATA_HOME and HOME are not absolute paths",
                )
            })?
    };

    Ok(base_dir.join("xodus").join("playtime.json"))
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), std::io::Error> {
    let file_name = path
        .file_name()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "playtime path has no file name"))?;
    let temp_path = path.with_file_name(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temp_path, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn record_session_at_path(
    path: &Path,
    content_id: &str,
    duration: Duration,
) -> Result<u64, std::io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "playtime path has no parent"))?;
    fs::create_dir_all(parent)?;
    let lock_path = path.with_extension("lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock.lock_exclusive()?;

    let mut store = PlayTimeStore::load_from_path(path)?;
    let total = store
        .get_playtime(content_id)
        .checked_add(duration.as_secs())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "playtime total overflow"))?;
    store.add_session(content_id, duration.as_secs());
    store.save_to_path(path)?;
    Ok(total)
}

/// Records a completed session and returns accumulated playtime in seconds.
pub fn record_session(content_id: &str, duration: Duration) -> Result<u64, std::io::Error> {
    record_session_at_path(&PlayTimeStore::get_storage_path()?, content_id, duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn formats_duration() {
        assert_eq!(PlayTimeStore::format_duration(45), "45s");
        assert_eq!(PlayTimeStore::format_duration(120), "2m");
        assert_eq!(PlayTimeStore::format_duration(125), "2m");
        assert_eq!(PlayTimeStore::format_duration(3600), "1h");
        assert_eq!(PlayTimeStore::format_duration(3665), "1h 1m");
        assert_eq!(PlayTimeStore::format_duration(7200), "2h");
    }

    #[test]
    fn store_save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("playtime.json");
        let mut store = PlayTimeStore::default();
        store.add_session("game-123", 3600);
        store.add_session("game-123", 1800);

        store.save_to_path(&file_path).unwrap();

        let loaded = PlayTimeStore::load_from_path(&file_path).unwrap();
        assert_eq!(loaded.get_playtime("game-123"), 5400);
        assert_eq!(loaded.get_playtime("non-existent"), 0);
        assert!(loaded.entries["game-123"].last_played_at.is_some());
    }

    #[test]
    fn missing_store_loads_as_empty() {
        let dir = tempdir().unwrap();
        let loaded = PlayTimeStore::load_from_path(&dir.path().join("missing.json")).unwrap();
        assert!(loaded.entries.is_empty());
    }

    #[test]
    fn malformed_store_is_not_overwritten() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("playtime.json");
        fs::write(&file_path, "not json").unwrap();

        let error =
            record_session_at_path(&file_path, "game-123", Duration::from_secs(10)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(file_path).unwrap(), "not json");
    }

    #[test]
    fn recording_sessions_accumulates_and_returns_total() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("playtime.json");

        assert_eq!(
            record_session_at_path(&file_path, "game-123", Duration::from_secs(40)).unwrap(),
            40
        );
        assert_eq!(
            record_session_at_path(&file_path, "game-123", Duration::from_secs(2)).unwrap(),
            42
        );

        let loaded = PlayTimeStore::load_from_path(&file_path).unwrap();
        assert_eq!(loaded.get_playtime("game-123"), 42);
    }

    #[test]
    fn concurrent_sessions_do_not_lose_updates() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("playtime.json");
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();

        for _ in 0..8 {
            let file_path = file_path.clone();
            let start = start.clone();
            threads.push(std::thread::spawn(move || {
                start.wait();
                record_session_at_path(&file_path, "game-123", Duration::from_secs(1)).unwrap();
            }));
        }

        for thread in threads {
            thread.join().unwrap();
        }

        let loaded = PlayTimeStore::load_from_path(&file_path).unwrap();
        assert_eq!(loaded.get_playtime("game-123"), 8);
    }

    #[test]
    fn recording_session_rejects_total_overflow() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("playtime.json");
        let mut store = PlayTimeStore::default();
        store.add_session("game-123", u64::MAX);
        store.save_to_path(&file_path).unwrap();

        let error =
            record_session_at_path(&file_path, "game-123", Duration::from_secs(1)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
        let loaded = PlayTimeStore::load_from_path(&file_path).unwrap();
        assert_eq!(loaded.get_playtime("game-123"), u64::MAX);
    }

    #[test]
    fn storage_path_uses_platform_data_directory() {
        assert_eq!(
            storage_path_for(
                Some(OsString::from("/xdg-data")),
                Some(OsString::from("/home/test")),
                false,
            )
            .unwrap(),
            PathBuf::from("/xdg-data/xodus/playtime.json")
        );
        assert_eq!(
            storage_path_for(None, Some(OsString::from("/home/test")), false).unwrap(),
            PathBuf::from("/home/test/.local/share/xodus/playtime.json")
        );
        assert_eq!(
            storage_path_for(None, Some(OsString::from("/Users/test")), true).unwrap(),
            PathBuf::from("/Users/test/Library/Application Support/xodus/playtime.json")
        );
    }

    #[test]
    fn storage_path_rejects_relative_or_missing_base_directories() {
        assert_eq!(
            storage_path_for(
                Some(OsString::from("relative")),
                Some(OsString::from("/home/test")),
                false,
            )
            .unwrap(),
            PathBuf::from("/home/test/.local/share/xodus/playtime.json")
        );
        assert!(storage_path_for(Some(OsString::new()), None, false).is_err());
        assert!(storage_path_for(None, None, true).is_err());
    }
}
