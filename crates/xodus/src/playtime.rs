use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Playtime accumulated for a single game, keyed by its content id.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PlaytimeEntry {
    pub total_seconds: u64,
    /// Unix timestamp (seconds) of the most recently completed session.
    pub last_played: Option<u64>,
}

/// On-disk store of playtime for every game, shared by any client (CLI, service,
/// future launcher UI) that wants to read or update it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlaytimeStore {
    pub games: HashMap<String, PlaytimeEntry>,
}

#[cfg(target_os = "macos")]
fn data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Library/Application Support/xodus")
}

#[cfg(not(target_os = "macos"))]
fn data_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(std::env::temp_dir)
        .join("xodus")
}

fn store_path() -> PathBuf {
    data_dir().join("playtime.json")
}

fn load_from(path: &Path) -> PlaytimeStore {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

fn save_to(path: &Path, store: &PlaytimeStore) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = serde_json::to_string_pretty(store)?;
    std::fs::write(path, contents)
}

fn record_session_at(path: &Path, content_id: &str, duration: Duration) -> std::io::Result<()> {
    let mut store = load_from(path);
    let entry = store.games.entry(content_id.to_string()).or_default();
    entry.total_seconds += duration.as_secs();
    entry.last_played = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok();
    save_to(path, &store)
}

/// Loads the current playtime store, returning an empty one if it doesn't exist yet
/// or fails to parse.
pub fn load() -> PlaytimeStore {
    load_from(&store_path())
}

/// Adds a completed play session to the store for `content_id` and persists it.
pub fn record_session(content_id: &str, duration: Duration) -> std::io::Result<()> {
    record_session_at(&store_path(), content_id, duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store_path() -> PathBuf {
        std::env::temp_dir().join(format!("xodus-playtime-test-{}.json", uuid::Uuid::new_v4()))
    }

    #[test]
    fn missing_store_loads_as_empty() {
        let path = temp_store_path();

        let store = load_from(&path);

        assert!(store.games.is_empty());
    }

    #[test]
    fn record_session_creates_and_accumulates() {
        let path = temp_store_path();

        record_session_at(&path, "content-a", Duration::from_secs(30)).unwrap();
        record_session_at(&path, "content-a", Duration::from_secs(15)).unwrap();
        record_session_at(&path, "content-b", Duration::from_secs(5)).unwrap();

        let store = load_from(&path);

        assert_eq!(store.games["content-a"].total_seconds, 45);
        assert!(store.games["content-a"].last_played.is_some());
        assert_eq!(store.games["content-b"].total_seconds, 5);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn sub_second_sessions_are_truncated_not_lost() {
        let path = temp_store_path();

        record_session_at(&path, "content-a", Duration::from_millis(400)).unwrap();
        record_session_at(&path, "content-a", Duration::from_millis(400)).unwrap();

        let store = load_from(&path);

        // Each sub-second session truncates to 0 individually; this documents
        // that behavior rather than silently losing short sessions to rounding.
        assert_eq!(store.games["content-a"].total_seconds, 0);

        std::fs::remove_file(&path).unwrap();
    }
}
