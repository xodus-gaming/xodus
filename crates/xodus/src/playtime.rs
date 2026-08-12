use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    /// Returns the default path to the playtime storage file (~/.config/xodus/playtime.json).
    pub fn get_storage_path() -> PathBuf {
        let base_dir = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));

        base_dir.join("xodus").join("playtime.json")
    }

    /// Load PlayTimeStore from default file path, returning default empty store if not exists.
    pub fn load() -> Self {
        Self::load_from_path(&Self::get_storage_path()).unwrap_or_default()
    }

    /// Load PlayTimeStore from a specific file path.
    pub fn load_from_path(path: &PathBuf) -> Result<Self, std::io::Error> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let store: PlayTimeStore = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(store)
    }

    /// Save PlayTimeStore to default file path.
    pub fn save(&self) -> Result<(), std::io::Error> {
        self.save_to_path(&Self::get_storage_path())
    }

    /// Save PlayTimeStore to a specific file path.
    pub fn save_to_path(&self, path: &PathBuf) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(path, content)
    }

    /// Add a session's played seconds for a specific content_id.
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

    /// Get played seconds for a specific content_id.
    pub fn get_playtime(&self, content_id: &str) -> u64 {
        self.entries
            .get(content_id)
            .map(|e| e.total_seconds)
            .unwrap_or(0)
    }

    /// Format seconds into human readable duration string (e.g., "2h 15m", "45m", "10s").
    pub fn format_duration(seconds: u64) -> String {
        if seconds < 60 {
            return format!("{}s", seconds);
        }
        let minutes = seconds / 60;
        let hours = minutes / 60;
        let remaining_minutes = minutes % 60;

        if hours > 0 {
            if remaining_minutes > 0 {
                format!("{}h {}m", hours, remaining_minutes)
            } else {
                format!("{}h", hours)
            }
        } else {
            format!("{}m", minutes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_format_duration() {
        assert_eq!(PlayTimeStore::format_duration(45), "45s");
        assert_eq!(PlayTimeStore::format_duration(120), "2m");
        assert_eq!(PlayTimeStore::format_duration(125), "2m");
        assert_eq!(PlayTimeStore::format_duration(3600), "1h");
        assert_eq!(PlayTimeStore::format_duration(3665), "1h 1m");
        assert_eq!(PlayTimeStore::format_duration(7200), "2h");
    }

    #[test]
    fn test_store_save_and_load() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_playtime.json");

        let mut store = PlayTimeStore::default();
        store.add_session("game-123", 3600);
        store.add_session("game-123", 1800);
        store.save_to_path(&file_path).unwrap();

        let loaded = PlayTimeStore::load_from_path(&file_path).unwrap();
        assert_eq!(loaded.get_playtime("game-123"), 5400);
        assert_eq!(loaded.get_playtime("non-existent"), 0);
    }
}
