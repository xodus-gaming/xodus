use std::{collections::HashMap, sync::Mutex, time::Instant};

use crate::tokens::store::{ExpiringTokenBackend, TokenBackend, TokenStoreError};

struct Slot {
    value: Vec<u8>,
    expires_at: Option<Instant>,
}

/// Ephemeral tier backend - process-local, lost on restart. Default for short-lived, tokens.
#[derive(Default)]
pub struct MemoryBackend {
    inner: Mutex<HashMap<String, Slot>>,
}

impl TokenBackend for MemoryBackend {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
        let mut map = self.inner.lock().unwrap();
        if let Some(slot) = map.get(key) {
            if slot.expires_at.is_some_and(|exp| exp <= Instant::now()) {
                map.remove(key);
                return Ok(None);
            }
            return Ok(Some(slot.value.clone()));
        }
        Ok(None)
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError> {
        self.inner.lock().unwrap().insert(
            key.to_string(),
            Slot {
                value: value.to_vec(),
                expires_at: None,
            },
        );
        Ok(())
    }
}

impl ExpiringTokenBackend for MemoryBackend {
    fn set_with_expiry(
        &self,
        key: &str,
        value: &[u8],
        expires_at: Instant,
    ) -> Result<(), TokenStoreError> {
        self.inner.lock().unwrap().insert(
            key.to_string(),
            Slot {
                value: value.to_vec(),
                expires_at: Some(expires_at),
            },
        );
        Ok(())
    }
}
