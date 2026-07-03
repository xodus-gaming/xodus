use std::{collections::HashMap, sync::Arc, time::Instant};

use crate::{
    licensing::splicense::ContentKey,
    models::{
        secrets::{Device, Token, User},
        xbox::XstsResponse,
    },
    tokens::{
        backend::{KeychainBackend, MemoryBackend},
        store::{ExpiringTokenBackend, TokenBackend, TokenStoreError},
    },
};

mod keys {
    pub const DEV_LICENSE: &str = "dev_license";
    pub const DEVICE_TOKENS: &str = "device-tokens";
    pub const USER_TOKENS: &str = "user-tokens";
    pub const USER_INFO: &str = "user-DA";
    pub const CONTENT_INTEGRITY_KEYS: &str = "content-integrity-keys";
}

pub const PASSPORT_STS: &str = "http://Passport.NET/STS";

/// Semantic facade over the two storage tiers: a persistent, keychain-backed tier
/// for STS/device/user credentials, and an ephemeral tier for short-lived
/// per-relying-party XSTS tokens. Centralizes the read-merge-write pattern that was
/// previously duplicated across `xodus-cli` and `xodus-service`.
#[derive(Clone)]
pub struct TokenManager {
    persistent: Arc<dyn TokenBackend>,
    ephemeral: Arc<dyn ExpiringTokenBackend>,
}

impl TokenManager {
    pub fn new(
        persistent: Arc<dyn TokenBackend>,
        ephemeral: Arc<dyn ExpiringTokenBackend>,
    ) -> Self {
        Self {
            persistent,
            ephemeral,
        }
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_keychain_and_memory() -> Self {
        Self::new(
            Arc::new(KeychainBackend),
            Arc::new(MemoryBackend::default()),
        )
    }

    // ---- Device identity / license -----------------------------------------

    pub fn get_device_license(&self) -> Result<Device, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::DEV_LICENSE)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_device_license(&self, device: &Device) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::DEV_LICENSE, &serde_json::to_vec(device)?)
    }

    // ---- Device STS tokens (keyed by SOAP "applies_to" address) -----------

    pub fn get_device_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::get_table(&*self.persistent, keys::DEVICE_TOKENS, address)
    }

    pub fn save_device_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_table(&*self.persistent, keys::DEVICE_TOKENS, address, token)
    }

    pub fn get_device_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_device_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User STS tokens (keyed by SOAP "applies_to" address) --------------

    pub fn get_user_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::get_table(&*self.persistent, keys::USER_TOKENS, address)
    }

    pub fn save_user_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_table(&*self.persistent, keys::USER_TOKENS, address, token)
    }

    pub fn get_user_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_user_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User info -----------------------------------------------------------

    pub fn get_user(&self) -> Result<User, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::USER_INFO)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_user(&self, user: &User) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::USER_INFO, &serde_json::to_vec(user)?)
    }

    // ---- Ephemeral XSTS-by-relying-party cache --------------------------------

    pub fn get_cached_xsts(&self, relying_party: &str) -> Option<XstsResponse> {
        let bytes = self.ephemeral.get(relying_party).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn cache_xsts(&self, relying_party: &str, token: &XstsResponse) {
        self.cache_xsts_response(relying_party, token);
    }

    fn cache_xsts_response(&self, key: &str, token: &XstsResponse) {
        let Ok(bytes) = serde_json::to_vec(token) else {
            return;
        };
        let remaining = (token.not_after - chrono::Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let _ = self
            .ephemeral
            .set_with_expiry(key, &bytes, Instant::now() + remaining);
    }

    // ---- CIK Content Integrity Key for MSIXVC decryption ----------------------

    pub fn get_cik(&self, uuid: uuid::Uuid) -> Result<Option<ContentKey>, TokenStoreError> {
        Self::get_table(
            &*self.persistent,
            keys::CONTENT_INTEGRITY_KEYS,
            &uuid.hyphenated().to_string(),
        )
    }

    pub fn save_cik(&self, uuid: uuid::Uuid, cik: ContentKey) -> Result<(), TokenStoreError> {
        Self::write_table(
            &*self.persistent,
            keys::CONTENT_INTEGRITY_KEYS,
            uuid.hyphenated().to_string(),
            cik,
        )
    }

    // ---- shared table read/modify/write helper ---------------------------

    /// A table is a collection of indexed elements with the same type, `T`.
    ///
    /// Reads a table from the [`TokenBackend`] under `key`.
    fn read_table<T>(
        backend: &dyn TokenBackend,
        key: &str,
    ) -> Result<HashMap<String, T>, TokenStoreError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let store = backend
            .get(key)?
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| serde_json::from_slice::<HashMap<String, T>>(&bytes))
            .transpose()?;

        Ok(store.unwrap_or_default())
    }

    /// Gets an element from a table of elements of type `T`.
    fn get_table<T>(
        backend: &dyn TokenBackend,
        key: &str,
        index: &str,
    ) -> Result<Option<T>, TokenStoreError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let mut store = Self::read_table(backend, key)?;
        Ok(store.remove(index))
    }

    /// Appends an element into a table of elements of type `T`.
    fn write_table<T>(
        backend: &dyn TokenBackend,
        key: &str,
        index: String,
        value: T,
    ) -> Result<(), TokenStoreError>
    where
        T: for<'de> serde::Deserialize<'de> + serde::Serialize,
    {
        let mut store: HashMap<String, T> = Self::read_table(backend, key)?;
        store.insert(index, value);

        backend.set(key, &serde_json::to_vec(&store)?)
    }
}
