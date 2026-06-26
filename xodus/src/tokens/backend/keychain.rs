use crate::tokens::store::{TokenBackend, TokenStoreError};

pub struct KeychainBackend;

impl TokenBackend for KeychainBackend {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
        let entry = crate::secrets::get_entry(key)?;
        match entry.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError> {
        Ok(crate::secrets::get_entry(key)?.set_secret(value)?)
    }
}
