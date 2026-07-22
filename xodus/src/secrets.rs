use keyring_core::{self, Entry};
use std::path::PathBuf;

pub static SERVICE_NAME: &str = "Xodus Service";

pub fn init_secrets() -> Result<(), keyring_core::Error> {
    #[cfg(target_os = "linux")]
    {
        keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new()?);
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let store = keyring_core::sample::Store::new_with_backing(
            secrets_backing_file()
                .to_str()
                .expect("Invalid secrets backing path"),
        )?;
        keyring_core::set_default_store(store);
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let store = keyring_core::sample::Store::new_with_configuration(
            &std::collections::HashMap::from([("persist", "true")]),
        )?;
        keyring_core::set_default_store(store);
        return Ok(());
    }
}

pub fn get_entry(user: &str) -> Result<Entry, keyring_core::Error> {
    Entry::new(SERVICE_NAME, user)
}

pub fn destroy_secrets() {
    keyring_core::unset_default_store();
}

#[cfg(target_os = "macos")]
fn secrets_backing_file() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".xodus-keyring.ron")
}
