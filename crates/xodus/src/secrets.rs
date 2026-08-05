pub static SERVICE_NAME: &str = "Xodus Service";

pub fn init_secrets() -> Result<(), keyring_core::Error> {
    #[cfg(feature = "key-chain-file")]
    {
        let store = keyring_core::sample::Store::new_with_backing(
            secrets_backing_file()
                .to_str()
                .expect("Invalid secrets backing path"),
        )?;
        keyring_core::set_default_store(store);
    }

    #[cfg(not(feature = "key-chain-file"))]
    {
        #[cfg(target_os = "linux")]
        {
            keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new()?);
        }

        #[cfg(target_os = "macos")]
        {
            keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let store = keyring_core::sample::Store::new_with_configuration(
                &std::collections::HashMap::from([("persist", "true")]),
            )?;
            keyring_core::set_default_store(store);
        }
    }

    Ok(())
}

pub fn get_entry(user: &str) -> Result<keyring_core::Entry, keyring_core::Error> {
    keyring_core::Entry::new(SERVICE_NAME, user)
}

pub fn destroy_secrets() {
    keyring_core::unset_default_store();
}

#[cfg(feature = "key-chain-file")]
fn secrets_backing_file() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".xodus-keyring.ron")
}
