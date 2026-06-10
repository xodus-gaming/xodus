use keyring_core::{self, Entry};

pub static SERVICE_NAME: &str = "Xodus Service";

pub fn init_secrets() {
    keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new().unwrap());
}

pub fn get_entry(user: &str) -> Result<Entry, keyring_core::Error> {
    Entry::new(SERVICE_NAME, user)
}

pub fn destroy_secrets() {
    keyring_core::unset_default_store();
}
