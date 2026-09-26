pub mod codec;

#[cfg(target_os = "linux")]
pub fn get_runtime_dir() -> String {
    std::env::var("XDG_RUNTIME_DIR").expect("Runtime dir not set")
}

#[cfg(target_os = "macos")]
pub fn get_runtime_dir() -> String {
    return "/tmp/".to_string();
}

pub mod proto {
    pub mod xodus {
        // pub mod auth {
        //     include!(concat!(env!("OUT_DIR"), "/xodus.auth.rs"));
        // }
        // pub mod catalog {
        //     include!(concat!(env!("OUT_DIR"), "/xodus.catalog.rs"));
        // }
        pub mod download {
            include!(concat!(env!("OUT_DIR"), "/xodus.download.rs"));
        }
    }
}