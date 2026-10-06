pub mod codec;

#[cfg(target_os = "linux")]
pub fn get_runtime_dir() -> String {
    std::env::var("XDG_RUNTIME_DIR").expect("Runtime dir not set")
}

#[cfg(target_os = "macos")]
pub fn get_runtime_dir() -> String {
    return "/tmp/".to_string();
}

#[cfg(feature = "service")]
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("unknown service {0}")]
    UnknownService(u8),
    #[error("unknown message {0}")]
    UnknownMessage(u8),
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    #[error(transparent)]
    Handler(Box<dyn std::error::Error + Send + Sync>),
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
        pub mod common {
            include!(concat!(env!("OUT_DIR"), "/xodus.common.rs"));
        }
        pub mod stub {
            include!(concat!(env!("OUT_DIR"), "/xodus.stub.rs"));
        }
    }
}
