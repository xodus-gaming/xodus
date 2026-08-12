pub mod api;
pub mod auth;
pub mod clep;
pub mod hardware;
pub mod licensing;
pub mod models;
#[cfg(unix)]
pub mod playtime;
pub mod secrets;
pub mod tokens;

pub const XBOX_LIVE_PACKAGES_PC: &str = "https://packagespc.xboxlive.com";

pub use xal;

pub mod proto {
    pub mod xodus {
        include!(concat!(env!("OUT_DIR"), "/xodus.rs"));
    }
}
