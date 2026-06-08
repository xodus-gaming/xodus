use serde::{Deserialize, Serialize};

use crate::models::soap::Timestamp;

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    pub puid: String,
    pub hwid: String,
    pub device_id: String,
    pub splicense: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub key_name: String,
    pub cipher_value: String,
    pub binary_secret: String,
    pub lifetime: Timestamp
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub da_token: String,
    pub da_session_key: String,
    pub lifetime: Timestamp,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub cid: String,
    pub puid: String
}