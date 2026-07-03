use serde::{Deserialize, Serialize};

use crate::models::soap::{self, Timestamp};

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    pub puid: String,
    pub hwid: String,
    pub device_id: String,
    pub splicense: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LegacyToken {
    pub key_name: Option<String>,
    pub token: String,
    pub binary_secret: Option<String>,
    pub lifetime: Timestamp,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Token {
    Legacy(LegacyToken),
    Compact(String),
}

impl From<soap::RequestSecurityTokenResponse> for Token {
    fn from(value: soap::RequestSecurityTokenResponse) -> Self {
        match value.token_type.as_str() {
            "urn:passport:legacy" => {
                let encrypted_data = value.requested_security_token.encrypted_data.unwrap();
                let key_name = encrypted_data.key_info.key_name.clone();
                let token = quick_xml::se::to_string(&encrypted_data).unwrap();
                Self::Legacy(LegacyToken {
                    key_name,
                    token,
                    binary_secret: value.requested_proof_token.map(|t| t.binary_secret),
                    lifetime: value.lifetime,
                })
            }
            "urn:passport:compact" => Self::Compact(
                value
                    .requested_security_token
                    .binary_security_token
                    .unwrap()
                    .value,
            ),
            "urn:passport:delegationcompact" => Self::Compact(format!(
                "d={}",
                value
                    .requested_security_token
                    .binary_security_token
                    .unwrap()
                    .value
            )),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub puid: String,
    pub username: String,
}
