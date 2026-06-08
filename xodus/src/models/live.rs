use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DAProperty {
    #[serde(rename = "DAToken")]
    pub da_token: String,
    #[serde(rename = "DASessionKey")]
    pub da_session_key: String,
    #[serde(rename = "DAStartTime")]
    pub da_start_time: String,
    #[serde(rename = "DAExpires")]
    pub da_expires: String,
    #[serde(rename = "STSInlineFlowToken")]
    pub sts_inline_flow_token: String,
    #[serde(rename = "FirstName")]
    pub first_name: String,
    #[serde(rename = "LastName")]
    pub last_name: String,
    #[serde(rename = "CID")]
    pub cid: String,
    #[serde(rename = "PUID")]
    pub puid: String,
    #[serde(rename = "Username")]
    pub username: String
}