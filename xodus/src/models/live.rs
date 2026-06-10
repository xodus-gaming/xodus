use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DAProperty {
    #[serde(rename = "sDAToken")]
    pub da_token: String,
    #[serde(rename = "sDASessionKey")]
    pub da_session_key: String,
    #[serde(rename = "sDAStartTime")]
    pub da_start_time: String,
    #[serde(rename = "sDAExpires")]
    pub da_expires: String,
    #[serde(rename = "sSTSInlineFlowToken")]
    pub sts_inline_flow_token: String,
    #[serde(rename = "sSigninName")]
    pub username: String
}