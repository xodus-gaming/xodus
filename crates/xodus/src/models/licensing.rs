use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseContentRequest {
    pub client_challenge: String,
    pub concurrency_mode: String,
    pub content_id: String,
    pub device_context: DeviceContext,
    pub license_version: u32,
    pub market: String,
    pub need_key: bool,
    pub key_only: bool,
    pub users: HashMap<String, Vec<LicenseUserIdentity>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceContext {
    pub hardware_manufacturer: String,
    pub hardware_type: String,
    pub mobile_operator: String,
}

impl Default for DeviceContext {
    fn default() -> Self {
        Self {
            hardware_manufacturer: "Public".into(),
            mobile_operator: "Public".into(),
            hardware_type: "Public".into(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseUserIdentity {
    pub identity_type: String,
    pub identity_value: String,
    pub local_ticket_reference: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseContentResponse {
    pub license: LicenseContent,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseContent {
    pub keys: Vec<LicenseKeys>,
    pub leases: Vec<LicenseKeys>,
}

#[derive(Debug, Deserialize)]
pub struct LicenseKeys {
    pub value: String,
}
