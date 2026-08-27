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
pub struct LicenseTokenRequest {
    pub parent_product_id: String,
    pub enforce_sellable_by: bool,
    pub related_product_ids: Vec<String>,
    pub custom_developer_string: String,
    pub beneficiaries: Vec<LicenseUserIdentity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseTokenResponse {
    pub license_token: String,
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
#[serde(untagged)]
pub enum LicenseContentResponse {
    Success {
        license: LicenseContent,
    },
    SatisfactionFailure {
        #[serde(rename = "satisfactionFailure")]
        satisfaction_failure: SatisfactionFailure,
    },
}

/// Returned instead of a license when the account has no entitlement for the
/// requested content (e.g. not owned, not covered by the account's Game Pass tier).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SatisfactionFailure {
    pub code: i64,
    pub description: String,
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
