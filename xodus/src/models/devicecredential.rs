use serde::{Deserialize, Serialize, ser::Error};

#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceAddRequest {
    pub client_info: ClientInfo,
    pub authentication: Authentication,
    pub device_info: Option<DeviceInfo>,
}
impl std::fmt::Display for DeviceAddRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let xml = quick_xml::se::to_string(self).map_err(std::fmt::Error::custom)?;
        f.write_str("<?xml version=\"1.0\"?>\n")?;
        f.write_str(&xml)
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ClientInfo {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@version")]
    pub version: String,
    pub binary_version: u32,
}

impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            name: "IDCRL".to_owned(),
            version: "1.0".to_owned(),
            binary_version: 55,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Authentication {
    pub membername: String,
    pub password: String,
}

impl Authentication {
    pub fn new(membername: String, password: String) -> Self {
        Self {
            membername,
            password,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceInfo {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "Component")]
    pub components: Vec<Component>,
}

#[derive(Serialize, Debug)]
pub struct Component {
    #[serde(rename = "@name")]
    pub name: u32,
    #[serde(rename = "$value")]
    pub value: Option<String>,
    #[serde(rename = "@error")]
    pub error: Option<String>,
}

impl Component {
    pub fn error(id: u32) -> Self {
        Self {
            name: id,
            value: None,
            error: Some("-2147024894".to_owned()),
        }
    }

    pub fn new(id: u32, value: String) -> Self {
        Self {
            name: id,
            value: Some(value),
            error: None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceAddResponse {
    #[serde(rename = "@Success")]
    pub success: bool,
    #[serde(rename = "puid")]
    pub puid: String,
    pub device_tpm_key_state: Vec<u32>,
    pub license: License,
    pub key_holder_license: KeyHolderLicense,
    #[serde(rename = "HWDeviceID")]
    pub hw_device_id: String,
    #[serde(rename = "GlobalDeviceID")]
    pub global_device_id: String,
    pub license_key_sequence: String,
    pub license_signature_key_version: u32,
    pub server_info: ServerInfo,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct License {
    #[serde(rename = "SPLicenseBlock")]
    pub splicense_block: String,
    pub license_info: LicenseInfo,
    pub custom_policies: Option<String>,
    pub binding: Binding,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseInfo {
    #[serde(rename = "@Type")]
    pub license_type: LicenseType,
    #[serde(rename = "@LicenseUsage")]
    pub license_usage: Option<LicenseUsage>,
    #[serde(rename = "@LicenseCategory")]
    pub license_category: Option<String>,
    pub issued_date: Option<String>,
    pub last_updated_date: Option<String>,
    pub begin_date: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Binding {
    #[serde(rename = "@Binding_Type")]
    pub binding_type: String,
    pub device_id: Option<String>,
    #[serde(rename = "ProductID")]
    pub product_id: Option<String>,
    #[serde(rename = "PFM")]
    pub pfm: Option<String>,
    #[serde(rename = "UserID")]
    pub user_id: Option<String>,
    #[serde(rename = "USID")]
    pub usid: Option<String>,
    pub lease_required: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub enum LicenseType {
    Device,
    User,
    Full,
    KeyHolder,
    Trial,
    #[serde(other)]
    Unknown
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub enum LicenseUsage {
    Online,
    Offline,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct KeyHolderLicense {
    pub license: License,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ServerInfo {
    #[serde(rename = "@ServerTime")]
    pub server_time: String,
    #[serde(rename = "$value")]
    pub id: String,
}
