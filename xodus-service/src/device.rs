use std::collections::HashMap;

use xodus::{
    hardware,
    licensing::utils::generate_string,
    models::{
        devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo},
        secrets::{Token, TokenStore},
        soap::BodyContent,
    },
};

pub async fn ensure_device_credentials(client: &reqwest::Client) {
    let license = get_dev_license();
    if license.is_err() {
        let username = format!("02{}", generate_string(14));
        let password = generate_string(20);
        let provision = DeviceAddRequest {
            client_info: ClientInfo::default(),
            authentication: Authentication::new(username.clone(), password.clone()),
            device_info: Some(DeviceInfo {
                id: "DeviceInfo".to_string(),
                components: hardware::probe_provision_components(),
            }),
        };

        let dev = xodus::api::live::login_device_credential(client, provision)
            .await
            .expect("Failed to get device creds");

        let device = xodus::models::secrets::Device {
            username: username.clone(),
            password: password.clone(),
            puid: dev.puid,
            hwid: dev.hw_device_id,
            device_id: dev.license.binding.device_id.unwrap_or_default(),
            splicense: dev.license.splicense_block,
        };

        let entry = xodus::secrets::get_entry("dev_license").unwrap();
        let json = serde_json::to_string(&device).unwrap();
        entry.set_secret(json.as_bytes()).unwrap();

        let tokens = xodus::api::live::authenticate_device(client, username, password)
            .await
            .expect("Failed to auth device");

        if let BodyContent::RequestSecurityTokenResponse(resp) = tokens.body.body {
            let key_name = resp
                .requested_security_token
                .encrypted_data
                .as_ref()
                .unwrap()
                .key_info
                .key_name
                .as_ref()
                .unwrap();
            let key_name = key_name.clone();
            let token: xodus::models::secrets::Token = resp.into();
            save_token(key_name, token);
        }
    } else if get_device_token().is_err() {
        let license = license.unwrap();
        let tokens =
            xodus::api::live::authenticate_device(client, license.username, license.password)
                .await
                .expect("Failed to auth device");

        if let BodyContent::RequestSecurityTokenResponse(resp) = tokens.body.body {
            let key_name = resp
                .requested_security_token
                .encrypted_data
                .as_ref()
                .unwrap()
                .key_info
                .key_name
                .as_ref()
                .unwrap();
            let key_name = key_name.clone();
            let token: xodus::models::secrets::Token = resp.into();
            save_token(key_name, token);
        }
    }
}

pub fn get_dev_license() -> Result<xodus::models::secrets::Device, Box<dyn std::error::Error>> {
    let device_entry = xodus::secrets::get_entry("dev_license")?;
    let secret = device_entry.get_secret()?;
    let dev = serde_json::from_slice::<xodus::models::secrets::Device>(secret.as_slice())?;
    Ok(dev)
}

pub fn get_device_token() -> Result<xodus::models::secrets::Token, Box<dyn std::error::Error>> {
    get_token("http://Passport.NET/STS".to_string()).ok_or("Error".into())
}

pub fn save_token(address: String, token: Token) {
    let entry = xodus::secrets::get_entry("device-tokens").unwrap();
    let passwd = entry.get_password().unwrap_or_default();

    let mut tokens = if !passwd.is_empty() {
        let tokens = serde_json::from_str::<TokenStore>(&passwd).unwrap();
        tokens.tokens
    } else {
        HashMap::new()
    };
    tokens.insert(address, token);
    let tokens = TokenStore { tokens };
    let tokens_str = serde_json::to_string(&tokens).unwrap();
    entry.set_password(&tokens_str).unwrap();
}

pub fn get_token(address: String) -> Option<Token> {
    let entry = xodus::secrets::get_entry("device-tokens").unwrap();
    let passwd = entry.get_password().unwrap_or_default();

    let tokens = if !passwd.is_empty() {
        let tokens = serde_json::from_str::<TokenStore>(&passwd).unwrap();
        tokens.tokens
    } else {
        HashMap::new()
    };
    tokens.get(&address).cloned()
}
