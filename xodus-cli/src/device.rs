use xodus::{
    hardware,
    licensing::utils::generate_string,
    models::{
        devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo},
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
            let encrypted_data = resp.requested_security_token.encrypted_data.unwrap();
            let token = xodus::models::secrets::Token {
                key_name: encrypted_data.key_info.as_named().key_name,
                cipher_value: encrypted_data.cipher_data.cipher_value,
                binary_secret: resp.requested_proof_token.unwrap().binary_secret,
                lifetime: resp.lifetime,
            };
            let entry = xodus::secrets::get_entry("device-STS").unwrap();
            let json = serde_json::to_string(&token).unwrap();
            entry.set_secret(json.as_bytes()).unwrap();
        }
    } else if get_device_token().is_err() {
        let license = license.unwrap();
        let tokens =
            xodus::api::live::authenticate_device(client, license.username, license.password)
                .await
                .expect("Failed to auth device");

        if let BodyContent::RequestSecurityTokenResponse(resp) = tokens.body.body {
            let encrypted_data = resp.requested_security_token.encrypted_data.unwrap();
            let token = xodus::models::secrets::Token {
                key_name: encrypted_data.key_info.as_named().key_name,
                cipher_value: encrypted_data.cipher_data.cipher_value,
                binary_secret: resp.requested_proof_token.unwrap().binary_secret,
                lifetime: resp.lifetime,
            };
            let entry = xodus::secrets::get_entry("device-STS").unwrap();
            let json = serde_json::to_string(&token).unwrap();
            entry.set_secret(json.as_bytes()).unwrap();
        }
    }
}

pub fn get_dev_license() -> Result<xodus::models::secrets::Device, Box<dyn std::error::Error>> {
    let device_entry = xodus::secrets::get_entry("dev_license")?;
    let secret = device_entry.get_secret()?;
    let dev = serde_json::from_slice::<xodus::models::secrets::Device>(&secret.as_slice())?;
    Ok(dev)
}

pub fn get_device_token() -> Result<xodus::models::secrets::Token, Box<dyn std::error::Error>> {
    let device_entry = xodus::secrets::get_entry("device-STS")?;
    let secret = device_entry.get_secret()?;
    let t = serde_json::from_slice::<xodus::models::secrets::Token>(&secret.as_slice())?;
    Ok(t)
}
