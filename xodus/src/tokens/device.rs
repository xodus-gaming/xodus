use crate::{
    hardware,
    licensing::utils::generate_string,
    models::{
        devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo},
        secrets::Device,
        soap::BodyContent,
    },
    tokens::manager::TokenManager,
};

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(client: &reqwest::Client, tokens: &TokenManager) {
    match tokens.get_device_license() {
        Err(_) => provision_device(client, tokens).await,
        Ok(license) if tokens.get_device_sts_token().is_err() => {
            reauthenticate_device(client, tokens, license).await
        }
        Ok(_) => {}
    }
}

async fn provision_device(client: &reqwest::Client, tokens: &TokenManager) {
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

    let dev = crate::api::live::login_device_credential(client, provision)
        .await
        .expect("Failed to get device creds");

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    tokens
        .save_device_license(&device)
        .expect("Failed to save device license");

    let resp = crate::api::live::authenticate_device(client, username, password)
        .await
        .expect("Failed to auth device");

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp);
    }
}

async fn reauthenticate_device(client: &reqwest::Client, tokens: &TokenManager, license: Device) {
    let resp = crate::api::live::authenticate_device(client, license.username, license.password)
        .await
        .expect("Failed to auth device");

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp);
    }
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: crate::models::soap::RequestSecurityTokenResponse,
) {
    let key_name = resp
        .requested_security_token
        .encrypted_data
        .as_ref()
        .unwrap()
        .key_info
        .key_name
        .as_ref()
        .unwrap()
        .clone();
    let token = resp.into();
    tokens
        .save_device_token(key_name, token)
        .expect("Failed to save device token");
}
