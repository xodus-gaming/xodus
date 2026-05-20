use xodus::{
    hardware,
    licensing::utils::generate_string,
    models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo},
};

pub async fn run(client: &reqwest::Client) {
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
    let tokens = xodus::api::live::authenticate_device(client, username, password)
        .await
        .expect("Failed to auth device");
}
