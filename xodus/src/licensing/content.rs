use std::collections::HashMap;

use xal::{cvlib::CorrelationVector, extensions::CorrelationVectorReqwestBuilder};

use crate::{
    licensing::utils,
    models::licensing::{DeviceContext, LicenseContentRequest, LicenseUserIdentity},
};

pub async fn get_license_content(
    client: &reqwest::Client,
    device_ms_token: String,
    user_ms_token: String,
    content_id: String,
    market: String,
) -> reqwest::Result<String> {
    let mut cv = CorrelationVector::new();
    let response = client
        .post("https://licensing.mp.microsoft.com/v7.0/licenses/content")
        .header("from", "XboxLicenseManager")
        .header("Authorization", device_ms_token)
        .header("user-agent", "XboxLm-PC/Microsoft.GamingServices_32.107.4002.0_x64__8wekyb3d8bbwe")
        .json(&LicenseContentRequest {
            content_id,
            market,
            client_challenge: "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8+PENsaWVudENoYWxsZW5nZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4bWxuczp4c2Q9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9vbmVzdG9yZS9zZWN1cml0eS9ta21zL0xpY1JlcS92MSIgVmVyc2lvbj0iMiI+PExpY2Vuc2VQcm90b2NvbFZlcnNpb24+NTwvTGljZW5zZVByb3RvY29sVmVyc2lvbj48U2lnbmluZ0tleVZlcnNpb24+MTwvU2lnbmluZ0tleVZlcnNpb24+PENsaWVudFZlcnNpb24+MjwvQ2xpZW50VmVyc2lvbj48L0NsaWVudENoYWxsZW5nZT4=".into(),
            concurrency_mode: "Rude".into(),
            license_version: 4,
            need_key: true,
            key_only: true,
            device_context: DeviceContext::default(),
            users: HashMap::from_iter(
                [(utils::generate_suid(),
                vec![LicenseUserIdentity {
                    identity_type: "Msa".to_string(),
                    identity_value: user_ms_token,
                    local_ticket_reference: "000CE6CA35BDEFFB".into(),
                }])],
            ),
        })
        .add_cv(&mut cv)
        .unwrap()
        .send()
        .await?;

    response.text().await
}
