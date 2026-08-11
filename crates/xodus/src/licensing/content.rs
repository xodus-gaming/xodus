use std::collections::HashMap;

use base64::prelude::*;
use xal::cvlib::CorrelationVector;
//use xal::extensions::CorrelationVectorReqwestBuilder;

use crate::licensing::utils;
use crate::models::devicecredential::License;
use crate::models::licensing::{
    DeviceContext, LicenseContentRequest, LicenseContentResponse, LicenseUserIdentity,
};

#[derive(Debug, thiserror::Error)]
pub enum LicenseContentError {
    #[error(
        "license response did not contain a license; make sure you own the game or have an active subscription that includes it"
    )]
    MissingLicense,
    #[error("license request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid license response: {0}")]
    InvalidResponse(#[from] serde_json::Error),
}

fn parse_license_response(body: &str) -> Result<LicenseContentResponse, LicenseContentError> {
    let response: serde_json::Value = serde_json::from_str(body)?;
    if response
        .get("license")
        .is_none_or(serde_json::Value::is_null)
    {
        return Err(LicenseContentError::MissingLicense);
    }

    Ok(serde_json::from_value(response)?)
}

// we might need a bump in xal-rs concerning reqwest,
// that might block us from using the correlationvector extension
pub async fn get_license_content(
    client: &reqwest::Client,
    device_ms_token: String,
    user_ms_token: String,
    ticket_reference: String,
    content_id: String,
    market: String,
) -> Result<(LicenseContentResponse, License), LicenseContentError> {
    let cv = CorrelationVector::new();
    let response = client
        .post("https://licensing.mp.microsoft.com/v7.0/licenses/content")
        .header("from", "XboxLicenseManager")
        .header("Authorization", device_ms_token)
        .header("user-agent", "XboxLm-PC/Microsoft.GamingServices_32.107.4002.0_x64__8wekyb3d8bbwe")
        .header("MS-CV", cv.to_string())
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
                    local_ticket_reference: ticket_reference,
                }])],
            ),
        })
        .send()
        .await?;

    let body = response.text().await?;
    let content_res = parse_license_response(&body)?;
    let license = &content_res.license.keys[0].value;
    let license = BASE64_STANDARD.decode(license).unwrap();
    let license = quick_xml::de::from_str::<License>(&String::from_utf8(license).unwrap()).unwrap();
    Ok((content_res, license))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_license_explains_ownership_requirement() {
        let error = parse_license_response(r#"{"error":"No license found"}"#).unwrap_err();

        assert_eq!(
            error.to_string(),
            "license response did not contain a license; make sure you own the game or have an active subscription that includes it"
        );
    }
}
