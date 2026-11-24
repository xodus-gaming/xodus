use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::{Device, Token};
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(client: &reqwest::Client, tokens: &TokenManager) {
    match tokens.get_device_license() {
        Err(_) => provision_device(client, tokens).await,
        Ok(license) if !device_sts_token_valid(tokens, chrono::Utc::now()) => {
            if let Err(e) = reauthenticate_device(client, tokens, license).await {
                tracing::warn!("Device STS token renewal failed: {e}");
            }
        }
        Ok(_) => {}
    }
}

/// A stored Legacy device STS token counts as valid until 5 minutes before its `Expires`.
fn device_sts_token_valid(tokens: &TokenManager, now: chrono::DateTime<chrono::Utc>) -> bool {
    match tokens.get_device_sts_token() {
        Ok(Token::Legacy(t)) => chrono::DateTime::parse_from_rfc3339(&t.lifetime.expires)
            .is_ok_and(|exp| exp > now + chrono::Duration::minutes(5)),
        Ok(Token::Compact(_)) => true,
        Err(_) => false,
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
            tpm_info: None,
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

    reauthenticate_device(client, tokens, device)
        .await
        .expect("Failed to auth device");
}

async fn reauthenticate_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
    license: Device,
) -> Result<(), String> {
    let sp_license = SPLicense::parse_base64(&license.splicense)
        .map_err(|e| format!("Failed to parse SPLicense: {e}"))?;
    let clep_sign_state = sp_license
        .clep_sign_state
        .ok_or("Missing clep sign state")?;
    let key = clep_sign_state.get_rsa_key();
    let private_key =
        parse_bcrypt_rsa_private(&key).map_err(|e| format!("Invalid device RSA key: {e}"))?;
    let resp = crate::api::live::authenticate_device(client, license.username, private_key)
        .await
        .map_err(|e| format!("Failed to auth device: {e}"))?;

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp)?;
    }
    Ok(())
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) -> Result<(), String> {
    let key_name = resp
        .requested_security_token
        .encrypted_data
        .as_ref()
        .and_then(|data| data.key_info.key_name.clone())
        .ok_or("Device token response has no key name")?;
    let token = (*resp).into();
    tokens
        .save_device_token(key_name, token)
        .map_err(|e| format!("Failed to save device token: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::secrets::LegacyToken;
    use crate::models::soap::Timestamp;
    use crate::tokens::PASSPORT_STS;

    fn with_expiry(expires: &str) -> TokenManager {
        let mgr = TokenManager::with_memory();
        let token = LegacyToken {
            key_name: None,
            token: String::new(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp { id: None, created: String::new(), expires: expires.into() },
        };
        mgr.save_device_token(PASSPORT_STS.into(), Token::Legacy(token)).unwrap();
        mgr
    }

    fn placeholder_device() -> Device {
        Device {
            puid: String::new(),
            hwid: String::new(),
            device_id: String::new(),
            splicense: String::new(),
            username: "02placeholder".into(),
            password: String::new(),
        }
    }

    #[test]
    fn device_sts_token_validity() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-12T00:00:00Z").unwrap().to_utc();
        assert!(!device_sts_token_valid(&TokenManager::with_memory(), now));
        assert!(!device_sts_token_valid(&with_expiry("2026-10-22T18:43:18Z"), now));
        assert!(!device_sts_token_valid(&with_expiry("2026-11-12T00:04:00Z"), now));
        assert!(!device_sts_token_valid(&with_expiry("garbage"), now));
        assert!(device_sts_token_valid(&with_expiry("2026-12-01T00:00:00Z"), now));
    }

    #[tokio::test]
    async fn device_sts_token_renewal_failure() {
        let expires = "2026-10-22T18:43:18Z";
        let tokens = with_expiry(expires);
        tokens.save_device_license(&placeholder_device()).unwrap();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_nanos(1))
            .build()
            .unwrap();
        ensure_device_credentials(&client, &tokens).await;
        match tokens.get_device_sts_token().unwrap() {
            Token::Legacy(t) => assert_eq!(t.lifetime.expires, expires),
            Token::Compact(_) => panic!("device token replaced"),
        }
        assert!(reauthenticate_device(&client, &tokens, placeholder_device()).await.is_err());
    }
}
