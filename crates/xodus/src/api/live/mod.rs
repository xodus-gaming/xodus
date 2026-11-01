use base64::prelude::*;
use chrono::{DateTime, FixedOffset};
use tracing::warn;
use zerocopy::transmute;

use crate::licensing::splicense::ClepHmacState;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;
use crate::tokens::TokenManager;
use crate::tokens::store::TokenStoreError;

mod rst;
mod utils;

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> reqwest::Result<DeviceAddResponse> {
    let data = quick_xml::se::to_string(&data).unwrap();

    let response = client
        .post("https://login.live.com/ppsecure/deviceaddcredential.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(data)
        .send()
        .await?;
    let text = response.text().await?;
    let resp: DeviceAddResponse = quick_xml::de::from_str(&text).expect("Failed to de xml");
    Ok(resp)
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    private_key: rsa::RsaPrivateKey,
) -> Result<soap::Envelope, rst::RSTError> {
    let request = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::devicetoken(username))
        .signature(rst::RSTSignature::Rsa(Box::new(private_key)))
        .scope_policy("http://Passport.NET/tb", None)
        .build()?;

    request.request(client).await
}

#[derive(Debug, Clone)]
pub enum ExchangeTokenResponseOutcome {
    RequestSecurityTokenResponseCollection(soap::RequestSecurityTokenResponseCollection),
    RequestSecurityTokenResponse(Box<soap::RequestSecurityTokenResponse>),
    Fault(Option<soap::PP>),
}

pub trait TraceTokenRefreshError {
    fn trace(self);
}

impl TraceTokenRefreshError for Result<(), TokenStoreError> {
    fn trace(self) {
        match self {
            Ok(_) => {}
            Err(err) => tracing::warn!("Failed to persist refreshed STS token: {err}"),
        }
    }
}

impl ExchangeTokenResponseOutcome {
    pub fn get_rps(&self) -> Option<(String, Option<DateTime<FixedOffset>>)> {
        match &self {
            ExchangeTokenResponseOutcome::RequestSecurityTokenResponse(resp) => Some(resp.as_ref()),
            ExchangeTokenResponseOutcome::RequestSecurityTokenResponseCollection(collection) => {
                collection.security_tokens.get(0)
            }
            b => {
                warn!("Exchange token supports only singular token right now {b:?}");
                None
            }
        }
        .map(|resp| {
            let Token::Compact(compact) = resp.clone().into() else {
                return None;
            };
            Some((
                compact,
                chrono::DateTime::parse_from_rfc3339(&resp.lifetime.expires).ok(),
            ))
        })
        .unwrap_or_default()
    }
    pub fn refresh_device(&self, tokens: &TokenManager) -> Result<(), TokenStoreError> {
        self.refresh(tokens, false)
    }
    pub fn refresh_user(&self, tokens: &TokenManager) -> Result<(), TokenStoreError> {
        self.refresh(tokens, true)
    }
    fn refresh_token(
        resp: &soap::RequestSecurityTokenResponse,
        tokens: &TokenManager,
        user: bool,
    ) -> Result<(), TokenStoreError> {
        let address = resp.applies_to.endpoint_reference.address.clone();
        let token = resp.clone().into();
        let address = if let Token::Legacy(legacy) = &token {
            legacy.key_name.clone().unwrap_or(address)
        } else {
            address
        };
        // Error not so important, except if happen more often
        if user {
            tokens.save_user_token(address, token)
        } else {
            tokens.save_device_token(address, token)
        }
    }
    fn refresh(&self, tokens: &TokenManager, user: bool) -> Result<(), TokenStoreError> {
        let mut result = None;
        match &self {
            ExchangeTokenResponseOutcome::RequestSecurityTokenResponse(resp) => {
                if let Err(e) = Self::refresh_token(resp, tokens, user) {
                    result = Some(e);
                }
            }
            ExchangeTokenResponseOutcome::RequestSecurityTokenResponseCollection(collection) => {
                for resp in &collection.security_tokens {
                    if let Err(e) = Self::refresh_token(resp, tokens, user) {
                        result = Some(e);
                    }
                }
            }
            b => {
                warn!("Exchange token supports only singular token right now {b:?}");
            }
        }
        result.map_or_else(|| Ok(()), |e| Err(e))
    }
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    device_token: LegacyToken,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> Result<ExchangeTokenResponseOutcome, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(device_token.binary_secret.as_ref().unwrap())?;
    let secret: [u8; 4096] = secret.try_into().unwrap();
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let request = rst::RSTRequestBuilder::new()
        .sso_flags("SsoRestr")
        .hosting_app(&hosting_app)
        .device_token(device_token)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        })
        .scope_policy(&scope, policy)
        .scope_policy("http://Passport.NET/tb", None)
        .build()?;

    let envelope = request.request(client).await?;

    Ok(match envelope.body.body {
        soap::BodyContent::Fault(_) => ExchangeTokenResponseOutcome::Fault(None),
        soap::BodyContent::RequestSecurityTokenResponse(f) => {
            ExchangeTokenResponseOutcome::RequestSecurityTokenResponse(f)
        }
        soap::BodyContent::RequestSecurityTokenResponseCollection(f) => {
            ExchangeTokenResponseOutcome::RequestSecurityTokenResponseCollection(f)
        }
        _ => {
            return Err(rst::RSTError::Deserialization(quick_xml::DeError::Custom(
                "Unexpected Answer".to_owned(),
            )));
        }
    })
}

// Each parameter maps directly to a distinct SOAP request field; grouping them
// into a params struct would just move the sprawl rather than reduce it.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_user_token(
    client: &reqwest::Client,
    user_token: LegacyToken,
    username: String,
    device_token: LegacyToken,
    inline_token: Option<String>,
    inline_ux: Option<String>,
    hosting_app: String,
    scope_policies: &[(String, Option<soap::PolicyReference>)],
) -> Result<ExchangeTokenResponseOutcome, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(device_token.binary_secret.as_ref().unwrap())?;
    let secret: [u8; 4096] = secret.try_into().unwrap();
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let mut builder = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::user_hint(username))
        .device_token(device_token)
        .user_token(Token::Legacy(user_token))
        .hosting_app(&hosting_app)
        .sso_flags("SsoRestr")
        .license_signature_key_version(None)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        });

    if let Some(ux) = inline_ux.as_deref() {
        builder = builder.inline_ux(ux);
    }
    if let Some(ft) = inline_token.as_deref() {
        builder = builder.inline_ft(ft);
    }
    for (scope, policy) in scope_policies {
        builder = builder.scope_policy(scope, policy.clone());
    }

    let request = builder.build()?;
    let envelope = request.request(client).await?;

    Ok(match envelope.body.body {
        soap::BodyContent::Fault(_) => ExchangeTokenResponseOutcome::Fault(envelope.header.pp),
        soap::BodyContent::RequestSecurityTokenResponse(f) => {
            ExchangeTokenResponseOutcome::RequestSecurityTokenResponse(f)
        }
        soap::BodyContent::RequestSecurityTokenResponseCollection(f) => {
            ExchangeTokenResponseOutcome::RequestSecurityTokenResponseCollection(f)
        }
        _ => {
            return Err(rst::RSTError::Deserialization(quick_xml::DeError::Custom(
                "Unexpected Answer".to_owned(),
            )));
        }
    })
}

#[cfg(test)]
mod test {
    use crate::api::live::exchange_device_token;
    use crate::models::secrets::Token;
    use crate::models::soap;
    use crate::tokens::TokenManager;
    use crate::tokens::device::ensure_device_credentials;

    #[tokio::test]
    async fn test_get_xbox_live_dev_token() {
        let client = reqwest::Client::new();

        let mgr = TokenManager::with_memory();
        ensure_device_credentials(&client, &mgr).await;

        let token: Token = mgr.get_device_sts_token().unwrap();
        let Token::Legacy(token) = token else {
            todo!("no a LegacyToken");
        };
        println!("{}\n{}", token.token, token.binary_secret.as_ref().unwrap());
        let resp = exchange_device_token(
            &client,
            token,
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await
        .unwrap();

        resp.refresh_device(&mgr).unwrap();

        let Some((ms_device_token, _)) = resp.get_rps() else {
            todo!("Unsupported token");
        };

        println!("{}", ms_device_token);
    }
}
