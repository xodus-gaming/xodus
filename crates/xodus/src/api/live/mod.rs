use base64::prelude::*;
use chrono::{DateTime, FixedOffset};
use zerocopy::transmute;

use crate::licensing::splicense::ClepHmacState;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;
use crate::tokens::TokenManager;
use crate::tokens::store::TokenStoreError;

pub mod rst;
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

pub trait ExchangeTokenResponseOutcome {
    fn get_rps(&self) -> Option<(String, Option<DateTime<FixedOffset>>)>;
    fn refresh_device(&self, tokens: &TokenManager) -> Result<(), TokenStoreError>;
    fn refresh_user(&self, tokens: &TokenManager) -> Result<(), TokenStoreError>;
}

impl ExchangeTokenResponseOutcome for soap::RequestSecurityTokenResponseCollection {
    fn get_rps(&self) -> Option<(String, Option<DateTime<FixedOffset>>)> {
        let Some((Token::Compact(compact), expiry)) = self.security_tokens.first().map(|t| {
            (
                t.clone().into(),
                chrono::DateTime::parse_from_rfc3339(&t.lifetime.expires).ok(),
            )
        }) else {
            return None;
        };
        Some((compact, expiry))
    }
    fn refresh_device(&self, tokens: &TokenManager) -> Result<(), TokenStoreError> {
        refresh_tokens(self, |address, token| {
            tokens.save_device_token(address, token)
        })
    }
    fn refresh_user(&self, tokens: &TokenManager) -> Result<(), TokenStoreError> {
        refresh_tokens(self, |address, token| {
            tokens.save_user_token(address, token)
        })
    }
}

fn refresh_tokens<F: Fn(String, Token) -> Result<(), TokenStoreError>>(
    collection: &soap::RequestSecurityTokenResponseCollection,
    store_token: F,
) -> Result<(), TokenStoreError> {
    let mut result = None;
    for resp in &collection.security_tokens {
        let address = resp.applies_to.endpoint_reference.address.clone();
        let token = resp.clone().into();
        let address = if let Token::Legacy(legacy) = &token {
            legacy.key_name.clone().unwrap_or(address)
        } else {
            address
        };
        if let Err(e) = store_token(address, token) {
            result = Some(e);
        }
    }
    result.map_or_else(|| Ok(()), Err)
}

fn to_outcome(
    envelope: soap::Envelope,
) -> Result<soap::RequestSecurityTokenResponseCollection, rst::RSTError> {
    match envelope.body.body {
        soap::BodyContent::Fault(_) => Err(rst::RSTError::TokenFault(envelope.header.pp)),
        soap::BodyContent::RequestSecurityTokenResponse(f) => {
            Ok(soap::RequestSecurityTokenResponseCollection {
                security_tokens: vec![*f],
            })
        }
        soap::BodyContent::RequestSecurityTokenResponseCollection(f) => Ok(f),
        _ => Err(rst::RSTError::UnexpectedTokenResponse(envelope.body.body)),
    }
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    private_key: rsa::RsaPrivateKey,
) -> Result<soap::RequestSecurityTokenResponseCollection, rst::RSTError> {
    let request = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::devicetoken(username))
        .signature(rst::RSTSignature::Rsa(Box::new(private_key)))
        .scope_policy("http://Passport.NET/tb", None)
        .build()?;

    to_outcome(request.request(client).await?)
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

pub async fn exchange_device_token(
    client: &reqwest::Client,
    device_token: LegacyToken,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> Result<soap::RequestSecurityTokenResponseCollection, rst::RSTError> {
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

    to_outcome(request.request(client).await?)
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
) -> Result<soap::RequestSecurityTokenResponseCollection, rst::RSTError> {
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

    to_outcome(request.request(client).await?)
}

#[cfg(test)]
mod test {
    use crate::api::live::{ExchangeTokenResponseOutcome, exchange_device_token};
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
