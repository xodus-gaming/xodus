use base64::prelude::*;
use zerocopy::transmute;

use crate::licensing::splicense::ClepHmacState;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;

mod rst;
pub use rst::fault::SoapFault;
pub use rst::RSTError;
mod utils;

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> Result<DeviceAddResponse, rst::RSTError> {
    let data = quick_xml::se::to_string(&data)?;

    let response = client
        .post("https://login.live.com/ppsecure/deviceaddcredential.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(data)
        .send()
        .await?;
    let text = response.text().await?;
    let resp: DeviceAddResponse = quick_xml::de::from_str(&text)?;
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

    request.request(client, None).await
}

fn clep_state(token: &LegacyToken) -> Result<ClepHmacState, rst::RSTError> {
    let secret = token.binary_secret.as_ref().ok_or(rst::RSTError::HmacKey)?;
    let secret = BASE64_STANDARD.decode(secret)?;
    let secret: [u8; 4096] = secret.try_into().map_err(|_| rst::RSTError::HmacKey)?;
    Ok(transmute!(secret))
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    token: LegacyToken,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
    timeout: Option<std::time::Duration>,
) -> Result<soap::RequestSecurityTokenResponse, rst::RSTError> {
    let hmac_secret = clep_state(&token)?.get_hmac_state();

    let request = rst::RSTRequestBuilder::new()
        .sso_flags("SsoRestr")
        .hosting_app(&hosting_app)
        .device_token(token)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        })
        .scope_policy(&scope, policy)
        .build()?;

    let envelope = request.request(client, timeout).await?;

    match envelope.body.body {
        soap::BodyContent::RequestSecurityTokenResponse(res) => Ok(*res),
        soap::BodyContent::RequestSecurityTokenResponseCollection(collection) => {
            collection.security_tokens.into_iter().next().ok_or_else(|| {
                rst::RSTError::UnexpectedResponse(
                    "empty RequestSecurityTokenResponseCollection".to_string(),
                )
            })
        }
        b => Err(rst::RSTError::UnexpectedResponse(format!("{b:?}"))),
    }
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
    timeout: Option<std::time::Duration>,
) -> Result<ExchangeUserTokenOutcome, rst::RSTError> {
    let hmac_secret = clep_state(&device_token)?.get_hmac_state();

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
    let (envelope, fault) = request.request_allow_fault(client, timeout).await?;

    match fault {
        None => Ok(ExchangeUserTokenOutcome::Issued(envelope.body.body)),
        Some(f) => interactive_fault(f, inline_ux.as_deref(), Some(&envelope))
            .map(|pp| ExchangeUserTokenOutcome::Fault(Some(pp))),
    }
}

/// Interactive callers (no `inline_ux`) can get a Fault whose decrypted `psf:pp` carries an
/// inline auth URL (e.g. "Platform SSO permission interrupt") to open in the webview.
/// Every other Fault, including one whose envelope could not be decrypted, stays `RSTError::Fault`.
fn interactive_fault(
    f: SoapFault,
    inline_ux: Option<&str>,
    envelope: Option<&soap::Envelope>,
) -> Result<soap::PP, rst::RSTError> {
    match envelope.and_then(|e| e.header.pp.as_ref()) {
        Some(pp) if inline_ux.is_none() && pp.inline_auth_url.is_some() => Ok(pp.clone()),
        _ => Err(rst::RSTError::Fault(f)),
    }
}

#[cfg(test)]
mod test {
    use super::{clep_state, interactive_fault, SoapFault};

    fn fault_envelope(inline_auth_url: Option<&str>) -> soap::Envelope {
        let mut envelope: soap::Envelope =
            quick_xml::de::from_str(include_str!("rst/testdata/rst-fault.xml")).unwrap();
        envelope.header.pp = Some(soap::PP {
            xmlns_psf: None,
            server_version: None,
            req_status: None,
            inline_auth_url: inline_auth_url.map(String::from),
            inline_end_auth_url: None,
            auth_state_internal: None,
            user_session_key: None,
        });
        envelope
    }

    #[test]
    fn request_allow_fault_undecryptable_is_fault() {
        let r = interactive_fault(SoapFault::default(), None, None);
        assert!(matches!(r, Err(super::rst::RSTError::Fault(_))));
    }

    #[test]
    fn request_allow_fault_inline_ux_is_fault() {
        let envelope = fault_envelope(Some("https://login.live.com/x"));
        let r = interactive_fault(SoapFault::default(), Some("ux"), Some(&envelope));
        assert!(matches!(r, Err(super::rst::RSTError::Fault(_))));
    }

    #[test]
    fn request_allow_fault_no_inline_auth_is_fault() {
        let envelope = fault_envelope(None);
        let r = interactive_fault(SoapFault::default(), None, Some(&envelope));
        assert!(matches!(r, Err(super::rst::RSTError::Fault(_))));
    }

    #[test]
    fn request_allow_fault_interactive_inline_auth_is_pp() {
        let envelope = fault_envelope(Some("https://login.live.com/x"));
        let pp = interactive_fault(SoapFault::default(), None, Some(&envelope)).unwrap();
        assert_eq!(pp.inline_auth_url.as_deref(), Some("https://login.live.com/x"));
    }
    use crate::models::secrets::LegacyToken;

    #[test]
    fn clep_state_rejects_missing_or_short_secret() {
        let mut t = LegacyToken {
            key_name: None,
            token: String::new(),
            binary_secret: None,
            tpm_key: None,
            lifetime: crate::models::soap::Timestamp {
                id: None,
                created: String::new(),
                expires: String::new(),
            },
        };
        assert!(matches!(clep_state(&t), Err(super::rst::RSTError::HmacKey)));
        t.binary_secret = Some(base64::Engine::encode(&base64::prelude::BASE64_STANDARD, [0u8; 8]));
        assert!(matches!(clep_state(&t), Err(super::rst::RSTError::HmacKey)));
    }

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
        let resp = exchange_device_token(
            &client,
            token,
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
            None,
        )
        .await
        .unwrap();

        let ms_device_token: Token = resp.into();
        let Token::Compact(ms_device_token) = ms_device_token else {
            todo!("Unsupported token");
        };

        println!("{}", ms_device_token);
    }
}
