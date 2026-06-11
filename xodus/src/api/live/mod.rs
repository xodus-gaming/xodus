use base64::prelude::*;
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};
use rsa::rand_core::{OsRng, RngCore};

use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::soap::{
    self, AlgorithmNode, AppliesTo, BinarySecurityTokenReq, DerivedKeyToken, EncryptedData,
    EndpointReference, ReferenceUri, RequestMultipleSecurityTokens, SecurityTokenReference,
    SignatureReference, SignatureTransforms, SignedInfo, UsernameToken,
};

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
    password: String,
) -> reqwest::Result<soap::Envelope> {
    let mut header = soap::Header::new();
    header.security.username_token = Some(UsernameToken::devicetoken(username, password));
    let body = soap::Body {
        body: soap::BodyContent::RequestSecurityToken(soap::RequestSecurityToken {
            id: "RST0".to_string(),
            request_type: "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue".to_string(),
            applies_to: AppliesTo {
                endpoint_reference: EndpointReference {
                    address: "http://Passport.NET/tb".to_string(),
                },
            },
            policy_reference: None,
        }),
    };
    let envelope = soap::Envelope::new(header, body);
    let xml = quick_xml::se::to_string(&envelope).unwrap();
    let xml = format!("{XML_HEADER}\n{xml}");
    let response = client
        .post("https://login.live.com/RST2.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(xml)
        .send()
        .await?;

    let text = response.text().await?;
    let res_envelope: soap::Envelope = quick_xml::de::from_str(&text).expect("Failed to de xml");

    Ok(res_envelope)
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    token: String,
    shared_secret: String,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> reqwest::Result<soap::RequestSecurityTokenResponse> {
    let mut header = soap::Header::new();
    if let Some(i) = header.auth_info.as_mut() {
        i.hosting_app = hosting_app;
        i.sso_flags = "SsoRestr".to_string();
    }
    let encrypted_data = quick_xml::de::from_str(&token).unwrap();
    header.security.encrypted_data = Some(encrypted_data);
    let nonce = utils::generate_nonce();
    let secret = BASE64_STANDARD.decode(shared_secret).unwrap();

    let hmac_key = utils::generate_shared_key(
        32,
        &secret,
        "WS-SecureConversationWS-SecureConversation",
        &nonce,
    );
    let nonceb64: String = BASE64_STANDARD.encode(nonce);

    header.security.derived_key_tokens = vec![DerivedKeyToken{
        nonce: nonceb64,
        id: "SignKey".to_string(),
        algorithm: "urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED".to_string(),
        token_reference: None,
        requested_token_reference: Some(soap::RequestedTokenReference { key_identifier: soap::KeyIdentifier { value_type: "http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".to_string(), value: None }, reference: soap::ReferenceUri { uri: "".to_string() } })
    }];
    header.security.signature = Some(soap::Signature {
        xmlns: "http://www.w3.org/2000/09/xmldsig#".to_string(),
        signed_info: SignedInfo {
            canonicalization_method: AlgorithmNode {
                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
            },
            reference: vec![
                SignatureReference {
                    uri: "#RST0".to_string(),
                    digest_method: AlgorithmNode {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
                    },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![AlgorithmNode {
                            algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                        }],
                    },
                },
                SignatureReference {
                    uri: "#Timestamp".to_string(),
                    digest_method: AlgorithmNode {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
                    },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![AlgorithmNode {
                            algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                        }],
                    },
                },
                SignatureReference {
                    uri: "#PPAuthInfo".to_string(),
                    digest_method: AlgorithmNode {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
                    },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![AlgorithmNode {
                            algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                        }],
                    },
                },
            ],
            signature_method: AlgorithmNode {
                algorithm: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256".to_string(),
            },
        },
        signature_value: "".to_string(),
        key_info: Some(soap::SignatureKeyInfo {
            security_token_reference: SecurityTokenReference {
                reference: ReferenceUri {
                    uri: "#SignKey".to_string(),
                },
            },
        }),
    });
    let body = soap::Body {
        body: soap::BodyContent::RequestSecurityToken(soap::RequestSecurityToken {
            id: "RST0".to_string(),
            request_type: "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue".to_string(),
            applies_to: AppliesTo {
                endpoint_reference: EndpointReference { address: scope },
            },
            policy_reference: policy,
        }),
    };

    let envelope = soap::Envelope::new(header, body);
    let xml = quick_xml::se::to_string(&envelope).unwrap();
    let xml = format!("{XML_HEADER}\n{xml}");

    let mut kmgr = KeysManager::new();
    kmgr.add_key(Key::new(KeyData::Hmac(hmac_key.to_vec()), KeyUsage::Sign));

    let ctx = DsigContext::new(kmgr).with_strict_verification(false);
    let prefixes: [&str; 0] = [];
    let min_xml = bergshamra::c14n::canonicalize(
        xml.as_str(),
        bergshamra_c14n::C14nMode::Exclusive,
        None,
        &prefixes,
    )
    .unwrap();

    let signed = bergshamra::sign(&ctx, std::str::from_utf8(&min_xml).unwrap()).unwrap();

    let response = client
        .post("https://login.live.com/RST2.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(signed)
        .send()
        .await?;

    let text = response.text().await?;

    let res_envelope: soap::Envelope = quick_xml::de::from_str(&text).expect("Failed to de xml");
    let mut nonce = None;
    for token in &res_envelope.header.security.derived_key_tokens {
        if token.id == "SignKey" {
            nonce = Some(token.nonce.clone());
            continue;
        }
    }
    let nonce = nonce.unwrap();
    let nonce = BASE64_STANDARD.decode(nonce).unwrap();
    let key = utils::generate_shared_key(
        32,
        &secret,
        "WS-SecureConversationWS-SecureConversation",
        &nonce,
    );

    let mut kmgr = KeysManager::new();
    kmgr.add_key(Key::new(KeyData::Hmac(key.to_vec()), KeyUsage::Verify));
    let ctx = DsigContext::new(kmgr).with_strict_verification(false);
    let result = bergshamra::verify(&ctx, &text).unwrap();
    match result {
        bergshamra::VerifyResult::Invalid { reason } => {
            println!("DEVICE {}", reason);
        }
        bergshamra::VerifyResult::Valid { .. } => {
            println!("signature valid");
        }
    }

    match utils::decrypt_response(res_envelope, &secret).expect("Failed to decrypt") {
        (soap::BodyContent::RequestSecurityTokenResponse(res), _) => Ok(res),
        (soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection), _) => {
            let token = collection.security_tokens.remove(0);
            Ok(token)
        }
        (b, _) => unimplemented!("Exchange token supports only singular token right now {b:?}"),
    }
}

pub async fn exchange_user_token(
    client: &reqwest::Client,
    user_token: String,
    username: String,
    device_token: String,
    shared_secret: String,
    inline_token: Option<String>,
    inline_ux: Option<String>,
    hosting_app: String,
    scope_policies: &[(String, Option<soap::PolicyReference>)],
) -> reqwest::Result<ExchangeUserTokenOutcome> {
    let mut header = soap::Header::new();
    if let Some(i) = header.auth_info.as_mut() {
        i.hosting_app = hosting_app;
        i.sso_flags = "SsoRestr".to_string();
        i.license_signature_key_version = None;
        i.inline_ux = inline_ux.unwrap_or("TokenBroker".to_string());
        i.inline_ft = inline_token
    }
    header.security.username_token = Some(soap::UsernameToken::user_hint(username));
    let data: EncryptedData = quick_xml::de::from_str(&user_token).unwrap();
    header.security.encrypted_data = Some(data);

    header.security.binary_security_token = vec![BinarySecurityTokenReq {
        id: "DeviceDAToken".to_string(),
        value_type: "urn:liveid:device".to_owned(),
        value: device_token,
    }];
    let mut nonce = [0u8; 32];
    _ = OsRng.try_fill_bytes(&mut nonce);
    let secret = BASE64_STANDARD.decode(shared_secret).unwrap();

    let hmac_key = utils::generate_shared_key(
        32,
        &secret,
        "WS-SecureConversationWS-SecureConversation",
        &nonce,
    );
    let mut nonceb64: String = "".to_string();
    BASE64_STANDARD.encode_string(nonce, &mut nonceb64);

    header.security.derived_key_tokens = vec![DerivedKeyToken{
        nonce: nonceb64,
        id: "SignKey".to_string(),
        algorithm: "urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED".to_string(),
        token_reference: None,
        requested_token_reference: Some(soap::RequestedTokenReference { key_identifier: soap::KeyIdentifier { value_type: "http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".to_string(), value: None }, reference: soap::ReferenceUri { uri: "#DeviceDAToken".to_string() } })
    }];
    let multiple_policies = scope_policies.len() > 1;
    header.security.signature = Some(soap::Signature {
        xmlns: "http://www.w3.org/2000/09/xmldsig#".to_string(),
        signed_info: SignedInfo {
            canonicalization_method: AlgorithmNode {
                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
            },
            reference: vec![
                SignatureReference {
                    uri: if multiple_policies { "#RSTS" } else { "#RST0" }.to_string(),
                    digest_method: AlgorithmNode {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
                    },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![AlgorithmNode {
                            algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                        }],
                    },
                },
                SignatureReference {
                    uri: "#Timestamp".to_string(),
                    digest_method: AlgorithmNode {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
                    },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![AlgorithmNode {
                            algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                        }],
                    },
                },
                SignatureReference {
                    uri: "#PPAuthInfo".to_string(),
                    digest_method: AlgorithmNode {
                        algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
                    },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![AlgorithmNode {
                            algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                        }],
                    },
                },
            ],
            signature_method: AlgorithmNode {
                algorithm: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256".to_string(),
            },
        },
        signature_value: "".to_string(),
        key_info: Some(soap::SignatureKeyInfo {
            security_token_reference: SecurityTokenReference {
                reference: ReferenceUri {
                    uri: "#SignKey".to_string(),
                },
            },
        }),
    });
    let body = if multiple_policies {
        let mut security_tokens: Vec<soap::RequestSecurityToken> =
            Vec::with_capacity(scope_policies.len());
        for (i, (scope, policy)) in scope_policies.iter().cloned().enumerate() {
            let id_num = i + 1;
            let id = format!("RST{id_num}");

            security_tokens.push(soap::RequestSecurityToken {
                id,
                request_type: "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue".to_string(),
                applies_to: AppliesTo {
                    endpoint_reference: EndpointReference { address: scope },
                },
                policy_reference: policy,
            });
        }

        soap::Body {
            body: soap::BodyContent::RequestMultipleSecurityTokens(RequestMultipleSecurityTokens {
                id: "RSTS".to_string(),
                ps: "http://schemas.microsoft.com/Passport/SoapServices/PPCRL".to_string(),
                security_tokens,
            }),
        }
    } else {
        let (scope, policy) = scope_policies[0].clone();
        soap::Body {
            body: soap::BodyContent::RequestSecurityToken(soap::RequestSecurityToken {
                id: "RST0".to_string(),
                request_type: "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue".to_string(),
                applies_to: AppliesTo {
                    endpoint_reference: EndpointReference { address: scope },
                },
                policy_reference: policy,
            }),
        }
    };

    let envelope = soap::Envelope::new(header, body);
    let xml = quick_xml::se::to_string(&envelope).unwrap();
    let xml = format!("{XML_HEADER}\n{xml}");

    let mut kmgr = KeysManager::new();
    kmgr.add_key(Key::new(KeyData::Hmac(hmac_key.to_vec()), KeyUsage::Sign));

    let ctx = DsigContext::new(kmgr).with_strict_verification(false);
    let prefixes: [&str; 0] = [];
    let min_xml = bergshamra::c14n::canonicalize(
        xml.as_str(),
        bergshamra_c14n::C14nMode::Exclusive,
        None,
        &prefixes,
    )
    .unwrap();

    let signed = bergshamra::sign(&ctx, std::str::from_utf8(&min_xml).unwrap()).unwrap();

    let response = client
        .post("https://login.live.com/RST2.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(signed)
        .send()
        .await?;

    let text = response.text().await?;

    let res_envelope: soap::Envelope = quick_xml::de::from_str(&text).expect("Failed to de xml");
    let mut nonce = None;
    for token in envelope.header.security.derived_key_tokens {
        if token.id == "SignKey" {
            nonce = Some(token.nonce);
            continue;
        }
    }
    let nonce = nonce.unwrap();
    let nonce = BASE64_STANDARD.decode(nonce).unwrap();
    let key = utils::generate_shared_key(
        32,
        &secret,
        "WS-SecureConversationWS-SecureConversation",
        &nonce,
    );

    let mut kmgr = KeysManager::new();
    kmgr.add_key(Key::new(KeyData::Hmac(key.to_vec()), KeyUsage::Verify));
    let ctx = DsigContext::new(kmgr).with_strict_verification(false);
    let result = bergshamra::verify(&ctx, &text).unwrap();
    match result {
        bergshamra::VerifyResult::Invalid { reason } => {
            println!("USER {}", reason);
        }
        bergshamra::VerifyResult::Valid { .. } => {
            println!("signature valid");
        }
    }

    let (body, pp) = utils::decrypt_response(res_envelope, &secret).expect("Failed to decrypt");

    match body {
        soap::BodyContent::Fault(_) => Ok(ExchangeUserTokenOutcome::Fault(pp)),
        body => Ok(ExchangeUserTokenOutcome::Issued(body)),
    }
}
