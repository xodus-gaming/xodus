use std::cmp::min;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use base64::prelude::*;
use bergshamra::VerifyResult::Invalid;
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};
use hmac::{Hmac, Mac};
use rsa::rand_core::{OsRng, RngCore};
use rsa::sha2::Sha256;
use url::{Url, form_urlencoded};
use zerocopy::IntoBytes;

use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::soap::{
    self, AlgorithmNode, AppliesTo, BinarySecurityToken, DerivedKeyToken, EncryptedData, EndpointReference, PolicyReference, ReferenceUri, SecurityTokenReference, SignatureReference, SignatureTransforms, SignedInfo, UsernameToken
};

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> reqwest::Result<DeviceAddResponse> {
    let data = quick_xml::se::to_string(&data).unwrap();

    let response = client
        .post(format!(
            "https://login.live.com/ppsecure/deviceaddcredential.srf"
        ))
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

pub async fn authenticate_apppwd(
    client: &reqwest::Client,
    username: String,
    password: String,
) -> reqwest::Result<soap::Envelope> {
    let mut header = soap::Header::new();
    header.security.username_token = Some(UsernameToken{
        id: "user".to_string(),
        username: username,
        password: password,
        login_option: "".to_string(),
        username_hint: "".to_string(),
    });
    let body = soap::Body {
        body: soap::BodyContent::RequestSecurityToken(soap::RequestSecurityToken {
            id: "RST0".to_string(),
            request_type: "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue".to_string(),
            applies_to: AppliesTo {
                endpoint_reference: EndpointReference {
                    address: "http://Passport.NET/tb".to_string(),
                },
            },
            policy_reference: Some(PolicyReference {
                uri: "TOKEN_BROKER".to_string(),
                val: "scope=service::www.microsoft.com::mbi_ssl&amp;uaid=FCFF621D-6BE5-4F41-9B69-68B6B2563B35&amp;clientid=%7Bf0c62012-2cef-4831-b1f7-930682874c86%7D&amp;ssoappgroup=none".to_string()
            }),
        }),
    };
    let envelope = soap::Envelope::new(header, body);
    let xml = quick_xml::se::to_string(&envelope).unwrap();
    let xml = format!("{XML_HEADER}\n{xml}");
    let response = client
        .post(format!(
            "https://login.live.com/RST2.srf"
        ))
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


pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    password: String,
) -> reqwest::Result<soap::Envelope> {
    let mut header = soap::Header::new();
    header.security.username_token = Some(UsernameToken::new(username, password));
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
        .post(format!(
            "https://login.live.com/RST2.srf"
        ))
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

// public static byte[] GenerateSharedKey(int keyLength, byte[] inKey, string keyUsage, byte[] nonce)
// {
//     // I have no idea how or why this works, just that it does

//     byte[] sharedKeyMaterial = new byte[4 + keyUsage.Length + 1 + nonce.Length + 4];
//     int offset = 0;
//     offset += 4;

//     Array.Copy(Encoding.UTF8.GetBytes(keyUsage), 0, sharedKeyMaterial, offset, keyUsage.Length);
//     offset += keyUsage.Length;

//     sharedKeyMaterial[offset] = 0x0;
//     offset++;

//     Array.Copy(nonce, 0, sharedKeyMaterial, offset, nonce.Length);
//     offset += nonce.Length;

//     var keyBitLength = keyLength * 8;

//     sharedKeyMaterial[offset] = (byte)((keyBitLength & 0xff000000) >> 24);
//     sharedKeyMaterial[offset + 1] = (byte)((keyBitLength & 0x00ff0000) >> 16);
//     sharedKeyMaterial[offset + 2] = (byte)((keyBitLength & 0x0000ff00) >> 8);
//     sharedKeyMaterial[offset + 3] = (byte)(keyBitLength & 0x000000ff);

//     offset += 4;

//     int currentKeyLength = 0;
//     int currentHashCount = 1;

//     var sharedKey = new byte[keyLength];

//     while (currentKeyLength < keyLength)
//     {
//         sharedKeyMaterial[0] = (byte)((currentHashCount & 0xff000000) >> 24);
//         sharedKeyMaterial[1] = (byte)((currentHashCount & 0x00ff0000) >> 16);
//         sharedKeyMaterial[2] = (byte)((currentHashCount & 0x0000ff00) >> 8);
//         sharedKeyMaterial[3] = (byte)(currentHashCount & 0x000000ff);

//         currentHashCount++;

//         var usedAlgo = new HMACSHA256(inKey);
//         usedAlgo.Initialize();

//         var signature = usedAlgo.ComputeHash(sharedKeyMaterial);
//         var amount = Math.Min(signature.Length, keyLength - currentKeyLength);
//         Array.Copy(signature, 0, sharedKey, currentKeyLength, amount);
//         currentKeyLength += amount;
//     }

//     return sharedKey;
// }
pub fn generate_shared_key(key_length: usize, in_key: &[u8], key_usage: &str, nonce: &[u8]) -> [u8; 32] {
    let len: usize = 4 + key_usage.len() + 1 + nonce.len() + 4;
    let mut shared_key_material: Vec<u8> = vec![];
    shared_key_material.resize(len, 0);

    let mut offset = 0;
    offset += 4;
    shared_key_material[offset..offset + key_usage.len()].copy_from_slice(key_usage.as_bytes());
    offset += key_usage.len();

    // Already zerod
    offset += 1;

    shared_key_material[offset..offset + nonce.len()].copy_from_slice(nonce);
    offset += nonce.len();

    let key_bit_length = u32::try_from(key_length * 8).unwrap();
    shared_key_material[offset..offset + 4].copy_from_slice(&key_bit_length.to_be_bytes());

    offset += 4;

    let mut current_key_length: usize = 0;
    let mut current_hash_count: u32 = 1;

    let mut shared_key = [0; 32];

    while current_key_length < key_length {
        shared_key_material[0..4].copy_from_slice(&current_hash_count.to_be_bytes());

        current_hash_count += 1;

        type HmacSha256 = Hmac<Sha256>;

        let mut hmac = HmacSha256::new_from_slice(in_key).unwrap();
        hmac.update(&shared_key_material[..offset]);
        let signature = hmac.finalize().into_bytes();
        let amount = min(signature.len(), key_length - current_key_length);
        shared_key[current_key_length..current_key_length + amount]
            .copy_from_slice(&signature.as_bytes()[0..amount]);
        current_key_length += amount;
    }

    return shared_key;
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
    header.auth_info.as_mut().map(|i| {
        i.hosting_app = hosting_app;
        i.sso_flags = "SsoRestr".to_string();
    });
    header.security.encrypted_data = Some(soap::EncryptedData::devicesoftware(token));
    let mut nonce = [0u8; 32];
    _ = OsRng.try_fill_bytes(&mut nonce);
    let secret = BASE64_STANDARD.decode(shared_secret).unwrap();

    let hmac_key = generate_shared_key(
        32,
        &secret,
        "WS-SecureConversationWS-SecureConversation",
        &nonce,
    );
    let mut nonceb64: String = "".to_string();
    BASE64_STANDARD.encode_string(nonce, &mut nonceb64);

    header.security.derived_key_token = vec![DerivedKeyToken{
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
    println!("{}", xml);

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

    println!("{}", signed);
    let response = client
        .post(format!(
            "https://login.live.com/RST2.srf"
        ))
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(signed)
        .send()
        .await?;

    let text = response.text().await?;
    println!("{}", text);

    let res_envelope: soap::Envelope = quick_xml::de::from_str(&text).expect("Failed to de xml");

    if let soap::BodyContent::EncryptedData(data) = res_envelope.body.body {
        let key_info = data.key_info.as_signature();
        let id = key_info.security_token_reference.reference.uri;
        let mut enc_nonce = None;
        let mut nonce = None;
        for token in res_envelope.header.security.derived_key_token {
            if format!("#{}", token.id) == id {
                enc_nonce = Some(token.nonce);
                continue;
            }
            if token.id == "SignKey" {
                nonce = Some(token.nonce);
                continue;
            }
        }
        let nonce = nonce.unwrap();
        let enc_nonce = enc_nonce.unwrap();
        let nonce = BASE64_STANDARD.decode(nonce).unwrap();
        let enc_nonce = BASE64_STANDARD.decode(enc_nonce).unwrap();
        let key = generate_shared_key(
            32,
            &secret,
            "WS-SecureConversationWS-SecureConversation",
            &nonce,
        );
        let enc_key = generate_shared_key(
            32,
            &secret,
            "WS-SecureConversationWS-SecureConversation",
            &enc_nonce,
        );

        let mut kmgr = KeysManager::new();
        kmgr.add_key(Key::new(KeyData::Hmac(key.to_vec()), KeyUsage::Verify));
        let ctx = DsigContext::new(kmgr).with_strict_verification(false);
        let result = bergshamra::verify(&ctx, &text).unwrap();
        match result {
            Invalid { reason } => {
                println!("{}", reason);
            }
            bergshamra::VerifyResult::Valid { .. } => {
                println!("signature valid");
            }
        }

        let value = BASE64_STANDARD
            .decode(data.cipher_data.cipher_value)
            .unwrap();
        let (iv, encrypted) = value.split_at(16);
        let iv: &[u8; 16] = iv.try_into().unwrap();

        let decryptor = Aes256CbcDec::new(&enc_key.into(), iv.into());
        let mut block = [0; 8192];

        decryptor
            .decrypt_padded_b2b::<Pkcs7>(&encrypted, &mut block)
            .expect("Failed");
        let result = std::str::from_utf8(&block).unwrap();
        let security_token_res: soap::RequestSecurityTokenResponse =
            quick_xml::de::from_str(&result).unwrap();
        return Ok(security_token_res)
    }

    match res_envelope.body.body {
        soap::BodyContent::RequestSecurityTokenResponse(res) => Ok(res),
        _ => unimplemented!("Exchange device token supports only one token variant")
    }
}


pub async fn exchange_user_token(
    client: &reqwest::Client,
    userToken: String,
    token: String,
    shared_secret: String,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> reqwest::Result<soap::RequestSecurityTokenResponse> {
    let mut header = soap::Header::new();
    header.auth_info.as_mut().map(|i| {
        i.hosting_app = hosting_app;
        i.sso_flags = "SsoRestr".to_string();
        i.license_signature_key_version = "".to_string();
        i.inline_ux = "Silent".to_string();
    });
    header.security.username_token = Some(UsernameToken{
        id: "user".to_string(),
        username: "".to_string(),
        password: "".to_string(),
        login_option: "1".to_string(),
        username_hint: "USERNAME".to_string(),
    });
    let data: EncryptedData = quick_xml::de::from_str(&userToken).unwrap();
    header.security.encrypted_data = Some(data);

    header.security.binary_security_token = vec![
        BinarySecurityToken {
            id: "DeviceDAToken".to_string(),
            value_type: "urn:liveid:device".to_owned(),
            value: quick_xml::se::to_string(&soap::EncryptedData::devicesoftware(token)).unwrap(),
        }
    ];
    let mut nonce = [0u8; 32];
    _ = OsRng.try_fill_bytes(&mut nonce);
    let secret = BASE64_STANDARD.decode(shared_secret).unwrap();

    let hmac_key = generate_shared_key(
        32,
        &secret,
        "WS-SecureConversationWS-SecureConversation",
        &nonce,
    );
    let mut nonceb64: String = "".to_string();
    BASE64_STANDARD.encode_string(nonce, &mut nonceb64);

    header.security.derived_key_token = vec![DerivedKeyToken{
        nonce: nonceb64,
        id: "SignKey".to_string(),
        algorithm: "urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED".to_string(),
        token_reference: None,
        requested_token_reference: Some(soap::RequestedTokenReference { key_identifier: soap::KeyIdentifier { value_type: "http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".to_string(), value: None }, reference: soap::ReferenceUri { uri: "#DeviceDAToken".to_string() } })
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
    println!("{}", xml);

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

    println!("{}", signed);
    let response = client
        .post(format!(
            "https://login.live.com/RST2.srf"
        ))
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(signed)
        .send()
        .await?;

    let text = response.text().await?;
    println!("{}", text);

    let res_envelope: soap::Envelope = quick_xml::de::from_str(&text).expect("Failed to de xml");

    if let soap::BodyContent::EncryptedData(data) = res_envelope.body.body {
        let key_info = data.key_info.as_signature();
        let id = key_info.security_token_reference.reference.uri;
        let mut enc_nonce = None;
        let mut nonce = None;
        for token in res_envelope.header.security.derived_key_token {
            if format!("#{}", token.id) == id {
                enc_nonce = Some(token.nonce);
                continue;
            }
            if token.id == "SignKey" {
                nonce = Some(token.nonce);
                continue;
            }
        }
        let nonce = nonce.unwrap();
        let enc_nonce = enc_nonce.unwrap();
        let nonce = BASE64_STANDARD.decode(nonce).unwrap();
        let enc_nonce = BASE64_STANDARD.decode(enc_nonce).unwrap();
        let key = generate_shared_key(
            32,
            &secret,
            "WS-SecureConversationWS-SecureConversation",
            &nonce,
        );
        let enc_key = generate_shared_key(
            32,
            &secret,
            "WS-SecureConversationWS-SecureConversation",
            &enc_nonce,
        );

        let mut kmgr = KeysManager::new();
        kmgr.add_key(Key::new(KeyData::Hmac(key.to_vec()), KeyUsage::Verify));
        let ctx = DsigContext::new(kmgr).with_strict_verification(false);
        let result = bergshamra::verify(&ctx, &text).unwrap();
        match result {
            Invalid { reason } => {
                println!("{}", reason);
            }
            bergshamra::VerifyResult::Valid { .. } => {
                println!("signature valid");
            }
        }

        let value = BASE64_STANDARD
            .decode(data.cipher_data.cipher_value)
            .unwrap();
        let (iv, encrypted) = value.split_at(16);
        let iv: &[u8; 16] = iv.try_into().unwrap();

        let decryptor = Aes256CbcDec::new(&enc_key.into(), iv.into());
        let mut block = [0; 8192];

        decryptor
            .decrypt_padded_b2b::<Pkcs7>(&encrypted, &mut block)
            .expect("Failed");
        let result = std::str::from_utf8(&block).unwrap();
        let security_token_res: soap::RequestSecurityTokenResponse =
            quick_xml::de::from_str(&result).unwrap();
        return Ok(security_token_res)
    }

    match res_envelope.body.body {
        soap::BodyContent::RequestSecurityTokenResponse(res) => Ok(res),
        _ => unimplemented!("Exchange device token supports only one token variant")
    }
}
