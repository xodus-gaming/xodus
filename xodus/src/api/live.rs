use std::cmp::min;
use std::io::Write;

use base64::Engine;
use bergshamra::VerifyResult::Invalid;
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};
use hmac::{Hmac, Mac};
use rsa::rand_core::{OsRng, RngCore};
use rsa::sha2::Sha256;
use zerocopy::IntoBytes;

use crate::licensing::splicense::derive_device_key;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::soap::{self, AlgorithmNode, AppliesTo, DerivedKeyToken, EndpointReference, ReferenceUri, SecurityTokenReference, SignatureReference, SignatureTransforms, SignedInfo, UsernameToken};

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

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
pub fn generateSharedKey(keyLength: usize, inKey: &[u8], keyUsage: String, nonce : &[u8]) -> Vec<u8> {
    let len : usize = 4 + keyUsage.len() + 1 + nonce.len() + 4;
    let mut sharedKeyMaterial : Vec<u8> = vec![];
    sharedKeyMaterial.resize(len, 0);

    let mut offset = 0;
    offset += 4;
    sharedKeyMaterial[offset..offset+keyUsage.len()].copy_from_slice(keyUsage.as_bytes());
    offset+=keyUsage.len();

    // Already zerod
    offset+=1;

    sharedKeyMaterial[offset..offset+nonce.len()].copy_from_slice(nonce);
    offset+=nonce.len();

    let keyBitLength = u32::try_from(keyLength * 8).unwrap();
    sharedKeyMaterial[offset..offset + 4].copy_from_slice(&keyBitLength.to_be_bytes());

    offset += 4;

    let mut currentKeyLength: usize = 0;
    let mut currentHashCount: u32 = 1;
    
    let mut sharedKey : Vec<u8> = vec![];
    sharedKey.resize(keyLength as usize, 0);

    while currentKeyLength < keyLength {
        sharedKeyMaterial[0..4].copy_from_slice(&currentHashCount.to_be_bytes());

        currentHashCount += 1;

        type HmacSha256 = Hmac<Sha256>;

        let mut hmac = HmacSha256::new_from_slice(inKey).unwrap();
        hmac.update(&sharedKeyMaterial[..offset]);
        let signature = hmac.finalize().into_bytes();
        let amount = min(signature.len(), keyLength - currentKeyLength);
        sharedKey[currentKeyLength..currentKeyLength + amount].copy_from_slice(&signature.as_bytes()[0..amount]);
        currentKeyLength += amount;
    }

    return sharedKey;
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    token: String,
    sharedSecret: String,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>
) -> reqwest::Result<soap::Envelope> {
    let mut header = soap::Header::new();
    header
        .auth_info
        .as_mut()
        .map(|i| i.hosting_app = hosting_app);
    header
        .auth_info
        .as_mut()
        .map(|i| i.sso_flags = "SsoRestr".to_string());
    header.security.encrypted_data = Some(soap::EncryptedData::devicesoftware(token));
    let mut nonce = [0u8; 32];
    OsRng.try_fill_bytes(&mut nonce);
    let secret = base64::engine::general_purpose::STANDARD
    .decode(sharedSecret)
    .unwrap();

    let hmacKey = generateSharedKey(32, secret.as_bytes(), "WS-SecureConversationWS-SecureConversation".to_string(), &nonce);
    let mut nonceb64 : String = "".to_string();
    base64::engine::general_purpose::STANDARD.encode_string(nonce, &mut nonceb64);
    let mut secretb64: String = String::new();
    base64::engine::general_purpose::STANDARD.encode_string(&secret, &mut secretb64);
    let mut hmac_key_b64: String = String::new();
    base64::engine::general_purpose::STANDARD.encode_string(&hmacKey, &mut hmac_key_b64);
    println!(
        "exchange_device_token: secret_b64={secretb64} nonce_b64={nonceb64} shared_key_b64={hmac_key_b64}"
    );

    header.security.derived_key_token = Some(DerivedKeyToken{
        nonce: nonceb64,
        id: "SignKey".to_string(),
        algorithm: "urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED".to_string(),
        requested_token_reference: soap::RequestedTokenReference { key_identifier: soap::KeyIdentifier { value_type: "http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".to_string(), value: None }, reference: soap::ReferenceUri { uri: "".to_string() } }
    });
    header.security.signature = Some(soap::Signature {
        xmlns: "http://www.w3.org/2000/09/xmldsig#".to_string(),
        signed_info: SignedInfo {
            canonicalization_method: AlgorithmNode{
                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string()
            },
            reference: vec![
                SignatureReference{
                    uri: "#RST0".to_string(),
                    digest_method: AlgorithmNode { algorithm:  "http://www.w3.org/2001/04/xmlenc#sha256".to_string() },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![
                            AlgorithmNode{
                                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                            }
                        ]
                    }
                },
                SignatureReference{
                    uri: "#Timestamp".to_string(),
                    digest_method: AlgorithmNode { algorithm:  "http://www.w3.org/2001/04/xmlenc#sha256".to_string() },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![
                            AlgorithmNode{
                                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                            }
                        ]
                    }
                },
                SignatureReference{
                    uri: "#PPAuthInfo".to_string(),
                    digest_method: AlgorithmNode { algorithm:  "http://www.w3.org/2001/04/xmlenc#sha256".to_string() },
                    digest_value: "".to_string(),
                    transforms: SignatureTransforms {
                        transform: vec![
                            AlgorithmNode{
                                algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
                            }
                        ]
                    }
                }
            ],
            signature_method: AlgorithmNode{
                algorithm: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256".to_string(),
            }
        },
        signature_value: "".to_string(),
        key_info: Some(soap::SignatureKeyInfo { security_token_reference: SecurityTokenReference { reference: ReferenceUri{ uri: "#SignKey".to_string() } } }) });
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
    kmgr.add_key(Key::new(
        KeyData::Hmac(hmacKey),
        KeyUsage::Any,
    ));

    let ctx = DsigContext::new(kmgr).with_debug(true).with_strict_verification(false);
    let prefixes: [&str; 0] = [];
    let minXml =bergshamra::c14n::canonicalize(xml.as_str(), bergshamra_c14n::C14nMode::Exclusive, None, &prefixes).unwrap();
    
    let signed = bergshamra::sign(
        &ctx,
        std::str::from_utf8(&minXml).unwrap(),
    )
    .unwrap();

    // println!("{}", signed);
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

        let result = bergshamra::verify(&ctx, &text).unwrap();
        match result {
            Invalid { reason } => {
                print!("{}", reason);
            }
            bergshamra::VerifyResult::Valid { .. } => {
                println!("signature valid");
            }
        }


    let res_envelope: soap::Envelope = quick_xml::de::from_str(&text).expect("Failed to de xml");

    Ok(res_envelope)
}
