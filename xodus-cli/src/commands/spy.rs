use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom::Start},
};

use base64::Engine;
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};
use reqwest::header;
use xodus::{
    api::{self, live::utils},
    licensing::splicense::{ClepHmacState, SPLicense},
    models::{
        devicecredential::{DeviceAddRequest, DeviceAddResponse},
        secrets::{Device, Token, TokenStore},
        soap::{self, BodyContent, EncryptedData, Envelope},
    },
    tokens::{TokenManager, device::save_device_sts_token},
};
use zerocopy::transmute;

pub(crate) async fn run(files: Vec<String>) {
    let tokens = TokenManager::with_memory();
    let mut secs: HashMap<String, String> = HashMap::new();

    let mut process = |e: &har::v1_2::Entries| {
        if e.request.url == "https://login.live.com/ppsecure/deviceaddcredential.srf" {
            let client = reqwest::Client::new();

            // println!("{}", e.response.content.text.as_ref().unwrap());
            let resp: DeviceAddResponse =
                quick_xml::de::from_str(e.response.content.text.as_ref().unwrap())
                    .expect("Failed to de xml");
            // println!("{}", resp.success);
            let req: DeviceAddRequest = quick_xml::de::from_str(
                e.request.post_data.as_ref().unwrap().text.as_ref().unwrap(),
            )
            .expect("Failed to de xml");

            // println!("{}", req.authentication.membername);

            let dev = resp;
            let device: Device = Device {
                username: req.authentication.membername.clone(),
                password: req.authentication.password.clone(),
                puid: dev.puid,
                hwid: dev.hw_device_id,
                device_id: dev.license.binding.device_id.unwrap_or_default(),
                splicense: dev.license.splicense_block,
            };

            tokens.save_device_license(&device).unwrap();
        } else if e.request.url == "https://login.live.com/RST2.srf" {
            println!("RST2");
            // println!("{}", e.request.post_data.as_ref().unwrap().text.as_ref().unwrap());
            let req: Envelope<String> = quick_xml::de::from_str(
                e.request.post_data.as_ref().unwrap().text.as_ref().unwrap(),
            )
            .expect("Failed to de xml");
            let resp_str = if let Some(enc) = &e.response.content.encoding
                && enc == "base64"
            {
                String::from_utf8(
                    base64::engine::general_purpose::STANDARD
                        .decode(e.response.content.text.as_ref().unwrap())
                        .unwrap(),
                )
                .unwrap()
            } else {
                e.response.content.text.as_ref().unwrap().to_owned()
            };
            let resp: Envelope<String> =
                quick_xml::de::from_str(&resp_str).expect("Failed to de xml");
            // println!("{:?}", req);
            // println!("{:?}", resp);

            if let Some(user) = req.header.security.username_token
                && user.id == "devicesoftware"
            {
                if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
                    // save_device_sts_token(&tokens, resp);
                    let token: Token = resp.into();
                    let Token::Legacy(token) = token else {
                        panic!("Hmm");
                    };
                    let data: EncryptedData<String> =
                        quick_xml::de::from_str(&token.token).unwrap();
                    println!("tkn={}", data.cipher_data.cipher_value);
                    secs.insert(data.cipher_data.cipher_value, token.binary_secret.unwrap());
                } else {
                    panic!("Hmm");
                }
                return;
            }

            let proof_token = if let Some(d) = req.header.security.encrypted_data {
                let Some(sec) = secs.get(&d.cipher_data.cipher_value).or(req
                    .header
                    .security
                    .binary_security_token
                    .iter()
                    .find(|p| p.value_type == "urn:liveid:device")
                    .map(|p| {
                        let data: EncryptedData<String> =
                            quick_xml::de::from_str(&p.value).unwrap();
                        secs.get(&data.cipher_data.cipher_value)
                    })
                    .unwrap_or(None))
                else {
                    println!("MISSING SECRET {}", &d.cipher_data.cipher_value);
                    return;
                };
                sec
            } else {
                todo!("???");
            };

            println!("{}", proof_token);

            let shared_secret = proof_token;

            let secret = base64::engine::general_purpose::STANDARD
                .decode(&shared_secret)
                .unwrap();
            let secret: [u8; 4096] = secret.try_into().unwrap();
            let secret: ClepHmacState = transmute!(secret);
            let secret = secret.get_hmac_state();

            let res_envelope = resp;
            let mut nonce = None;
            for token in &res_envelope.header.security.derived_key_tokens {
                if token.id == "SignKey" {
                    nonce = Some(token.nonce.clone());
                    break;
                }
            }
            let nonce = nonce.unwrap();
            let nonce = base64::engine::general_purpose::STANDARD
                .decode(nonce)
                .unwrap();
            let key = utils::generate_shared_key(
                32,
                &*secret,
                "WS-SecureConversationWS-SecureConversation",
                &nonce,
            );

            let mut kmgr = KeysManager::new();
            kmgr.add_key(Key::new(KeyData::Hmac(key.to_vec()), KeyUsage::Verify));
            let ctx = DsigContext::new(kmgr).with_strict_verification(false);
            let result = bergshamra::verify(&ctx, &resp_str).unwrap();
            match result {
                bergshamra::VerifyResult::Invalid { reason } => {
                    println!("DEVICE {}", reason);
                    println!(
                        "{}",
                        e.request.post_data.as_ref().unwrap().text.as_ref().unwrap()
                    );
                }
                bergshamra::VerifyResult::Valid { .. } => {
                    println!("signature valid");

                    let dec = utils::decrypt_response(res_envelope, &*secret);
                    if dec.is_err() {
                        println!("decryption failed");
                        return;
                    }
                    let res = match dec.unwrap() {
                        (soap::BodyContent::RequestSecurityTokenResponse(res), _) => Some(res),
                        (
                            soap::BodyContent::RequestSecurityTokenResponseCollection(
                                mut collection,
                            ),
                            _,
                        ) => {
                            let token = collection.security_tokens.remove(0);
                            Some(token)
                        }
                        (b, _) => None,
                    };
                }
            }
        }
    };

    for f in &files {
        println!("====={f}=====");

        let mut reader = File::open(f).unwrap();
        let mut bom = [0u8; 3];
        reader.read_exact(&mut bom).unwrap();
        if bom != [0xEF, 0xBB, 0xBF] {
            reader.seek(Start(0)).unwrap();
        }
        let h = har::from_reader(reader).unwrap();
        let har::Spec::V1_2(entries) = &h.log else {
            panic!();
        };
        for e in &entries.entries {
            process(e);
        }
    }
}
