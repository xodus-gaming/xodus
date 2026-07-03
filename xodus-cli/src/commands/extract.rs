use msixvc::xvd::{XvdFile, unpack_file};
use xodus::tokens::TokenManager;

use std::collections::{HashMap, HashSet};

use crate::license::get_license;
pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    path: String,
    destination: String,
    market: String,
) {
    let xvd = XvdFile::parse_file(path.to_string())
        .await
        .expect("Failed to parse");

    let required_ciks = xvd.required_ciks();

    let mut content_keys: HashMap<uuid::Uuid, [u8; 32]> = HashMap::new();
    let mut missing_ciks: HashSet<uuid::Uuid> = HashSet::new();

    for cik_uuid in required_ciks {
        match tokens.get_cik(cik_uuid).unwrap() {
            Some(cik) => {
                content_keys.insert(cik_uuid, *cik);
            }
            None => {
                missing_ciks.insert(cik_uuid);
            }
        }
    }

    if !missing_ciks.is_empty() {
        let license = get_license(client, tokens, xvd.content_id().to_string(), market).await;
        if let Err(err) = license {
            eprintln!("{}", err);
            return;
        }

        let (key, game_splicense) = license.unwrap();
        for (uuid, content_key) in game_splicense.content_keys {
            let unpacked = content_key.unpack(&key).expect("failed to unpack");
            tokens.save_cik(uuid, unpacked).unwrap();

            if missing_ciks.remove(&uuid) {
                content_keys.insert(uuid, *unpacked);
            }
        }

        if !missing_ciks.is_empty() {
            panic!("missing CIK in game splicense: {:?}", missing_ciks)
        }
    }

    unpack_file(xvd, path.to_string(), destination.to_string(), content_keys).expect("unpack ok");
}
