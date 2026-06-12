use crate::{device, user};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};
use xodus::{
    licensing::splicense::{parse_license, unpack_key},
    models::{live::ExchangeUserTokenOutcome, secrets::Token, soap},
};

pub async fn run(client: &reqwest::Client, content_id: String, market: String, ciks: String) {
    let dev_token = device::get_device_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        eprintln!("Invalid STS token");
        return;
    };
    let user = user::get_user().unwrap();
    let user_token = user::get_token("http://Passport.NET/STS".to_string()).unwrap();
    let Token::Legacy(legacy) = user_token else {
        eprintln!("Unspported user token");
        return;
    };

    let secret = dev_token.binary_secret.unwrap();

    let ms_device_token = xodus::api::live::exchange_device_token(
        client,
        dev_token.token.clone(),
        secret.clone(),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .unwrap();

    let user_token = xodus::api::live::exchange_user_token(
        client,
        legacy.token,
        user.username,
        dev_token.token,
        secret,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let ms_device_token: Token = ms_device_token.into();
    let Token::Compact(ms_device_token) = ms_device_token else {
        eprintln!("Unsupported token");
        return;
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            eprintln!("Failed to get exchange MS token");
            return;
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => token.into(),
        _ => unreachable!("Only responses are handled"),
    };
    let Token::Compact(user_token) = user_token else {
        eprintln!("Unsupported token");
        return;
    };

    let (_response, game_license) = xodus::licensing::content::get_license_content(
        client,
        ms_device_token,
        user_token,
        user.puid,
        content_id,
        market,
    )
    .await
    .expect("failed to get license");

    let game_splicense = parse_license(game_license.splicense_block);

    let dev_license = device::get_dev_license().unwrap();
    let device_license = parse_license(dev_license.splicense);
    let key = device_license
        .encrypted_device_key
        .unwrap()
        .derive_device_key();
    println!("{game_splicense:?}");
    tokio::fs::create_dir_all(&ciks).await.unwrap();
    for (uuid, content_key) in game_splicense.content_keys {
        let unpacked = unpack_key(&key, content_key).expect("failed to unpack");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(format!("{ciks}/{uuid}.cik"))
            .await
            .unwrap();
        let uuid_buf = uuid.to_bytes_le();
        file.write(&uuid_buf).await.unwrap();
        file.write(&unpacked).await.unwrap();
        file.flush().await.unwrap();
    }
}
