use msixvc::xvd::{XvdFile, unpack_file};
use xodus::tokens::TokenManager;

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
    let license = get_license(client, tokens, xvd.content_id().to_string(), market).await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        )
    }
    if let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() {
        let unpacked = content_key.unpack(&key).expect("failed to unpack");
        unpack_file(xvd, path.to_string(), destination.to_string(), *unpacked).expect("unpack ok");
    }
}
