use xodus::{licensing::splicense::{unpack_key}, xvd::utils::{parse_file, unpack_file}};

use crate::{license::get_license};
pub async fn run(client: &reqwest::Client, path: String, destination: String, content_id: String, market: String) {
    let xvd = parse_file(path.to_string()).await.expect("Failed to parse");
    let license = get_license(client, content_id, market).await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!("unexpected number of content keys {}", game_splicense.content_keys.len())
    }
    if let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() {
        let unpacked: Vec<u8> = unpack_key(&key, content_key).expect("failed to unpack");
        unpack_file(
            xvd,
            path.to_string(),
            destination.to_string(),
            unpacked.try_into().expect("match"),
        )
        .expect("unpack ok");
    }
}
