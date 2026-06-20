use xodus::xvd::{streaming2::HttpFileAsync, utils::{XvdFile, unpack_file}};

use crate::license::get_license;
pub async fn run(client: &reqwest::Client, path: String, destination: String, market: String) {
    let xvd = XvdFile::parse_file(path.to_string())
        .await
        .expect("Failed to parse");
    let license = get_license(client, xvd.content_id().to_string(), market).await;
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
        unpack_file(xvd, path.to_string(), destination.to_string(), unpacked).expect("unpack ok");
    }
}

#[tokio::test]
async fn test_it() {
    let client = reqwest::Client::new();
    let mut file =  HttpFileAsync::open(client, "http://assets1.xboxlive.com/12/480484ea-7b1c-4443-b152-411e07e1329d/7792d9ce-355a-493c-afbd-768f4a77c3b0/1.26.3005.0.48bff00d-cff7-4432-8d1e-662d92be1b14/Microsoft.MinecraftUWP_1.26.3005.0_x64__8wekyb3d8bbwe.msixvc").await.expect("no err");
    let xvd = XvdFile::parse(&mut file).await.expect("no err");
}