use crate::license::get_license;
use tokio::{fs::OpenOptions, io::AsyncWriteExt};
use xodus::tokens::TokenManager;

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
    ciks: String,
) {
    let license = get_license(client, tokens, content_id, market).await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return;
    }

    let (key, game_splicense) = license.unwrap();
    tokio::fs::create_dir_all(&ciks).await.unwrap();
    for (uuid, content_key) in game_splicense.content_keys {
        let unpacked = content_key.unpack(&key).expect("failed to unpack");
        tokens.save_cik(uuid, unpacked).unwrap();
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(format!("{ciks}/{uuid}.cik"))
            .await
            .unwrap();
        let uuid_buf = uuid.to_bytes_le();
        file.write_all(&uuid_buf).await.unwrap();
        file.write_all(&*unpacked).await.unwrap();
        file.flush().await.unwrap();
    }
}
