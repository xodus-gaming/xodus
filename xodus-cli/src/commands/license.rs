use crate::license::get_license;
use tokio::{fs::OpenOptions, io::AsyncWriteExt};
use xodus::licensing::splicense::unpack_key;

pub async fn run(client: &reqwest::Client, content_id: String, market: String, ciks: String) {
    let license = get_license(client, content_id, market).await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return;
    }

    let (key, game_splicense) = license.unwrap();
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
        file.write_all(&uuid_buf).await.unwrap();
        file.write_all(&unpacked).await.unwrap();
        file.flush().await.unwrap();
    }
}
