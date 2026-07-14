use std::{collections::HashMap, path::Path};

use msixvc::{
    models::xvd::PAGE_SIZE,
    xvd::{SegmentFile, XvdFile},
};
use tokio::fs::OpenOptions;
use xodus::tokens::TokenManager;

use crate::{
    license::get_license,
};

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    market: Option<String>,
) {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .unwrap();

    let xvd = XvdFile::parse(&mut file).await.expect("no err");

    let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
            for (n, sfile) in &sfiles {
                if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                    println!("{}: {} {}", n, sfile.offset, sfile.length);
                }
            }
            lfiles = sfiles;
        }
    }

    let sfiles = xvd
        .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
        .await
        .expect("ok");
    for (n, sfile) in &sfiles {
        if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
            println!("{}: {} {}", n, sfile.offset, sfile.length);
        }
    }
    lfiles.extend(sfiles);

    let license = get_license(
        client,
        tokens,
        xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    todo!("Implement this")
}
