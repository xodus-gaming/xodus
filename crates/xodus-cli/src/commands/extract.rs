use std::io::Read;
use std::process::ExitCode;
use xodus::tokens::TokenManager;

use crate::commands::streaming;

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    path: String,
    destination: String,
    market: String,
) -> ExitCode {
    // Detect MSIXVC2 containers (ZIP archive with "PK\x03\x04" header)
    if let Ok(file) = std::fs::File::open(&path) {
        let mut magic = [0u8; 4];
        if (&file).read_exact(&mut magic).is_ok() && &magic == b"PK\x03\x04" {
            tracing::info!("Detected MSIXVC2 container, extracting with msixvc2 engine...");
            match msixvc::msixvc2::Msixvc2Archive::open(&path) {
                Ok(mut archive) => {
                    let content_id = archive.package().content_id.to_string();
                    tracing::info!("Package ContentId: {content_id}");

                    let license =
                        crate::license::get_license(client, tokens, content_id, market.clone())
                            .await;

                    if let Ok((key, game_splicense)) = license
                        && let Some((_, content_key)) =
                            game_splicense.content_keys.into_iter().next()
                        && let Ok(full_key) = content_key.unpack(&key)
                    {
                        archive.submit_keys(Some(&*full_key), None);
                    }

                    if let Err(e) = archive.extract_all(&destination) {
                        eprintln!("MSIXVC2 extraction failed: {e}");
                        return ExitCode::FAILURE;
                    }

                    println!("MSIXVC2 extraction complete: {destination}");
                    return ExitCode::SUCCESS;
                }
                Err(e) => {
                    eprintln!("Failed to parse MSIXVC2 package: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    streaming::run(
        client,
        tokens,
        "file://".to_owned() + &path,
        destination,
        false,
        None,
        Some(market),
    )
    .await
}
