use xodus::tokens::TokenManager;

use crate::commands::streaming;

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    path: String,
    destination: String,
    market: String,
) {
    streaming::run(
        client,
        tokens,
        "file://".to_owned() + &path,
        destination,
        false,
        None,
        Some(market),
    )
    .await;
}
