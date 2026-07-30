use xgameui::{PlayerPicker, fetch_friends};
use xodus::{auth::do_sisu, secrets::init_secrets, tokens::TokenManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Runtime::new()?;
    let users = runtime.block_on(async {
        let client = reqwest::Client::new();
        init_secrets()?;
        let tokens = TokenManager::with_keychain_and_memory();

        let (_, resp) = do_sisu(&client, &tokens, "0000000040159362", 896928775).await?;

        let xid = resp
            .authorization_token
            .display_claims
            .as_ref()
            .map(|d| d.xui[0]["xid"].clone())
            .unwrap();

        let users = fetch_friends(
            &client,
            &resp.authorization_token.authorization_header_value(),
            &xid,
        )
        .await?;
        Ok::<_, Box<dyn std::error::Error>>(users)
    })?;

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([860.0, 560.0])
            .with_title("Player Picker"),
        ..Default::default()
    };

    eframe::run_native(
        "io.github.xodus-gaming.xodus",
        native_options,
        Box::new(|cc| Ok(Box::new(PlayerPicker::new(cc, users)))),
    )
    .expect("Faield to run native app");

    Ok(())
}
