use xgameui::{PlayerPicker, fetch_friends};
use xodus::{auth::do_sisu, secrets::init_secrets, tokens::TokenManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Runtime::new()?;
    let (users, access_token) = runtime.block_on(async {
        let client = reqwest::Client::new();
        init_secrets()?;
        let tokens = TokenManager::with_keychain_and_memory();

        let (_, resp) = do_sisu(&client, &tokens, "0000000040159362", 896928775).await?;

        let users = fetch_friends(
            &client,
            &resp.authorization_token.authorization_header_value(),
        )
        .await?;
        Ok::<_, Box<dyn std::error::Error>>((
            users,
            resp.authorization_token.authorization_header_value(),
        ))
    })?;

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_title("Player Picker"),
        ..Default::default()
    };

    eframe::run_native(
        "io.github.xodus-gaming.xodus",
        native_options,
        Box::new(|cc| Ok(Box::new(PlayerPicker::new(cc, users, Some(access_token))))),
    )?;

    Ok(())
}
