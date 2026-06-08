use clap::{Parser, Subcommand};
mod commands;
mod device;
mod user;
mod webview;
use xodus::models::live::DAProperty;
use xodus::xal::client_params::CLIENT_WINDOWS;

use crate::webview::WebviewCallbackHandler;

#[derive(Subcommand)]
enum SubCommand {
    Download {
        product: String,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    License {
        content_id: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    Login,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[command(subcommand)]
    command: SubCommand,
}

#[tokio::main]
async fn main() {
    env_logger::init_from_env("XODUS_LOG");
    let client = reqwest::ClientBuilder::new()
        .user_agent(CLIENT_WINDOWS().user_agent)
        .connection_verbose(true)
        .build()
        .unwrap();

    xodus::secrets::init_secrets();
    device::ensure_device_credentials(&client).await;

    let args = CliArgs::parse();

    match args.command {
        SubCommand::Download {
            product,
            market,
            dry_run,
        } => (), //commands::download::run(&client, &ts, product, market, dry_run).await,
        SubCommand::License { content_id, market } => {
            commands::license::run(&client).await;
        }
        SubCommand::Login => {
            let webview = WebviewCallbackHandler {};
            let token = webview.call().await.expect("failed to login");
            if let Some(da_token) = token {
                let prop: DAProperty = serde_json::from_str(&da_token).expect("Invalid structure");
                let user_data = xodus::models::secrets::User {
                    da_token: prop.da_token,
                    da_session_key: prop.da_session_key,
                    lifetime: xodus::models::soap::Timestamp {
                        id: None,
                        created: prop.da_start_time,
                        expires: prop.da_expires,
                    },
                    username: prop.username,
                    first_name: prop.first_name,
                    last_name: prop.last_name,
                    cid: prop.cid,
                    puid: prop.puid,
                };
                user::save_user(user_data);
            }
        }
    }

    xodus::secrets::destroy_secrets();
}
