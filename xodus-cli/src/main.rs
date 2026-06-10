use std::f32::consts::E;

use clap::{Parser, Subcommand};
mod commands;
mod device;
mod user;
mod webview;
use xodus::models::live::{DAProperty, ExchangeUserTokenOutcome};
use xodus::models::soap::{self, PolicyReference};
use xodus::xal::client_params::CLIENT_WINDOWS;

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
            let clientid = "000000004424da1f".to_string();
            let token = webview::login_client(clientid.clone(), "pl-PL".to_string())
                .expect("failed to login");
            if let Some(prop) = token {
                println!("Got token");
                let device = device::get_device_token().unwrap();

                let exchanged = xodus::api::live::exchange_user_token(
                    &client,
                    prop.da_token,
                    prop.username,
                    device.cipher_value.clone(),
                    device.binary_secret.clone(),
                    Some(prop.sts_inline_flow_token),
                    clientid.clone(),
                    "scope=service::user.auth.xboxlive.com::MBI_SSL&amp;api-version=2.0"
                        .to_string(),
                    Some(PolicyReference::token_broker()),
                )
                .await
                .expect("failed to exchange");

                match exchanged {
                    ExchangeUserTokenOutcome::Fault(pp) => {
                        if let Some(pp) = pp {
                            let auth_url = pp.inline_auth_url.expect("No inline auth url");
                            let result = webview::finalize(auth_url)
                                .await
                                .expect("failed to exchange");
                            let prop = result.unwrap();
                            let exchanged = xodus::api::live::exchange_user_token(
                                &client,
                                prop.da_token,
                                prop.username,
                                device.cipher_value,
                                device.binary_secret,
                                Some(prop.sts_inline_flow_token),
                                clientid.clone(),
                                "scope=service::user.auth.xboxlive.com::MBI_SSL&amp;api-version=2.0"
                                    .to_string(),
                                Some(PolicyReference::token_broker()),
                            )
                            .await
                            .expect("failed to exchange");

                            println!("{exchanged:?}");
                        }
                    }
                    ExchangeUserTokenOutcome::Issued(da) => {
                        println!("{da:?}");
                    }
                }

                // let user_data = xodus::models::secrets::User {
                //     da_token: prop.da_token,
                //     da_session_key: prop.da_session_key,
                //     lifetime: xodus::models::soap::Timestamp {
                //         id: None,
                //         created: prop.da_start_time,
                //         expires: prop.da_expires,
                //     },
                //     username: prop.username,
                // };
                // user::save_user(user_data);
            }
        }
    }

    xodus::secrets::destroy_secrets();
}
