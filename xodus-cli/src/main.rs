use clap::{Parser, Subcommand};
mod commands;
mod device;
mod user;
mod webview;

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
        .user_agent("Xodus/1.0.0")
        .connection_verbose(true)
        .build()
        .unwrap();
    let args = CliArgs::parse();

    xodus::secrets::init_secrets();
    device::ensure_device_credentials(&client).await;

    match args.command {
        SubCommand::Download {
            product,
            market,
            dry_run,
        } => commands::download::run(&client, product, market, dry_run).await,
        SubCommand::License { content_id, market } => {
            commands::license::run(&client, content_id, market.unwrap_or("neutral".to_string()))
                .await;
        }
        SubCommand::Login => {
            commands::login::run(&client).await;
        }
    }

    xodus::secrets::destroy_secrets();
}
