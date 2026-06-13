use clap::{Parser, Subcommand};
mod commands;
mod device;
mod user;
mod license;
mod webview;
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
        #[clap(help = "Content Id of a license")]
        content_id: String,
        #[clap(help = "A path where to dump CIKs")]
        ciks: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    Extract {
        #[clap(help = "Content Id of a license")]
        content_id: String,
        path: String,
        destination: String,
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
    let args = CliArgs::parse();

    xodus::secrets::init_secrets();
    device::ensure_device_credentials(&client).await;

    match args.command {
        SubCommand::Download {
            product,
            market,
            dry_run,
        } => commands::download::run(&client, product, market, dry_run).await,
        SubCommand::License {
            content_id,
            market,
            ciks,
        } => {
            commands::license::run(
                &client,
                content_id,
                market.unwrap_or("neutral".to_string()),
                ciks,
            )
            .await;
        }
        SubCommand::Login => {
            commands::login::run(&client).await;
        }
        SubCommand::Extract {
            path,
            destination,
            content_id,
            market
        } => {
            commands::extract::run(&client, path, destination, content_id, market.unwrap_or("neutral".to_string())).await;
        }
    }

    xodus::secrets::destroy_secrets();
}
