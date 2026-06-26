use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{MultiSelect, validator::Validation};
use tokio::io::AsyncWriteExt;
use xodus::{
    XBOX_LIVE_PACKAGES_PC,
    api::displaycatalog::find_products_by_id,
    models::{
        packagespc::{PackageFile, PackageResponse},
        secrets::Token,
    },
    tokens::TokenManager,
};

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    market: Option<String>,
    dry_run: bool,
) {
    let displaycatalog = find_products_by_id(
        client,
        product,
        market.unwrap_or("neutral".to_owned()),
        vec!["en".to_string(), "neutral".to_string()],
    )
    .await;

    let displaycatalog = match displaycatalog {
        Ok(dc) => dc,
        Err(err) => {
            log::error!("Failed to load displaycatalog {err:?}");
            return;
        }
    };

    let package_result = get_packages(client, tokens, content_id.clone()).await;
    let Ok(package) = package_result else {
        let Err(err) = package_result else {
            eprintln!("Unknown Error");
            return;
        };
        eprintln!("{}", err.to_string());
        return;
    };

    let Ok(files) = MultiSelect::new("Select files to download", package.package_files)
        .with_page_size(30)
        .with_validator(|input: &[inquire::list_option::ListOption<&PackageFile>]| {
            if !input.is_empty() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "At least one item has to be selected".into(),
                ))
            }
        })
        .prompt()
    else {
        log::error!("Selection failed");
        return;
    };
    println!();
    for file in files {
        let url = format!(
            "{}{}",
            file.cdn_root_paths.first().unwrap(),
            file.relative_url
        );
        if dry_run {
            println!("{}", url);
            continue;
        }

        let progress_bar = ProgressBar::new(file.file_size as u64).with_style(
            ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})").unwrap()
            .progress_chars("#>-")
        );

        let res = client
            .get(url)
            .send()
            .await
            .expect("Failed to request the download");
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file.file_name)
            .await
            .unwrap();
        let mut stream = res.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chk = chunk.expect("Failed to stream file");
            file.write_all(&chk).await.expect("Failed to write to file");
            progress_bar.inc(chk.len() as u64);
        }

        progress_bar.finish();
    }

    println!("ContentID: {content_id}");
}
