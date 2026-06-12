use futures_util::StreamExt;
use inquire::{MultiSelect, validator::Validation};
use tokio::io::AsyncWriteExt;
use xodus::{
    XBOX_LIVE_PACKAGES_PC,
    api::displaycatalog::find_products_by_id,
    models::{
        packagespc::{PackageFile, PackageResponse},
        secrets::Token,
    },
};

use crate::{device, user};

pub async fn run(client: &reqwest::Client, product: String, market: Option<String>, dry_run: bool) {
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

    let product_details = displaycatalog.product;

    let mut found_package = None;
    'o: for availability in &product_details.display_sku_availabilities {
        for package in &availability.sku.properties.packages {
            if package
                .platform_dependencies
                .iter()
                .any(|dep| dep.platform_name == "Windows.Desktop")
            {
                found_package = Some(package);
                break 'o;
            }
        }
    }

    let Some(package) = found_package else {
        log::error!(
            "Windows.Desktop package not found, if you believe this is an error, please report it"
        );
        return;
    };

    let Some(content_id) = &package.content_id else {
        log::error!("ContentId not found, if you believe this is an error, please report it");
        return;
    };

    let dev_token = device::get_device_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        eprintln!("Invalid STS token");
        return;
    };
    let user_token = user::get_token("http://Passport.NET/STS".to_string()).unwrap();
    let Token::Legacy(legacy) = user_token else {
        eprintln!("Unspported user token");
        return;
    };

    let xsts_token =
        xodus::api::xbox::run(client, dev_token, legacy, "http://update.xboxlive.com").await;

    let response = client
        .get(format!(
            "{XBOX_LIVE_PACKAGES_PC}/GetBasePackage/{content_id}"
        ))
        .header("x-xbl-contract-version", "3")
        .header(
            "Authorization",
            xodus::api::xbox::get_xsts_auth_header(xsts_token),
        )
        .send()
        .await
        .unwrap();

    let res: PackageResponse = response.json().await.expect("Failed to get data");

    let PackageResponse::Found(package) = res else {
        log::error!("Package was not found, is it owned by the user?");
        return;
    };

    let Ok(files) = MultiSelect::new("Select files to download", package.package_files)
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
        let file_size = file.file_size as f64;
        let total_mib = file_size / 1024_f64 / 1024_f64;
        let mut downloaded_size = 0_f64;
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
            downloaded_size += chk.len() as f64;
            file.write_all(&chk).await.expect("Failed to write to file");
            let percent = downloaded_size / file_size * 100_f64;
            let downloaded_mib = downloaded_size / 1024_f64 / 1024_f64;
            print!("{percent:02.02}% - {downloaded_mib:05.0}MiB/{total_mib:05.0}MiB\r")
        }
        println!();
    }
}
