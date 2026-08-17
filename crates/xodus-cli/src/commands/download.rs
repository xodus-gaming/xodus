use std::io::SeekFrom;
use std::process::ExitCode;
use std::time::Duration;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use reqwest::header::RANGE;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

/// Consecutive attempts that move no bytes before a download is called off.
const MAX_DOWNLOAD_ATTEMPTS: u32 = 10;

use crate::package::{get_content_id, get_packages};

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    market: Option<String>,
    dry_run: bool,
) -> ExitCode {
    let content_id_task = get_content_id(client, product, market).await;
    let Ok(content_id) = content_id_task else {
        let Err(err) = content_id_task else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };

    let package_result = get_packages(client, tokens, content_id.clone()).await;
    let Ok(package) = package_result else {
        let Err(err) = package_result else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
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
        return ExitCode::FAILURE;
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

        let total = file.file_size as u64;
        let progress_bar = ProgressBar::new(total).with_style(
            ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})").unwrap()
            .progress_chars("#>-")
        );

        // Packages run to tens of gigabytes and the CDN drops long-lived streams,
        // so a dropped connection has to resume rather than start over - which is
        // also why an already partial file on disk is picked up instead of
        // truncated. The CDN advertises Accept-Ranges: bytes.
        let mut downloaded = match tokio::fs::metadata(&file.file_name).await {
            Ok(meta) if meta.len() <= total => meta.len(),
            _ => 0,
        };

        let mut handle = match tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(downloaded == 0)
            .open(&file.file_name)
            .await
        {
            Ok(handle) => handle,
            Err(err) => {
                eprintln!("Failed to open {}: {err}", file.file_name);
                return ExitCode::FAILURE;
            }
        };

        if downloaded > 0 {
            if let Err(err) = handle.seek(SeekFrom::Start(downloaded)).await {
                eprintln!("Failed to resume {}: {err}", file.file_name);
                return ExitCode::FAILURE;
            }
            println!("Resuming {} at {downloaded} bytes", file.file_name);
        }
        progress_bar.set_position(downloaded);

        let mut attempts = 0;
        while downloaded < total {
            let mut request = client.get(&url);
            if downloaded > 0 {
                request = request.header(RANGE, format!("bytes={downloaded}-"));
            }

            match request.send().await {
                Ok(res) if res.status().is_success() => {
                    // A server that ignores the range and replays the whole body
                    // would corrupt the file, so only append when it agreed to it.
                    if downloaded > 0 && res.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                        eprintln!("Server ignored the resume request, starting over");
                        if handle.seek(SeekFrom::Start(0)).await.is_err() {
                            eprintln!("Failed to rewind {}", file.file_name);
                            return ExitCode::FAILURE;
                        }
                        downloaded = 0;
                        progress_bar.set_position(0);
                    }

                    let mut stream = res.bytes_stream();
                    let resumed_at = downloaded;
                    while let Some(chunk) = stream.next().await {
                        let chk = match chunk {
                            Ok(chk) => chk,
                            Err(err) => {
                                progress_bar.println(format!("Stream interrupted: {err}"));
                                break;
                            }
                        };
                        if let Err(err) = handle.write_all(&chk).await {
                            eprintln!("Failed to write to {}: {err}", file.file_name);
                            return ExitCode::FAILURE;
                        }
                        downloaded += chk.len() as u64;
                        progress_bar.set_position(downloaded);
                    }
                    // Only a retry that gained no ground counts against the budget,
                    // otherwise a long download on a flaky link exhausts it.
                    attempts = if downloaded > resumed_at { 0 } else { attempts + 1 };
                }
                Ok(res) => {
                    progress_bar.println(format!("Download returned {}", res.status()));
                    attempts += 1;
                }
                Err(err) => {
                    progress_bar.println(format!("Request failed: {err}"));
                    attempts += 1;
                }
            }

            if downloaded >= total {
                break;
            }

            if attempts > MAX_DOWNLOAD_ATTEMPTS {
                progress_bar.abandon();
                eprintln!(
                    "Giving up on {} after {MAX_DOWNLOAD_ATTEMPTS} attempts with no progress ({downloaded}/{total} bytes). Re-run to resume.",
                    file.file_name
                );
                return ExitCode::FAILURE;
            }

            if let Err(err) = handle.flush().await {
                eprintln!("Failed to flush {}: {err}", file.file_name);
                return ExitCode::FAILURE;
            }
            tokio::time::sleep(Duration::from_secs(2 * attempts.min(5) as u64)).await;
        }

        if let Err(err) = handle.flush().await {
            eprintln!("Failed to flush {}: {err}", file.file_name);
            return ExitCode::FAILURE;
        }
        progress_bar.finish();
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}
