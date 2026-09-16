use std::path::Path;
use std::process::ExitCode;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use reqwest::{Client, StatusCode, header::RANGE};
use tokio::io::AsyncWriteExt;
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::package::{get_content_id, get_packages};

async fn download_file(
    client: &Client,
    url: &str,
    destination: &Path,
    expected_size: u64,
    progress: &ProgressBar,
) -> Result<(), Box<dyn std::error::Error>> {
    let existing_size = match tokio::fs::metadata(destination).await {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };

    if existing_size > expected_size {
        return Err(format!(
            "local file is larger than expected: {} > {} bytes",
            existing_size, expected_size
        )
        .into());
    }
    if existing_size == expected_size {
        progress.set_position(existing_size);
        progress.finish();
        return Ok(());
    }

    let mut request = client.get(url);
    if existing_size > 0 {
        request = request.header(RANGE, format!("bytes={existing_size}-"));
    }
    let response = request.send().await?;
    let resume = existing_size > 0 && response.status() == StatusCode::PARTIAL_CONTENT;

    if existing_size > 0 && response.status() == StatusCode::PARTIAL_CONTENT {
        let expected_prefix = format!("bytes {existing_size}-");
        let content_range = response
            .headers()
            .get("content-range")
            .and_then(|value| value.to_str().ok())
            .ok_or("resume response is missing Content-Range")?;
        if !content_range.starts_with(&expected_prefix) {
            return Err(format!(
                "resume response has invalid Content-Range: expected prefix {expected_prefix:?}, got {content_range:?}"
            )
            .into());
        }
    } else if !response.status().is_success() {
        return Err(format!("download failed with HTTP status {}", response.status()).into());
    }

    progress.set_position(if resume { existing_size } else { 0 });
    let mut output = tokio::fs::OpenOptions::new();
    output.create(true).write(true);
    if resume {
        output.append(true);
    } else {
        output.truncate(true);
    }
    let mut output = output.open(destination).await?;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        output.write_all(&chunk).await?;
        progress.inc(chunk.len() as u64);
    }
    output.flush().await?;
    drop(output);

    let actual_size = tokio::fs::metadata(destination).await?.len();
    if actual_size != expected_size {
        return Err(
            format!("download ended with {actual_size} bytes; expected {expected_size}").into(),
        );
    }
    progress.finish();
    Ok(())
}

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
        tracing::error!("Selection failed");
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

        let progress_bar = ProgressBar::new(file.file_size as u64).with_style(
            ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})").unwrap()
            .progress_chars("#>-"),
        );

        if let Err(error) = download_file(
            client,
            &url,
            Path::new(&file.file_name),
            file.file_size as u64,
            &progress_bar,
        )
        .await
        {
            progress_bar.abandon();
            eprintln!("failed to download {}: {error}", file.file_name);
            return ExitCode::FAILURE;
        }
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::download_file;

    async fn serve_once(
        body: Vec<u8>,
        status: &'static str,
        content_range: Option<String>,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let size = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..size]).to_string();
            let range = request
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("range:"))
                .map(str::to_owned);
            let mut response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            if let Some(content_range) = content_range {
                response.push_str(&format!("Content-Range: {content_range}\r\n"));
            }
            response.push_str("\r\n");
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            socket.shutdown().await.unwrap();
            range.unwrap_or_default()
        });
        (format!("http://{address}/file"), handle)
    }

    fn progress(size: u64) -> indicatif::ProgressBar {
        indicatif::ProgressBar::hidden()
            .with_style(indicatif::ProgressStyle::default_bar())
            .with_position(size)
    }

    #[tokio::test]
    async fn fresh_download_writes_and_validates_the_complete_file() {
        let data = b"complete payload".to_vec();
        let (url, server) = serve_once(data.clone(), "200 OK", None).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(0),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(path).await.unwrap(), data);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn partial_download_resumes_with_range_and_appends_only_the_suffix() {
        let data = b"complete payload".to_vec();
        let split = 8;
        let (url, server) = serve_once(
            data[split..].to_vec(),
            "206 Partial Content",
            Some(format!("bytes {split}-{}", data.len() - 1)),
        )
        .await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        tokio::fs::write(&path, &data[..split]).await.unwrap();

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(split as u64),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(path).await.unwrap(), data);
        assert_eq!(server.await.unwrap(), format!("range: bytes={split}-"));
    }

    #[tokio::test]
    async fn complete_file_is_skipped_without_a_request() {
        let data = b"already complete".to_vec();
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        tokio::fs::write(&path, &data).await.unwrap();
        let progress = progress(data.len() as u64);

        download_file(
            &reqwest::Client::new(),
            "http://127.0.0.1:1/unused",
            &path,
            data.len() as u64,
            &progress,
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(path).await.unwrap(), data);
    }

    #[tokio::test]
    async fn server_without_range_support_restarts_instead_of_appending() {
        let data = b"fresh response".to_vec();
        let (url, server) = serve_once(data.clone(), "200 OK", None).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        tokio::fs::write(&path, b"stale prefix").await.unwrap();

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(12),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(path).await.unwrap(), data);
        assert_eq!(server.await.unwrap(), "range: bytes=12-");
    }

    #[tokio::test]
    async fn invalid_content_range_is_rejected_without_modifying_the_partial_file() {
        let data = b"suffix".to_vec();
        let (url, server) = serve_once(
            data,
            "206 Partial Content",
            Some("bytes 0-5/12".to_string()),
        )
        .await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        let original = b"partial".to_vec();
        tokio::fs::write(&path, &original).await.unwrap();

        let error = download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            12,
            &progress(original.len() as u64),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Content-Range"));
        assert_eq!(tokio::fs::read(path).await.unwrap(), original);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn size_mismatch_is_reported_after_an_incomplete_response() {
        let (url, server) = serve_once(b"short".to_vec(), "200 OK", None).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");

        let error = download_file(&reqwest::Client::new(), &url, &path, 10, &progress(0))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("expected 10"));
        assert_eq!(tokio::fs::read(path).await.unwrap(), b"short");
        server.await.unwrap();
    }
}
