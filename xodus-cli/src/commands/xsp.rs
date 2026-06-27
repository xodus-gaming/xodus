use msixvc::utils::XspFile;

pub async fn run(path: String) {
    if let Err(err) = XspFile::parse_file(path).await {
        log::error!("Failed to parse xsp: {err}");
    }
}