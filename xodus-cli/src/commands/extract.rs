use xodus::xvd::utils::parse_file;
pub async fn run(path: String) {
    parse_file(path).await.expect("Failed to parse");
}
