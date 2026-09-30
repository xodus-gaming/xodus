use xodus_peer::proto::xodus::download::*;

pub struct Download;

#[async_trait::async_trait]
impl DownloadService for Download {
    async fn get_progress(
        &self,
        req: ProgressRequest,
    ) -> Result<ProgressResponse, Box<dyn std::error::Error + Send + Sync>> {
        todo!();
    }
}
