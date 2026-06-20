use tokio::io::{AsyncRead, AsyncSeek};

pub struct HttpFileAsync<'t> {
    client: &'t reqwest::Client,
    url : String,
}

impl<'t> HttpFileAsync<'t> {
    pub fn Open(client: &'t reqwest::Client, url : String) -> HttpFileAsync<'t> {
        return HttpFileAsync { client, url };
    }
}

impl<'t> AsyncRead for HttpFileAsync<'t> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }
}

impl<'t> AsyncSeek for HttpFileAsync<'t> {
    fn start_seek(self: std::pin::Pin<&mut Self>, position: std::io::SeekFrom) -> std::io::Result<()> {
        todo!()
    }

    fn poll_complete(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<u64>> {
        todo!()
    }
}