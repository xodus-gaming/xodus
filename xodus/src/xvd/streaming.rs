use std::pin::Pin;

use bytes::Bytes;
use futures_util::{Future, Stream, StreamExt};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncRead, AsyncSeek},
};

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

struct PendingRequest {
    stream: ByteStream,
}

type PendingChunkFetch = Pin<Box<dyn Future<Output = std::io::Result<Bytes>> + Send + 'static>>;

pub struct HttpFileAsync<'t> {
    client: &'t reqwest::Client,
    url: String,

    position: u64,
    cache: File,
    pending: Option<PendingRequest>,
    pending_chunk: Option<PendingChunkFetch>,
}

impl<'t> HttpFileAsync<'t> {
    pub async fn Open(
        client: &'t reqwest::Client,
        url: String,
        cache: String,
    ) -> Result<HttpFileAsync<'t>, Box<dyn std::error::Error>> {
        return Ok(HttpFileAsync {
            client,
            url,
            position: 0,
            pending: None,
            pending_chunk: None,
            cache: OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(cache)
                .await?,
        });
    }

    async fn start_fetch(&self) -> Result<PendingRequest, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(self.url.clone())
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(response.status(), 200);
        println!("status: {}", response.status());
        println!("headers:\n{:#?}", response.headers());
        println!(
            "content-length: {:?}",
            response.headers().get(reqwest::header::CONTENT_LENGTH)
        );
        Ok(PendingRequest {
            stream: Box::pin(response.bytes_stream()),
        })
    }

    async fn download_next_chunk(&mut self) -> Result<Bytes, Box<dyn std::error::Error>> {
        if let Some(pending) = &mut self.pending {
            if let Some(n) = pending.stream.next().await {
                let n = n?;
                return Ok(n);
            }
        }
        Ok(Bytes::new())
    }

    async fn download_next(&mut self) -> Result<Bytes, Box<dyn std::error::Error>> {
        if self.pending.is_none() {
            self.pending = Some(self.start_fetch().await?);
        }
        self.download_next_chunk().await
    }
}

impl<'t> AsyncRead for HttpFileAsync<'t> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let _ = self;
        todo!("streaming sketch: store a bytes_stream and poll it from here")
    }
}

impl<'t> AsyncSeek for HttpFileAsync<'t> {
    fn start_seek(
        self: std::pin::Pin<&mut Self>,
        _position: std::io::SeekFrom,
    ) -> std::io::Result<()> {
        let _ = self;
        todo!("streaming sketch: update logical position and reset stream as needed")
    }

    fn poll_complete(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        let _ = self;
        todo!("streaming sketch: complete pending seek")
    }
}
