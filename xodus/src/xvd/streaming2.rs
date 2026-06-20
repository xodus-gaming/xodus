use std::cmp::min;
use std::future::Future;
use std::io::{Error, ErrorKind, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

const DEFAULT_READ_AHEAD_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_SMALL_FORWARD_SKIP_BYTES: u64 = 64 * 1024;

type PendingRangeFetch =
    Pin<Box<dyn Future<Output = std::io::Result<RangeBuffer>> + Send + 'static>>;

#[derive(Debug, Clone)]
struct RangeBuffer {
    start: u64,
    data: Vec<u8>,
}

impl RangeBuffer {
    fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }

    fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset < self.end()
    }
}

#[derive(Debug, Clone)]
pub struct HttpFileConfig {
    pub read_ahead_bytes: u64,
    pub small_forward_skip_bytes: u64,
}

impl Default for HttpFileConfig {
    fn default() -> Self {
        Self {
            read_ahead_bytes: DEFAULT_READ_AHEAD_BYTES,
            small_forward_skip_bytes: DEFAULT_SMALL_FORWARD_SKIP_BYTES,
        }
    }
}

pub struct HttpFileAsync {
    client: reqwest::Client,
    url: String,
    len: u64,
    pos: u64,
    pending_seek: Option<u64>,
    config: HttpFileConfig,
    buffer: Option<RangeBuffer>,
    pending_fetch: Option<PendingRangeFetch>,
}

impl HttpFileAsync {
    pub async fn open(
        client: reqwest::Client,
        url: impl Into<String>,
    ) -> std::io::Result<HttpFileAsync> {
        Self::open_with_config(client, url, HttpFileConfig::default()).await
    }

    pub async fn open_with_config(
        client: reqwest::Client,
        url: impl Into<String>,
        config: HttpFileConfig,
    ) -> std::io::Result<HttpFileAsync> {
        let url = url.into();
        let len = probe_len(&client, &url).await?;

        Ok(HttpFileAsync {
            client,
            url,
            len,
            pos: 0,
            pending_seek: None,
            config,
            buffer: None,
            pending_fetch: None,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn buffer_copy_into(&mut self, dst: &mut ReadBuf<'_>) -> usize {
        let Some(buffer) = &self.buffer else {
            return 0;
        };
        if !buffer.contains(self.pos) {
            return 0;
        }

        let start = (self.pos - buffer.start) as usize;
        let available = &buffer.data[start..];
        let to_copy = min(available.len(), dst.remaining());
        dst.put_slice(&available[..to_copy]);
        self.pos += to_copy as u64;
        to_copy
    }

    fn should_keep_buffer_for_seek(&self, next_pos: u64) -> bool {
        let Some(buffer) = &self.buffer else {
            return false;
        };

        if buffer.contains(next_pos) {
            return true;
        }

        next_pos > self.pos
            && next_pos.saturating_sub(self.pos) <= self.config.small_forward_skip_bytes
            && next_pos >= buffer.start
            && next_pos <= buffer.end()
    }

    fn begin_fetch(&mut self) {
        if self.pending_fetch.is_some() || self.pos >= self.len {
            return;
        }

        let start = self.pos;
        let end = min(
            self.len,
            start.saturating_add(self.config.read_ahead_bytes),
        );
        let client = self.client.clone();
        let url = self.url.clone();

        self.pending_fetch = Some(Box::pin(async move {
            fetch_range(client, url, start, end).await
        }));
    }
}

impl AsyncRead for HttpFileAsync {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if dst.remaining() == 0 || self.pos >= self.len {
            return Poll::Ready(Ok(()));
        }

        if self.buffer_copy_into(dst) > 0 {
            return Poll::Ready(Ok(()));
        }

        if self.pending_fetch.is_none() {
            self.begin_fetch();
        }

        let Some(fetch) = self.pending_fetch.as_mut() else {
            return Poll::Ready(Ok(()));
        };

        match fetch.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_fetch = None;
                let buffer = result?;

                if buffer.data.is_empty() {
                    return Poll::Ready(Ok(()));
                }

                self.buffer = Some(buffer);
                let copied = self.buffer_copy_into(dst);
                if copied == 0 {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "range fetch did not cover requested offset",
                    )));
                }

                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncSeek for HttpFileAsync {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        let base = match position {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.pos.checked_add(delta as u64)
                } else {
                    self.pos.checked_sub(delta.unsigned_abs())
                }
            }
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.len.checked_add(delta as u64)
                } else {
                    self.len.checked_sub(delta.unsigned_abs())
                }
            }
        }
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid seek"))?;

        self.pending_seek = Some(base);
        Ok(())
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        let next_pos = self.pending_seek.take().unwrap_or(self.pos);
        if next_pos > self.len {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past remote end",
            )));
        }

        if !self.should_keep_buffer_for_seek(next_pos) {
            self.buffer = None;
            self.pending_fetch = None;
        }

        self.pos = next_pos;
        Poll::Ready(Ok(self.pos))
    }
}

async fn probe_len(client: &reqwest::Client, url: &str) -> std::io::Result<u64> {
    let head = client.head(url).send().await.map_err(http_err)?;
    if let Some(content_length) = head.headers().get(CONTENT_LENGTH) {
        let content_length = content_length
            .to_str()
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
            .parse::<u64>()
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        if content_length > 0 {
            return Ok(content_length);
        }
    }

    let response = client
        .get(url)
        .header(RANGE, "bytes=0-0")
        .send()
        .await
        .map_err(http_err)?;

    parse_total_len_from_content_range(&response)
}

async fn fetch_range(
    client: reqwest::Client,
    url: String,
    start: u64,
    end: u64,
) -> std::io::Result<RangeBuffer> {
    if end <= start {
        return Ok(RangeBuffer {
            start,
            data: Vec::new(),
        });
    }

    let response = client
        .get(url)
        .header(RANGE, format!("bytes={start}-{}", end - 1))
        .send()
        .await
        .map_err(http_err)?
        .error_for_status()
        .map_err(http_err)?;

    let data = response.bytes().await.map_err(http_err)?.to_vec();
    Ok(RangeBuffer { start, data })
}

fn parse_total_len_from_content_range(response: &reqwest::Response) -> std::io::Result<u64> {
    let value = response
        .headers()
        .get(CONTENT_RANGE)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Content-Range"))?;
    let value = value
        .to_str()
        .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    let (_, total) = value
        .rsplit_once('/')
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid Content-Range"))?;
    total
        .parse::<u64>()
        .map_err(|err| Error::new(ErrorKind::InvalidData, err))
}

fn http_err(err: reqwest::Error) -> std::io::Error {
    Error::other(err)
}
