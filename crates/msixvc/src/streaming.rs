use std::future::Future;
use std::io::{Error, ErrorKind, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

const UPSTREAM_READ_CHUNK_SIZE: usize = 64 * 1024;

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;
type PendingHttpOpen = Pin<Box<dyn Future<Output = std::io::Result<OpenedHttpStream>> + Send>>;

struct ActiveHttpStream {
    next_offset: u64,
    end_offset: u64,
    stream: ByteStream,
}

struct OpenedHttpStream {
    start: u64,
    len: u64,
    stream: ByteStream,
}

pub struct HttpRead<'t> {
    client: reqwest::Client,
    url: String,
    len: u64,
    pos: u64,
    pending_open: Option<PendingHttpOpen>,
    active: Option<ActiveHttpStream>,
    pending_chunk: Option<Bytes>,
    pending_chunk_offset: usize,
    progress: Option<Box<dyn FnMut(u64, u64) + Send + 't>>,
}

impl<'t> HttpRead<'t> {
    pub async fn open<Progress>(
        client: reqwest::Client,
        url: impl Into<String>,
        progress: Option<Progress>,
    ) -> std::io::Result<Self>
    where
        Progress: FnMut(u64, u64) + Send + 't,
    {
        Self::open_at(client, url, 0, progress).await
    }

    /// Open the same remote file, but starting at `start`.
    ///
    /// Used to continue an interrupted download: a Range request returns the
    /// total length in Content-Range, so `len` still describes the whole file
    /// and only the bytes after `start` come down the wire.
    pub async fn open_at<Progress>(
        client: reqwest::Client,
        url: impl Into<String>,
        start: u64,
        progress: Option<Progress>,
    ) -> std::io::Result<Self>
    where
        Progress: FnMut(u64, u64) + Send + 't,
    {
        let url = url.into();
        let initial =
            open_http_stream(client.clone(), url.clone(), (start > 0).then_some(start)).await?;

        Ok(Self {
            client,
            url,
            len: initial.len,
            pos: start,
            pending_open: None,
            active: Some(ActiveHttpStream {
                next_offset: initial.start,
                end_offset: initial.len,
                stream: initial.stream,
            }),
            pending_chunk: None,
            pending_chunk_offset: 0,
            progress: progress.map(|v| Box::new(v) as Box<dyn FnMut(u64, u64) + Send + 't>),
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn begin_open_stream(&mut self, start: u64) {
        let client = self.client.clone();
        let url = self.url.clone();
        let range_start = if start == 0 { None } else { Some(start) };
        self.pending_open = Some(Box::pin(async move {
            open_http_stream(client, url, range_start).await
        }));
    }

    fn poll_open_if_needed(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.active.is_none() && self.pending_open.is_none() {
            let pos = self.pos;
            self.begin_open_stream(pos);
        }

        let Some(fut) = self.pending_open.as_mut() else {
            return Poll::Ready(Ok(()));
        };

        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_open = None;
                let opened = result?;
                self.len = opened.len;
                self.active = Some(ActiveHttpStream {
                    next_offset: opened.start,
                    end_offset: opened.len,
                    stream: opened.stream,
                });
                Poll::Ready(Ok(()))
            }
        }
    }

    fn copy_from_pending_chunk(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        let Some(chunk) = self.pending_chunk.as_ref() else {
            return 0;
        };

        let available = &chunk[self.pending_chunk_offset..];
        if available.is_empty() || buf.remaining() == 0 {
            return 0;
        }

        let to_copy = available.len().min(buf.remaining());
        buf.put_slice(&available[..to_copy]);
        self.pending_chunk_offset += to_copy;
        self.pos += to_copy as u64;

        if let Some(progress) = self.progress.as_mut() {
            progress(self.pos, self.len);
        }

        if self.pending_chunk_offset >= chunk.len() {
            self.pending_chunk = None;
            self.pending_chunk_offset = 0;
        }

        to_copy
    }
}

impl<'t> AsyncRead for HttpRead<'t> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 || self.pos >= self.len {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.copy_from_pending_chunk(buf) > 0 {
                return Poll::Ready(Ok(()));
            }

            match self.as_mut().poll_open_if_needed(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }

            let Some(active) = self.active.as_mut() else {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "missing active http stream",
                )));
            };

            match active.stream.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    active.next_offset += chunk.len() as u64;
                    if active.next_offset > active.end_offset {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::InvalidData,
                            "received more bytes than expected from http stream",
                        )));
                    }
                    self.pending_chunk = Some(chunk);
                    self.pending_chunk_offset = 0;
                }
                Poll::Ready(Some(Err(_err))) => {
                    self.active = None;
                    continue;
                }
                Poll::Ready(None) => {
                    self.active = None;
                    if self.pos >= self.len {
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CacheReadState {
    Idle,
    Seeking { offset: u64 },
    Reading { started_len: usize },
}

#[derive(Clone, Copy, Debug)]
enum CacheWriteState {
    Idle,
    Seeking { offset: u64 },
    Writing,
}

pub struct PrefixCacheFile<R> {
    upstream: R,
    len: u64,
    pos: u64,
    cache_reader: File,
    cache_writer: File,
    cached_len: u64,
    pending_seek: Option<u64>,
    pending_chunk: Option<Vec<u8>>,
    pending_chunk_offset: usize,
    cache_read_state: CacheReadState,
    cache_write_state: CacheWriteState,
    cache_write_pos: u64,
    upstream_buf: Vec<u8>,
}

impl<R> PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn new(
        upstream: R,
        len: u64,
        cache_path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        Self::open(upstream, len, cache_path, 0).await
    }

    /// How much of `cache_path` can be trusted as an already-downloaded prefix.
    ///
    /// The cache is written strictly in order, and the length on disk only grows
    /// once bytes are written, so the file length is the resume point. The last
    /// megabyte is given up anyway: if the machine lost power or a drive was
    /// pulled mid-write, that tail is the only part that could have reached the
    /// filesystem's length without its data, and a megabyte is far cheaper to
    /// fetch again than a corrupt package is to diagnose.
    pub async fn resumable_prefix(cache_path: impl AsRef<std::path::Path>) -> u64 {
        const MARGIN: u64 = 1024 * 1024;
        match tokio::fs::metadata(cache_path.as_ref()).await {
            Ok(meta) => meta.len().saturating_sub(MARGIN) / MARGIN * MARGIN,
            Err(_) => 0,
        }
    }

    /// Open with `resume_from` bytes already cached.
    ///
    /// `upstream` must be positioned at `resume_from`, because everything read
    /// from it is appended to the cache at that point.
    pub async fn open(
        upstream: R,
        len: u64,
        cache_path: impl AsRef<std::path::Path>,
        resume_from: u64,
    ) -> std::io::Result<Self> {
        let cache_path = cache_path.as_ref();

        let mut cache_writer = OpenOptions::new()
            .create(true)
            .truncate(resume_from == 0)
            .read(true)
            .write(true)
            .open(cache_path)
            .await?;
        // Drop anything past the resume point, so the file length and
        // `cached_len` cannot disagree.
        //
        // The cursor has to be moved there too. The write path skips its seek
        // whenever `cache_write_pos` already matches `cached_len`, and a
        // freshly opened file sits at 0 -- so without this the continued
        // download overwrites the start of the cache instead of appending, and
        // the file never grows past the resume point.
        if resume_from > 0 {
            use tokio::io::AsyncSeekExt;
            cache_writer.set_len(resume_from).await?;
            cache_writer
                .seek(std::io::SeekFrom::Start(resume_from))
                .await?;
        }
        let cache_reader = OpenOptions::new().read(true).open(cache_path).await?;

        Ok(Self {
            upstream,
            len,
            pos: 0,
            cache_reader,
            cache_writer,
            cached_len: resume_from,
            pending_seek: None,
            pending_chunk: None,
            pending_chunk_offset: 0,
            cache_read_state: CacheReadState::Idle,
            cache_write_state: CacheWriteState::Idle,
            cache_write_pos: resume_from,
            upstream_buf: vec![0u8; UPSTREAM_READ_CHUNK_SIZE],
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn cached_len(&self) -> u64 {
        self.cached_len
    }

    fn poll_copy_from_cache(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<usize>> {
        if self.pos >= self.cached_len || buf.remaining() == 0 {
            return Poll::Ready(Ok(0));
        }

        loop {
            match self.cache_read_state {
                CacheReadState::Idle => {
                    let pos = self.pos;
                    AsyncSeek::start_seek(Pin::new(&mut self.cache_reader), SeekFrom::Start(pos))?;
                    self.cache_read_state = CacheReadState::Seeking { offset: pos };
                }
                CacheReadState::Seeking { offset } => {
                    match AsyncSeek::poll_complete(Pin::new(&mut self.cache_reader), cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(actual)) => {
                            if actual != offset {
                                self.cache_read_state = CacheReadState::Idle;
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "cache seek completed at unexpected position",
                                )));
                            }
                            self.cache_read_state = CacheReadState::Reading {
                                started_len: buf.filled().len(),
                            };
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_read_state = CacheReadState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                CacheReadState::Reading { started_len } => {
                    match AsyncRead::poll_read(Pin::new(&mut self.cache_reader), cx, buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            let read = buf.filled().len() - started_len;
                            self.cache_read_state = CacheReadState::Idle;
                            if read == 0 {
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::UnexpectedEof,
                                    "cache ended before cached_len",
                                )));
                            }
                            self.pos += read as u64;
                            return Poll::Ready(Ok(read));
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_read_state = CacheReadState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }
    }

    fn poll_flush_pending_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Some(chunk) = self.pending_chunk.as_ref().cloned() else {
            self.cache_write_state = CacheWriteState::Idle;
            return Poll::Ready(Ok(()));
        };

        loop {
            match self.cache_write_state {
                CacheWriteState::Idle => {
                    let cached_len = self.cached_len;
                    if self.cache_write_pos == cached_len {
                        self.cache_write_state = CacheWriteState::Writing;
                    } else {
                        AsyncSeek::start_seek(
                            Pin::new(&mut self.cache_writer),
                            SeekFrom::Start(cached_len),
                        )?;
                        self.cache_write_state = CacheWriteState::Seeking { offset: cached_len };
                    }
                }
                CacheWriteState::Seeking { offset } => {
                    match AsyncSeek::poll_complete(Pin::new(&mut self.cache_writer), cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(actual)) => {
                            if actual != offset {
                                self.cache_write_state = CacheWriteState::Idle;
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "cache write seek completed at unexpected position",
                                )));
                            }
                            self.cache_write_pos = actual;
                            self.cache_write_state = CacheWriteState::Writing;
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                CacheWriteState::Writing => {
                    let pending_offset = self.pending_chunk_offset;
                    match AsyncWrite::poll_write(
                        Pin::new(&mut self.cache_writer),
                        cx,
                        &chunk[pending_offset..],
                    ) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(0)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::WriteZero,
                                "cache write returned zero",
                            )));
                        }
                        Poll::Ready(Ok(written)) => {
                            self.pending_chunk_offset += written;
                            self.cached_len += written as u64;
                            self.cache_write_pos += written as u64;
                            if self.pending_chunk_offset >= chunk.len() {
                                self.pending_chunk = None;
                                self.pending_chunk_offset = 0;
                                self.cache_write_state = CacheWriteState::Idle;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }
    }

    fn poll_fill_from_upstream(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        if self.pending_chunk.is_some() {
            return Poll::Ready(Ok(true));
        }

        let mut upstream_buf = std::mem::take(&mut self.upstream_buf);
        if upstream_buf.is_empty() {
            upstream_buf.resize(UPSTREAM_READ_CHUNK_SIZE, 0);
        }
        let mut read_buf = ReadBuf::new(&mut upstream_buf);
        let poll = match AsyncRead::poll_read(Pin::new(&mut self.upstream), cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    let chunk = read_buf.filled().to_vec();
                    self.pending_chunk = Some(chunk);
                    self.pending_chunk_offset = 0;
                    Poll::Ready(Ok(true))
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        };
        self.upstream_buf = upstream_buf;
        poll
    }
}

impl<R> AsyncRead for PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 || self.pos >= self.len {
            return Poll::Ready(Ok(()));
        }

        match self.as_mut().poll_copy_from_cache(cx, buf) {
            Poll::Ready(Ok(read)) if read > 0 => return Poll::Ready(Ok(())),
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let target_end = self.len.min(
            self.pos
                .saturating_add(buf.remaining() as u64)
                .max(self.pos.saturating_add(1)),
        );

        loop {
            if self.cached_len >= target_end {
                match self.as_mut().poll_copy_from_cache(cx, buf) {
                    Poll::Ready(Ok(read)) => {
                        if read == 0 {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "cached prefix did not reach requested read position",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            match self.as_mut().poll_flush_pending_chunk(cx) {
                Poll::Ready(Ok(())) => {
                    if self.pending_chunk.is_some() {
                        continue;
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }

            match self.as_mut().poll_fill_from_upstream(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {
                    // Flushing the last chunk falls through to here without
                    // rechecking, so an upstream that ends exactly when the
                    // cache is complete is not a failure -- the bytes asked
                    // for did arrive. Only a genuinely short read is.
                    if self.cached_len >= target_end {
                        continue;
                    }
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "upstream ended before requested prefix was cached",
                    )));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<R> AsyncSeek for PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        let next = match position {
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

        self.pending_seek = Some(next);
        Ok(())
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        let next = self.pending_seek.take().unwrap_or(self.pos);
        if next > self.len {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past remote end",
            )));
        }

        self.pos = next;
        Poll::Ready(Ok(self.pos))
    }
}

async fn open_http_stream(
    client: reqwest::Client,
    url: String,
    start: Option<u64>,
) -> std::io::Result<OpenedHttpStream> {
    let mut request = client.get(url);
    if let Some(start) = start {
        request = request.header(RANGE, format!("bytes={start}-"));
    }

    let response = request
        .send()
        .await
        .map_err(http_err)?
        .error_for_status()
        .map_err(http_err)?;

    let (actual_start, len) = match start {
        None => {
            if response.status() != reqwest::StatusCode::OK {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("expected 200 OK, got {}", response.status()),
                ));
            }
            let len = response
                .headers()
                .get(CONTENT_LENGTH)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Content-Length"))?
                .to_str()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            (0, len)
        }
        Some(expected_start) => {
            if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("expected 206 Partial Content, got {}", response.status()),
                ));
            }
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Content-Range"))?
                .to_str()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            let (range, total) = content_range
                .split_once('/')
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid Content-Range"))?;
            let range = range.strip_prefix("bytes ").ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "invalid Content-Range prefix")
            })?;
            let (start_s, _) = range.split_once('-').ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "invalid Content-Range bounds")
            })?;
            let actual_start = start_s
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            if actual_start != expected_start {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("range resume mismatch: expected {expected_start}, got {actual_start}"),
                ));
            }
            let len = total
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            (actual_start, len)
        }
    };

    Ok(OpenedHttpStream {
        start: actual_start,
        len,
        stream: Box::pin(response.bytes_stream()),
    })
}

fn http_err(err: reqwest::Error) -> std::io::Error {
    Error::other(err)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::SeekFrom;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{HttpRead, PrefixCacheFile};

    #[derive(Clone, Debug)]
    struct RequestRecord {
        range: Option<String>,
    }

    #[derive(Clone)]
    struct ServerConfig {
        body: Arc<Vec<u8>>,
        first_body_limit: Option<usize>,
        resume_start_adjustment: i64,
        requests: Arc<Mutex<Vec<RequestRecord>>>,
        request_count: Arc<AtomicUsize>,
    }

    struct TestServer {
        url: String,
        requests: Arc<Mutex<Vec<RequestRecord>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        fn request_ranges(&self) -> Vec<Option<String>> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.range.clone())
                .collect()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_server(
        body: Vec<u8>,
        first_body_limit: Option<usize>,
        resume_start_adjustment: i64,
    ) -> io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let config = ServerConfig {
            body: Arc::new(body),
            first_body_limit,
            resume_start_adjustment,
            requests: requests.clone(),
            request_count: Arc::new(AtomicUsize::new(0)),
        };

        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, config).await;
                });
            }
        });

        Ok(TestServer {
            url: format!("http://{addr}/file"),
            requests,
            handle,
        })
    }

    async fn handle_connection(mut stream: TcpStream, config: ServerConfig) -> io::Result<()> {
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let request_text = String::from_utf8_lossy(&request);
        let range_header = request_text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("range") {
                Some(value.trim().to_owned())
            } else {
                None
            }
        });
        config.requests.lock().unwrap().push(RequestRecord {
            range: range_header.clone(),
        });

        let request_index = config.request_count.fetch_add(1, Ordering::SeqCst);
        let body_len = config.body.len() as u64;

        let (status_line, response_headers, response_body) = match range_header {
            None => {
                let body = if request_index == 0 {
                    if let Some(limit) = config.first_body_limit {
                        config.body[..limit.min(config.body.len())].to_vec()
                    } else {
                        config.body.as_ref().clone()
                    }
                } else {
                    config.body.as_ref().clone()
                };
                (
                    "HTTP/1.1 200 OK\r\n".to_owned(),
                    format!("Content-Length: {body_len}\r\nConnection: close\r\n"),
                    body,
                )
            }
            Some(range) => {
                let start = parse_range_start(&range)?;
                let adjusted_start = if config.resume_start_adjustment == 0 {
                    start
                } else {
                    (start as i64 + config.resume_start_adjustment) as u64
                };
                let body = config.body[adjusted_start as usize..].to_vec();
                let content_length = body.len();
                (
                    "HTTP/1.1 206 Partial Content\r\n".to_owned(),
                    format!(
                        "Content-Length: {content_length}\r\nContent-Range: bytes {adjusted_start}-{}/{body_len}\r\nConnection: close\r\n",
                        body_len.saturating_sub(1)
                    ),
                    body,
                )
            }
        };

        stream.write_all(status_line.as_bytes()).await?;
        stream.write_all(response_headers.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        stream.write_all(&response_body).await?;
        stream.shutdown().await?;
        Ok(())
    }

    fn parse_range_start(range: &str) -> io::Result<u64> {
        let value = range
            .strip_prefix("bytes=")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid range prefix"))?;
        let (start, _) = value
            .split_once('-')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid range bounds"))?;
        start
            .parse::<u64>()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    fn cache_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("xodus-streaming4-{name}-{nanos}.bin"))
    }

    fn test_body() -> Vec<u8> {
        (0..16384).map(|i| (i % 251) as u8).collect()
    }

    async fn open_cached_reader<'t>(
        server: &TestServer,
        cache: &PathBuf,
    ) -> PrefixCacheFile<HttpRead<'t>> {
        let http = HttpRead::open(reqwest::Client::new(), &server.url, Some(|_, _| {}))
            .await
            .unwrap();
        let len = http.len();
        PrefixCacheFile::new(http, len, cache).await.unwrap()
    }

    /// 5 MiB, so the 1 MiB resume margin has something to bite on.
    fn large_body() -> Vec<u8> {
        (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn an_interrupted_download_continues_where_it_stopped() {
        let body = large_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("resume");

        // A first attempt that stops part-way, as a closed lid or a killed
        // process would leave it.
        {
            let mut file = open_cached_reader(&server, &cache).await;
            let mut buf = vec![0u8; 3 * 1024 * 1024];
            file.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, body[..buf.len()]);
        }

        // The last megabyte is given up deliberately, so the resume point is
        // behind what was actually written.
        let resume = PrefixCacheFile::<tokio::fs::File>::resumable_prefix(&cache).await;
        assert_eq!(resume, 2 * 1024 * 1024, "should round down by the margin");

        let http = HttpRead::open_at(reqwest::Client::new(), &server.url, resume, Some(|_, _| {}))
            .await
            .unwrap();
        let len = http.len();
        assert_eq!(len, body.len() as u64, "a ranged open still knows the total");

        let mut file = PrefixCacheFile::open(http, len, &cache, resume).await.unwrap();
        let mut all = Vec::new();
        file.read_to_end(&mut all).await.unwrap();

        // The whole file, not a seam of duplicated or missing bytes at the
        // resume point -- which is the only thing that matters here.
        assert_eq!(all.len(), body.len());
        assert_eq!(all, body);

        // And the continuation really was a range request, rather than
        // re-fetching from the start.
        let ranges = server.request_ranges();
        assert!(
            ranges.last().unwrap().as_deref() == Some("bytes=2097152-"),
            "expected a resume range, got {ranges:?}"
        );
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn nothing_to_resume_from_is_zero() {
        let missing = cache_path("absent");
        assert_eq!(
            PrefixCacheFile::<tokio::fs::File>::resumable_prefix(&missing).await,
            0
        );

        // Below the margin there is nothing worth keeping either.
        let tiny = cache_path("tiny");
        std::fs::write(&tiny, vec![0u8; 1024]).unwrap();
        assert_eq!(
            PrefixCacheFile::<tokio::fs::File>::resumable_prefix(&tiny).await,
            0
        );
        let _ = std::fs::remove_file(tiny);
    }

    #[tokio::test]
    async fn cached_prefix_read_completes() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("small-prefix");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 64];
        file.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..], &body[..64]);
        assert!(file.cached_len() >= 64);
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn cached_backward_seek_uses_prefix() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("backward-seek");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut first = [0u8; 128];
        file.read_exact(&mut first).await.unwrap();
        file.seek(SeekFrom::Start(32)).await.unwrap();
        let mut second = [0u8; 64];
        file.read_exact(&mut second).await.unwrap();

        assert_eq!(&first[..], &body[..128]);
        assert_eq!(&second[..], &body[32..96]);
        assert_eq!(server.request_ranges(), vec![None]);
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn cached_reader_resumes_http_source() {
        let body = test_body();
        let server = spawn_server(body.clone(), Some(96), 0).await.unwrap();
        let cache = cache_path("resume");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 256];
        file.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..], &body[..256]);
        let ranges = server.request_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], None);
        assert_eq!(ranges[1].as_deref(), Some("bytes=96-"));
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn cached_reader_propagates_resume_mismatch() {
        let server = spawn_server(test_body(), Some(96), 1).await.unwrap();
        let cache = cache_path("resume-mismatch");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 256];
        let err = file.read_exact(&mut buf).await.unwrap_err();
        assert!(err.to_string().contains("range resume mismatch"));
        let _ = std::fs::remove_file(cache);
    }
}
