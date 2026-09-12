use crate::layout::PAGE_SIZE;
use crate::models::xvd::layout::{HASH_ENTRIES_IN_PAGE, HASH_ENTRY_LENGTH};

use futures_util::stream::Stream;
use pin_project::pin_project;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, ReadBuf};

use std::hint;
use std::io::{self, Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

type HashEntry = [u8; HASH_ENTRY_LENGTH];
type Page = [u8; PAGE_SIZE];

#[derive(Debug, Error)]
#[error(
    r#"hash mismatch at page {page_index}:
  expected {expected:?},
  got {got:?}"#
)]
pub struct HashMismatch {
    page_index: usize,
    expected: HashEntry,
    got: HashEntry,
}

#[derive(Debug, Error)]
pub enum HashTreeStreamError {
    #[error("IO error: {0}")]
    Io(#[from] Error),

    #[error(transparent)]
    HashMismatch(#[from] HashMismatch),
}

/// The `PageVerifier` struct is used to verify the integrity of pages from a
/// list of hashes.
///
/// The hashes must be allocated in memory, so this struct cannot be used if
/// the hashes are not in memory yet. If the hashes have to be read from an
/// [`AsyncRead`]er, see [`HashTreeStream`] for parsing a hash table into an
/// async [`Stream`] of hashes.
struct PageVerifier {
    hashes: Box<[HashEntry]>,
}

impl PageVerifier {
    pub fn new(hashes: Box<[HashEntry]>) -> Self {
        Self { hashes }
    }

    /// Verifies that the provided `page` is intact.
    ///
    /// # Panics
    ///
    /// If provided `page` and `page_index` is not in-bounds.
    pub fn verify_page(&self, page: &Page, page_index: usize) -> Result<(), HashMismatch> {
        assert!(page_index < self.hashes.len());

        let expected_hash = self.hashes[page_index];
        let hash: HashEntry = *Sha256::digest(page)
            .first_chunk::<HASH_ENTRY_LENGTH>()
            .unwrap();

        if expected_hash != hash {
            hint::cold_path();
            return Err(HashMismatch {
                page_index,
                expected: expected_hash,
                got: hash,
            });
        }

        Ok(())
    }
}

/// The `PageStream<R>` struct wraps an asynchronous reader and yields data
/// one page at a time.
///
/// See [`PageStream::poll_next_page`] for more information.
#[pin_project]
struct PageStream<R> {
    #[pin]
    reader: R,

    buf: Box<Page>,
    filled: usize,
}

impl<R: AsyncRead> PageStream<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Box::new([0u8; PAGE_SIZE]),
            filled: 0,
        }
    }

    /// Returns the last page returned by [`Self::poll_next_page`].
    ///
    /// Returns `None` before the first call to [`Self::poll_next_page`], and
    /// after a call that returned [`Poll::Pending`] or an error. This function
    /// returns the same page until the next call to [`Self::poll_next_page`].
    pub fn buffer(&self) -> Option<&Page> {
        (self.filled == PAGE_SIZE).then_some(&self.buf)
    }

    /// Attempt to pull out the next page of this stream, registering the
    /// current task for wakeup if the page is not yet available.
    ///
    /// The caller must stop calling this function once the stream has returned
    /// the expected number of pages because it will return an
    /// [`ErrorKind::UnexpectedEof`] error otherwise.
    ///
    /// # Return value
    ///
    /// There are several possible return values, each indicating a distinct
    /// stream state:
    ///
    /// - `Poll::Pending` means that this stream's next page is not ready yet.
    ///   The current task will be notified when the next value may be ready.
    ///
    /// - `Poll::Ready(Err(err))` means that the underlying reader has returned
    ///   an error. The stream must not be polled again.
    ///
    /// - `Poll::Ready(Ok(page))` means that the stream has successfully
    ///   produced a value, `page`, and may produce further values on subsequent
    ///   [`Self::poll_next_page`] calls. The page can also be accessed through
    ///   [`Self::buffer`] until the next call to [`Self::poll_next_page`],
    ///   which will reset the buffer.
    pub fn poll_next_page<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<&'a Page>> {
        let mut this = self.project();

        // If the last page is fully filled, reset the buffer.
        if *this.filled == PAGE_SIZE {
            *this.filled = 0;
        }

        while *this.filled < PAGE_SIZE {
            // `buf` contains the unfilled portion of the buffer.
            let mut buf = ReadBuf::new(&mut this.buf[*this.filled..]);

            match ready!(this.reader.as_mut().poll_read(cx, &mut buf)) {
                Err(e) if let ErrorKind::Interrupted = e.kind() => {}
                Err(e) => return Poll::Ready(Err(e)),
                Ok(()) if buf.filled().is_empty() => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    )));
                }
                Ok(()) => *this.filled += buf.filled().len(),
            }
        }

        // `this.filled` is exactly `PAGE_SIZE`, so the page buffer is now full.
        assert_eq!(*this.filled, PAGE_SIZE);

        // `this.filled` mustn't be set to 0 here because we want to be able to
        // obtain the filled buffer through `Self::buffer`. The next call to
        // `poll_next_page` will clear the buffer in order to start a new poll.

        Poll::Ready(Ok(this.buf))
    }
}

/// Stream over level 0 hash tree entries.
///
/// This struct wraps an [`AsyncRead`]er over the level 0 hash tree and returns
/// a [`Stream`] of hash entries. The hash tree is fetched page by page, and
/// each page is hashed and verified against the corresponding hash provided in
/// [`HashTreeStream::new`]. Because this struct already pulls data in pages,
/// the underlying reader doesn't need to be buffered.
#[pin_project]
pub struct HashTreeStream<R> {
    #[pin]
    reader: PageStream<R>,

    current_page: usize,
    page_verifier: PageVerifier,

    remaining_hashes: usize,
    next_entry_in_page: usize,
}

impl<R: AsyncRead> HashTreeStream<R> {
    /// Creates a new [`HashTreeStream`].
    ///
    /// # Panics
    ///
    /// If `level_0_hashes` doesn't fit exactly into `level_1_hashes.len()` pages.
    pub fn new(reader: R, level_1_hashes: Box<[HashEntry]>, level_0_hashes: usize) -> Self {
        assert_eq!(
            level_0_hashes.div_ceil(HASH_ENTRIES_IN_PAGE as usize),
            level_1_hashes.len()
        );

        Self {
            reader: PageStream::new(reader),
            current_page: 0,
            page_verifier: PageVerifier::new(level_1_hashes),
            remaining_hashes: level_0_hashes,
            next_entry_in_page: 0,
        }
    }
}

impl<R> Stream for HashTreeStream<R>
where
    R: AsyncRead,
{
    type Item = Result<HashEntry, HashTreeStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        if *this.remaining_hashes == 0 {
            return Poll::Ready(None);
        }

        // If there are remaining hash entries in the buffer that have not been
        // returned, then return the next one and advance the counter.
        if let Some(buf) = this.reader.buffer()
            && let Some(hash) = buf
                .as_chunks::<HASH_ENTRY_LENGTH>()
                .0
                .get(*this.next_entry_in_page)
        {
            *this.remaining_hashes -= 1;
            *this.next_entry_in_page += 1;
            return Poll::Ready(Some(Ok(*hash)));
        }

        let buf = ready!(this.reader.poll_next_page(cx)?);

        // Check that the hash of the current page is the expected one. It's fine
        // to calculate the hash here because it's a single hash, so it doesn't
        // block the thread for long.

        this.page_verifier.verify_page(buf, *this.current_page)?;
        *this.current_page += 1;

        // Return the first hash of the current page, and set `next_entry_in_page`
        // to 1 so subsequent calls to `poll_next` return the next entries.

        *this.remaining_hashes -= 1;
        *this.next_entry_in_page = 1;

        Poll::Ready(Some(Ok(*buf.first_chunk::<HASH_ENTRY_LENGTH>().unwrap())))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining_hashes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::pin::pin;
    use std::task::Waker;

    #[test]
    fn test_page_verifier() {
        let mut pages = [[0u8; PAGE_SIZE], [1u8; PAGE_SIZE], [2u8; PAGE_SIZE]];
        let hashes = [
            // Truncated Sha256 of a Page full of bytes `0u8`.
            [
                173, 127, 172, 178, 88, 111, 198, 233, 102, 192, 4, 215, 209, 209, 107, 2, 79, 88,
                5, 255, 124, 180, 124, 122,
            ],
            // Truncated Sha256 of a Page full of bytes `1u8`.
            [
                52, 49, 56, 55, 33, 81, 12, 241, 194, 17, 222, 2, 124, 249, 88, 193, 131, 225, 109,
                181, 250, 187, 107, 35,
            ],
            // Truncated Sha256 of a Page full of bytes `2u8`.
            [
                48, 214, 188, 22, 78, 165, 65, 136, 170, 157, 240, 193, 79, 32, 196, 251, 200, 161,
                85, 197, 100, 75, 204, 158,
            ],
        ];

        let page_verifier = PageVerifier::new(Box::new(hashes));

        for (i, page) in pages.iter_mut().enumerate() {
            // Place invalid data into the page.
            page[0] = !page[0];

            // Check that the page verification fails.
            let err = page_verifier.verify_page(page, i).unwrap_err();
            assert_eq!(err.page_index, i);
            assert_eq!(err.expected, hashes[i]);

            // Restore the page to its original state.
            page[0] = !page[0];

            // Check that now the page verification succeeds.
            page_verifier.verify_page(page, i).unwrap();
        }
    }

    #[test]
    #[should_panic]
    fn test_page_verifier_oob() {
        let page = [0u8; PAGE_SIZE];
        let hashes = [[0u8; 24]; 0];

        let page_verifier = PageVerifier::new(Box::new(hashes));

        // When running out of hashes, the `PageVerifier` should panic.
        let _ = page_verifier.verify_page(&page, 0);
    }

    #[test]
    fn test_page_stream() {
        // Fill a buffer with test data.
        let test_data: [u8; PAGE_SIZE * 3 + 84] = std::array::from_fn(|i| {
            // Make sure that the first `u8::MAX` pages are all different.
            let page = i / PAGE_SIZE;
            (page as u8).wrapping_add(i as u8)
        });

        // Create a `PageStream` over the test data.
        let mut page_stream = pin!(PageStream::new(Cursor::new(&test_data)));
        let mut cx = Context::from_waker(Waker::noop());

        assert_eq!(page_stream.buffer(), None);

        // For each full page in `test_data`, check that `PageStream` returns
        // exactly the same data.
        for chunk in test_data.as_chunks::<PAGE_SIZE>().0 {
            let Poll::Ready(Ok(buf)) = page_stream.as_mut().poll_next_page(&mut cx) else {
                unreachable!("An in-memory Cursor mustn't block nor fail");
            };

            assert_eq!(buf, chunk);
            assert_eq!(page_stream.buffer(), Some(chunk));
        }

        // After we've consumed every full page, the stream must return an
        // `io::ErrorKind::UnexpectedEof` error.
        let Poll::Ready(Err(e)) = page_stream.as_mut().poll_next_page(&mut cx) else {
            unreachable!("After consuming all the pages, it must return an error");
        };

        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(page_stream.buffer(), None);
    }
}
