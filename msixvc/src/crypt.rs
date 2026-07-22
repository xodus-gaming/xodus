#![expect(unused)]

mod buffer;
use buffer::PageBuffer;

mod region;
pub use region::{Region, RegionTable};

mod xts;
pub use xts::{TweakGenerator, decrypt_page_xts};

use crate::models::xvd::{PAGE_SIZE, XvcRegionId};

use std::io::{self, BufRead, Read, Seek, SeekFrom};

use aes::cipher::KeyInit;
use aes::{Aes128Dec, Aes128Enc};
use uuid::Uuid;

/// A [`RegionDecryptor`] decrypts pages within an XVC region using AES-XTS.
///
/// It is generic over `Units` (bounded by `AsRef<[u32]>`) so callers can supply
/// data units as borrowed or owned.
#[derive(Clone, Debug)]
pub struct RegionDecryptor<Units> {
    tweak: TweakGenerator,

    tweak_cipher: Aes128Enc,
    data_cipher: Aes128Dec,

    /// If integrity is enabled, it must contain one entry per page in the region.
    /// If integrity is disabled, `page_in_section` is used as the data unit instead, so this
    /// field must be left empty (`&[]`).
    data_units: Units,
}

impl<Units> RegionDecryptor<Units>
where
    Units: AsRef<[u32]>,
{
    pub fn new(region_id: XvcRegionId, vduid: Uuid, full_key: [u8; 32], data_units: Units) -> Self {
        Self {
            tweak: TweakGenerator::new(region_id, vduid),
            tweak_cipher: Aes128Enc::new(full_key[..16].try_into().unwrap()),
            data_cipher: Aes128Dec::new(full_key[16..].try_into().unwrap()),
            data_units,
        }
    }

    /// Decrypts `page` in place, using the corresponding tweak for `page_in_region`.
    ///
    /// The caller must ensure that `page_in_region` is in-bounds for this region.
    /// Else, this function will place invalid data into `page`.
    pub fn decrypt_at(&self, page_in_region: usize, page: &mut [u8; PAGE_SIZE]) {
        let tweak = self.tweak.with_data_unit(
            // Get the data unit that corresponds to this page, or `page_in_region` if missing.
            self.data_units
                .as_ref()
                .get(page_in_region)
                .copied()
                .unwrap_or(page_in_region as u32),
        );

        decrypt_page_xts(page, tweak, &self.tweak_cipher, &self.data_cipher);
    }
}

#[derive(Debug)]
pub struct DecryptorReader<R, Units> {
    /// The underlying reader, which spans the whole file.
    inner: R,

    /// The current offset that this reader is positioned at (relative to the start
    /// of the inner reader).
    read_offset: usize,

    /// Table of all regions that this reader spans.
    regions: RegionTable<Units>,

    /// Cache of the currently loaded page, used to decrypt whole pages at a time.
    buffer: PageBuffer,
}

impl<R, Units> DecryptorReader<R, Units> {
    #[inline]
    fn is_finished(&self) -> bool {
        self.read_offset as u64 >= self.regions.reader_len()
    }

    #[inline]
    fn current_page(&self) -> usize {
        self.regions.pages().start as usize + self.read_offset / PAGE_SIZE
    }

    #[inline]
    fn buffer(&self) -> Option<&[u8]> {
        self.buffer.get().map(|buf| {
            let page_offset = self.read_offset % PAGE_SIZE;
            &buf[page_offset..]
        })
    }

    /// [`Seek`] position of the inner reader (measured in pages).
    #[inline]
    fn inner_reader_pos(&self) -> usize {
        // The inner reader is usually positioned at the start of the next page.
        // However, when the current page hasn't been loaded yet (`self.buffer().is_none()`),
        // the inner reader is placed at the start of the current page.

        let current_page = self.current_page();

        match self.buffer() {
            Some(_) => current_page + 1,
            None => current_page,
        }
    }
}

impl<R, Units> DecryptorReader<R, Units>
where
    R: Read,
    Units: AsRef<[u32]>,
{
    /// Creates a new [`DecryptorReader`], which decrypts pages on-the-fly as they
    /// are read from the underlying reader.
    ///
    /// `inner` must already be positioned at the start of the first region in
    /// `regions`, i.e. at byte offset `regions.pages().start * PAGE_SIZE as u64`.
    pub fn new(inner: R, regions: RegionTable<Units>) -> Self {
        Self {
            inner,
            read_offset: 0,
            regions,
            buffer: PageBuffer::new(),
        }
    }

    /// Fill the internal buffer with the next page of data.
    ///
    /// The underlying reader must be positioned at the start of the page that will
    /// be read. `self.read_offset` itself doesn't need to be page-aligned, it only
    /// needs to be within the bounds of that page.
    fn next_page(&mut self) -> io::Result<()> {
        // If there are no remaining pages in this region, return without
        // filling the buffer.
        if self.is_finished() {
            self.buffer.clear();
            return Ok(());
        }

        let current_page = self.current_page() as u64;
        let current_region = self.regions.region_at(current_page);

        // Start the buffer refill process. The buffer will be marked as available
        // after the guard is dropped.
        let mut guard = self.buffer.refill();

        // Read the new page.
        self.inner.read_exact(&mut *guard)?;

        // Decrypt the new page.
        current_region.decrypt_at(current_page, &mut guard);

        Ok(())
    }
}

impl<R, Units> BufRead for DecryptorReader<R, Units>
where
    R: Read,
    Units: AsRef<[u32]>,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        // This can't be an `if let Some(buf) = ...` because of limitations with the
        // current Rust borrow checker. Once polonius (the next-gen borrow checker)
        // is stabilized, this code should be simplified.
        if self.buffer().is_some() {
            return Ok(self.buffer().unwrap());
        }

        // If the buffer is empty, refill it.
        self.next_page()?;

        // Return the new page, or an empty slice if the reader reached EOF.
        Ok(self.buffer().unwrap_or_default())
    }

    fn consume(&mut self, amount: usize) {
        let current_off = self.read_offset;
        let next_off = current_off + amount;

        let current_page = current_off / PAGE_SIZE;
        let next_page = next_off / PAGE_SIZE;

        assert!(amount <= PAGE_SIZE);
        assert!(next_off <= (current_page + 1) * PAGE_SIZE);

        // Advance the read offset
        self.read_offset = next_off;

        // Clear the buffer if it has been fully consumed.
        if next_page > current_page {
            self.buffer.clear();
        }
    }
}

impl<R, Units> Read for DecryptorReader<R, Units>
where
    R: Read,
    Units: AsRef<[u32]>,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let remaining_page = self.fill_buf()?;
        let bytes = std::cmp::min(buf.len(), remaining_page.len());

        buf[..bytes].copy_from_slice(&remaining_page[..bytes]);
        self.consume(bytes);

        Ok(bytes)
    }
}

impl<R, Units> Seek for DecryptorReader<R, Units>
where
    R: Seek,
    Units: AsRef<[u32]>,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let old_pos = self.read_offset as u64;
        let new_pos = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.regions.reader_len().checked_add_signed(n),
            SeekFrom::Current(n) => old_pos.checked_add_signed(n),
        };

        let new_pos = match new_pos {
            Some(pos) if pos <= self.regions.reader_len() => pos,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid seek to a negative or overflowing position",
                ));
            }
        };

        let old_page = old_pos / PAGE_SIZE as u64;
        let new_page = new_pos / PAGE_SIZE as u64;

        // If the page hasn't changed, don't modify the buffer.
        if new_page == old_page {
            self.read_offset = new_pos as usize;
            return Ok(new_pos);
        }

        // Get the inner reader pos, to detect if we can avoid a seek.
        let reader_pos = self.inner_reader_pos() as u64;

        // Update the read offset pointer.
        self.read_offset = new_pos as usize;

        // The page has changed, so the page buffer must be invalidated.
        self.buffer.clear();

        // The seek can be avoided if the reader is already positioned at the target offset.
        let absolute_new_page = self.regions.pages().start + new_page;
        if absolute_new_page == reader_pos {
            return Ok(new_pos);
        }

        // Seek to the start of the new page
        self.inner
            .seek(SeekFrom::Start(absolute_new_page * PAGE_SIZE as u64))?;

        Ok(new_pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.read_offset as u64)
    }
}

pub struct SectionReader<'t, R> {
    inner: R,
    section_offset: u64,
    section_length: u64,

    tweak: TweakGenerator,

    tweak_cipher: Aes128Enc,
    data_cipher: Aes128Dec,

    // If integrity is enabled, this must contain one entry per page in the section.
    // If integrity is disabled, use page_in_section as the data unit instead.
    data_units: Option<&'t [u32]>,

    // simplest useful cache
    cached_page_index: Option<u64>,
    cached_page_plaintext: [u8; PAGE_SIZE],
}

impl<'t, R: Read + Seek> SectionReader<'t, R> {
    pub fn new(
        inner: R,
        section_offset: u64,
        section_length: u64,
        header_id: XvcRegionId,
        vduid: Uuid,
        full_key: [u8; 32],
        data_units: Option<&'t [u32]>,
    ) -> Self {
        let mut tweak_key = [0u8; 16];
        let mut data_key = [0u8; 16];
        tweak_key.copy_from_slice(&full_key[..16]);
        data_key.copy_from_slice(&full_key[16..]);

        Self {
            inner,
            section_offset,
            section_length,
            tweak: TweakGenerator::new(header_id, vduid),
            tweak_cipher: Aes128Enc::new((&tweak_key).into()),
            data_cipher: Aes128Dec::new((&data_key).into()),
            data_units,
            cached_page_index: None,
            cached_page_plaintext: [0u8; PAGE_SIZE],
        }
    }

    pub fn read_at(&mut self, offset_in_section: u64, mut out: &mut [u8]) -> io::Result<()> {
        let end = offset_in_section
            .checked_add(out.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range overflow"))?;

        if end > self.section_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read exceeds section length",
            ));
        }

        let mut cur_off = offset_in_section;

        while !out.is_empty() {
            let page_in_section = cur_off / PAGE_SIZE as u64;
            let in_page = (cur_off % PAGE_SIZE as u64) as usize;
            let copy_len = std::cmp::min(out.len(), PAGE_SIZE - in_page);

            self.ensure_page_decrypted(page_in_section)?;
            out[..copy_len]
                .copy_from_slice(&self.cached_page_plaintext[in_page..in_page + copy_len]);

            cur_off += copy_len as u64;
            out = &mut out[copy_len..];
        }

        Ok(())
    }

    fn ensure_page_decrypted(&mut self, page_in_section: u64) -> io::Result<()> {
        if self.cached_page_index == Some(page_in_section) {
            return Ok(());
        }

        let file_offset = self
            .section_offset
            .checked_add(page_in_section * PAGE_SIZE as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow"))?;

        let tweak = self.tweak.with_data_unit(match &self.data_units {
            Some(units) => *units
                .get(page_in_section as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing data unit"))?,
            None => page_in_section as u32,
        });

        let mut page = [0u8; PAGE_SIZE];
        self.inner.seek(SeekFrom::Start(file_offset))?;
        self.inner.read_exact(&mut page)?;

        decrypt_page_xts(&mut page, tweak, &self.tweak_cipher, &self.data_cipher);

        self.cached_page_plaintext = page;
        self.cached_page_index = Some(page_in_section);
        Ok(())
    }
}
