// Copyright 2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;
use std::io::{Read, Seek, SeekFrom};

/// `SectorReader` encapsulates any reader and only performs read and seek operations on it
/// on boundaries of the given sector size.
///
/// This can be very useful for readers that only accept sector-sized reads (like reading
/// from a raw partition on Windows).
/// The sector size must be a power of two.
///
/// This reader does not keep any buffer.
/// You are advised to encapsulate `SectorReader` in a buffered reader, as unbuffered reads of
/// just a few bytes here and there are highly inefficient.
pub struct SectorReader<R>
where
    R: Read + Seek,
{
    /// The inner reader stream.
    inner: R,
    /// The sector size set at creation.
    sector_size: usize,
    /// The current stream position as requested by the caller through `read` or `seek`.
    /// The implementation will internally make sure to only read/seek on sector boundaries.
    stream_position: u64,
    /// This buffer is only part of the struct as a small performance optimization (keeping it allocated between reads).
    temp_buf: Vec<u8>,
}

impl<R> SectorReader<R>
where
    R: Read + Seek,
{
    pub fn new(inner: R, sector_size: usize) -> io::Result<Self> {
        if !sector_size.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "sector_size is not a power of two",
            ));
        }

        Ok(Self {
            inner,
            sector_size,
            stream_position: 0,
            temp_buf: Vec::new(),
        })
    }

    fn align_down_to_sector_size(&self, n: u64) -> u64 {
        n / self.sector_size as u64 * self.sector_size as u64
    }

    fn align_up_to_sector_size(&self, n: u64) -> u64 {
        self.align_down_to_sector_size(n) + self.sector_size as u64
    }
}

impl<R> Read for SectorReader<R>
where
    R: Read + Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // We can only read from a sector boundary, and `self.stream_position` specifies the position where the
        // caller thinks we are.
        // Align down to a sector boundary to determine the position where we really are (see our `seek` implementation).
        let aligned_position = self.align_down_to_sector_size(self.stream_position);

        // We have to read more bytes now to make up for the alignment difference.
        // We can also only read in multiples of the sector size, so align up to the next sector boundary.
        let start = (self.stream_position - aligned_position) as usize;
        let end = start + buf.len();
        let aligned_bytes_to_read = self.align_up_to_sector_size(end as u64) as usize;

        // Perform the sector-sized read and copy the actually requested bytes into the given buffer.
        self.temp_buf.resize(aligned_bytes_to_read, 0);
        self.inner.read_exact(&mut self.temp_buf)?;
        buf.copy_from_slice(&self.temp_buf[start..end]);

        // We are done.
        self.stream_position += buf.len() as u64;
        Ok(buf.len())
    }
}

impl<R> Seek for SectorReader<R>
where
    R: Read + Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(_n) => {
                // This is unsupported, because it's not safely possible under Windows.
                // We cannot seek to the end to determine the raw partition size.
                // Which makes it impossible to set `self.stream_position`.
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "SeekFrom::End is unsupported for SectorReader",
                ));
            }
            SeekFrom::Current(n) => {
                if n >= 0 {
                    self.stream_position.checked_add(n as u64)
                } else {
                    self.stream_position.checked_sub(n.wrapping_neg() as u64)
                }
            }
        };

        match new_pos {
            Some(n) => {
                // We can only seek on sector boundaries, so align down the requested seek position and seek to that.
                let aligned_n = self.align_down_to_sector_size(n);
                self.inner.seek(SeekFrom::Start(aligned_n))?;

                // Make the caller believe that we seeked to the actually requested position.
                // Our `read` implementation will cover the difference.
                self.stream_position = n;
                Ok(self.stream_position)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )),
        }
    }
}
