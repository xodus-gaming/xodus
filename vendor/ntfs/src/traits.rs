// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use binrw::io;
use binrw::io::{Read, Seek, SeekFrom};

use crate::error::{NtfsError, Result};

/// Trait to read/seek in a source by the help of a temporarily passed mutable reference to the filesystem reader.
///
/// By requiring the user to pass the filesystem reader on every read, we circumvent the problems associated with permanently
/// holding a mutable reference.
/// If we held one, we could not read from two objects in alternation.
pub trait NtfsReadSeek {
    /// See [`std::io::Read::read`].
    fn read<T>(&mut self, fs: &mut T, buf: &mut [u8]) -> Result<usize>
    where
        T: Read + Seek;

    /// See [`std::io::Read::read_exact`].
    fn read_exact<T>(&mut self, fs: &mut T, mut buf: &mut [u8]) -> Result<()>
    where
        T: Read + Seek,
    {
        // This implementation is taken from https://github.com/rust-lang/rust/blob/5662d9343f0696efcc38a1264656737c9f22d427/library/std/src/io/mod.rs
        // It handles all corner cases properly and outputs the known `io` error messages.
        while !buf.is_empty() {
            match self.read(fs, buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &mut buf[n..];
                }
                Err(NtfsError::Io(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        if !buf.is_empty() {
            Err(NtfsError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            )))
        } else {
            Ok(())
        }
    }

    /// See [`std::io::Seek::seek`].
    fn seek<T>(&mut self, fs: &mut T, pos: SeekFrom) -> Result<u64>
    where
        T: Read + Seek;

    /// See [`std::io::Seek::stream_position`].
    fn stream_position(&self) -> u64;
}
