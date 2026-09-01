//! Runtime-sized parsing helpers.
//!
//! [`BytesReader`](crate::parse::BytesReader) gives compile-time-checked reads for
//! *fixed*-size structures, but every section also contains tables whose element
//! count is only known at runtime (from a preceding header field). [`Cursor`] is the
//! dynamic counterpart used to walk those tables: it performs the same kind of
//! sequential reads, but with a runtime bounds check (returning
//! [`PriParseError::Truncated`] instead of panicking or reading out of bounds) rather
//! than a compile-time one.

use bytes::Bytes;

use crate::parse::{BinaryParse, BinaryTryParse};
use crate::resources::error::PriParseError;

/// Borrows `len` bytes starting at `offset` out of `data`, or a
/// [`PriParseError::Truncated`] if the requested range falls outside of `data`.
pub(crate) fn slice_range<'a>(
    data: &'a [u8],
    offset: usize,
    len: usize,
    context: &'static str,
) -> Result<&'a [u8], PriParseError> {
    let end = offset
        .checked_add(len)
        .ok_or(PriParseError::Truncated { context })?;
    data.get(offset..end)
        .ok_or(PriParseError::Truncated { context })
}

/// Like [`slice_range`], but returns an owned, cheaply-clonable [`Bytes`] view
/// sharing the same underlying allocation, for data that needs to outlive parsing
/// (e.g. a resource candidate's payload).
pub(crate) fn bytes_slice(
    data: &Bytes,
    offset: usize,
    len: usize,
    context: &'static str,
) -> Result<Bytes, PriParseError> {
    let end = offset
        .checked_add(len)
        .ok_or(PriParseError::Truncated { context })?;
    if end > data.len() {
        return Err(PriParseError::Truncated { context });
    }
    Ok(data.slice(offset..end))
}

/// A sequential reader over a byte slice with a runtime-determined number of
/// reads, bounds-checked against [`PriParseError::Truncated`] rather than the
/// compile-time checks [`crate::parse::BytesReader`] provides.
pub(crate) struct Cursor<'a> {
    buffer: &'a Bytes,
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buffer: &'a Bytes, offset: usize) -> Self {
        Self { buffer, offset }
    }

    fn take_slice(&mut self, len: usize, context: &'static str) -> Result<&'a [u8], PriParseError> {
        let slice = slice_range(self.buffer, self.offset, len, context)?;
        self.offset += len;
        Ok(slice)
    }

    /// Borrows the next `len` bytes without decoding them.
    pub(crate) fn take(
        &mut self,
        len: usize,
        context: &'static str,
    ) -> Result<&'a [u8], PriParseError> {
        self.take_slice(len, context)
    }

    /// Like [`Cursor::take`], but returns an owned, cheaply-clonable [`Bytes`] view.
    pub(crate) fn take_bytes(
        &mut self,
        len: usize,
        context: &'static str,
    ) -> Result<Bytes, PriParseError> {
        let bytes = bytes_slice(self.buffer, self.offset, len, context)?;
        self.offset += len;
        Ok(bytes)
    }

    pub(crate) fn skip(&mut self, len: usize, context: &'static str) -> Result<(), PriParseError> {
        self.take_slice(len, context)?;
        Ok(())
    }

    pub(crate) fn read<T: BinaryParse>(
        &mut self,
        context: &'static str,
    ) -> Result<T::Output, PriParseError> {
        Ok(T::from_slice(self.take_slice(T::SIZE, context)?))
    }

    pub(crate) fn try_read<T>(&mut self, context: &'static str) -> Result<T::Output, PriParseError>
    where
        T: BinaryTryParse,
        PriParseError: From<T::Error>,
    {
        T::try_from_slice(self.take_slice(T::SIZE, context)?).map_err(PriParseError::from)
    }

    pub(crate) fn read_u16(&mut self, context: &'static str) -> Result<u16, PriParseError> {
        let slice = self.take_slice(2, context)?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }

    pub(crate) fn read_u32(&mut self, context: &'static str) -> Result<u32, PriParseError> {
        let slice = self.take_slice(4, context)?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    pub(crate) fn read_u16_array(
        &mut self,
        count: usize,
        context: &'static str,
    ) -> Result<Vec<u16>, PriParseError> {
        (0..count).map(|_| self.read_u16(context)).collect()
    }
}

/// Decodes a whole byte buffer as UTF-16LE (used for candidate/data-item payloads,
/// where the slice bounds already delimit the string exactly).
pub(crate) fn decode_utf16_bytes(bytes: &[u8]) -> String {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decodes `count` UTF-16LE code units starting at `offset_units` (in code units, as
/// name/value block offsets are always given) out of a Unicode name/value block.
///
/// Lenient by design: name/value blocks are leaf-level text data, so a bad offset or
/// count only affects the one name being decoded rather than misaligning every
/// subsequent read the way a bad *structural* offset would - it's clamped to the
/// block's bounds rather than treated as a hard parse error.
pub(crate) fn decode_utf16_at(block: &[u8], offset_units: usize, count: usize) -> String {
    let start = offset_units.saturating_mul(2).min(block.len());
    let end = start
        .saturating_add(count.saturating_mul(2))
        .min(block.len());
    decode_utf16_bytes(&block[start..end])
}

/// Like [`decode_utf16_at`], but for a zero-terminated (`wcharz`) string whose
/// length isn't given up front - scans for the terminating NUL code unit.
pub(crate) fn decode_utf16_z(block: &[u8], offset_units: usize) -> String {
    let start = offset_units.saturating_mul(2).min(block.len());
    let units = block[start..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0);
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decodes `count` bytes starting at `offset` out of an ASCII name block. See
/// [`decode_utf16_at`] for the leniency rationale.
pub(crate) fn decode_ascii_at(block: &[u8], offset: usize, count: usize) -> String {
    let start = offset.min(block.len());
    let end = start.saturating_add(count).min(block.len());
    block[start..end].iter().map(|&b| b as char).collect()
}

/// Like [`decode_ascii_at`], but for a zero-terminated string of unknown length.
pub(crate) fn decode_ascii_z(block: &[u8], offset: usize) -> String {
    let start = offset.min(block.len());
    block[start..]
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_utf16_at_and_z() {
        // "Hi\0" as UTF-16LE, followed by more data that must not be included.
        let block = [b'H', 0, b'i', 0, 0, 0, b'X', 0];
        assert_eq!(decode_utf16_at(&block, 0, 2), "Hi");
        assert_eq!(decode_utf16_z(&block, 0), "Hi");
    }

    #[test]
    fn test_decode_ascii_at_and_z() {
        let block = b"Hi\0X";
        assert_eq!(decode_ascii_at(block, 0, 2), "Hi");
        assert_eq!(decode_ascii_z(block, 0), "Hi");
    }

    #[test]
    fn test_decode_lenient_on_bad_offset() {
        let block = [b'H', 0, b'i', 0];
        // Way out of bounds - must clamp rather than panic.
        assert_eq!(decode_utf16_at(&block, 1000, 5), "");
        assert_eq!(decode_ascii_z(&block, 1000), "");
    }

    #[test]
    fn test_cursor_reads_sequentially() {
        let buffer = Bytes::from_static(&[1, 0, 2, 0, 3, 0, 0, 0]);
        let mut cursor = Cursor::new(&buffer, 0);
        assert_eq!(cursor.read_u16("a").unwrap(), 1);
        assert_eq!(cursor.read_u16("b").unwrap(), 2);
        assert_eq!(cursor.read_u32("c").unwrap(), 3);
        assert!(cursor.read_u16("d").is_err());
    }
}
