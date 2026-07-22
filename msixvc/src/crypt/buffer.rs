use crate::models::xvd::PAGE_SIZE;

use std::ops::{Deref, DerefMut};

/// Page buffer, needed for decryption because pages must be decrypted as a whole.
/// The buffer is stored inside a `Box` in order to make the struct smaller.
///
/// Stores whether the current buffer is valid or it needs to be refilled.
#[derive(Debug)]
pub struct PageBuffer {
    buffer: Box<[u8; PAGE_SIZE]>,
    is_valid: bool,
}

impl PageBuffer {
    pub fn new() -> Self {
        Self {
            buffer: Box::new([0u8; PAGE_SIZE]),
            is_valid: false,
        }
    }

    pub fn get(&self) -> Option<&[u8; PAGE_SIZE]> {
        self.is_valid.then_some(&*self.buffer)
    }

    pub fn clear(&mut self) {
        self.is_valid = false;
    }

    pub fn refill(&mut self) -> BufferRefillGuard<'_> {
        BufferRefillGuard(self)
    }
}

/// A guard returned by [`PageBuffer::refill`], granting mutable access to the
/// buffer while it's being refilled. Marks the buffer valid again once dropped.
pub struct BufferRefillGuard<'a>(&'a mut PageBuffer);

impl Deref for BufferRefillGuard<'_> {
    type Target = [u8; PAGE_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0.buffer
    }
}

impl DerefMut for BufferRefillGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0.buffer
    }
}

impl Drop for BufferRefillGuard<'_> {
    fn drop(&mut self) {
        self.0.is_valid = true;
    }
}
