//! Bit-level reader.

use std::borrow::Cow;

use crate::error::{AperError, ErrorKind, Result};

/// Reads bits MSB-first from a byte slice. All APER decoders are methods on this type (see the other modules).
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current offset in bits.
    pub fn bit_position(&self) -> usize {
        self.pos
    }

    pub fn remaining_bits(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    /// An error positioned at the current read offset.
    pub fn error(&self, kind: ErrorKind) -> AperError {
        AperError::new(kind, self.pos)
    }

    pub fn read_bit(&mut self) -> Result<bool> {
        Ok(self.read_bits(1)? != 0)
    }

    /// Read `n <= 64` bits as an unsigned number.
    pub fn read_bits(&mut self, n: u32) -> Result<u64> {
        debug_assert!(n <= 64);
        if (n as usize) > self.remaining_bits() {
            return Err(self.error(ErrorKind::UnexpectedEof));
        }
        let mut out = 0u64;
        let mut remaining = n;
        while remaining > 0 {
            let used = (self.pos % 8) as u32;
            let avail = 8 - used;
            let take = avail.min(remaining);
            let byte = self.data[self.pos / 8];
            let chunk = (byte >> (avail - take)) & (((1u16 << take) - 1) as u8);
            out = (out << take) | u64::from(chunk);
            self.pos += take as usize;
            remaining -= take;
        }
        Ok(out)
    }

    /// Skip to the next octet boundary (the padding bits are not checked).
    pub fn align(&mut self) -> Result<()> {
        let rem = self.pos % 8;
        if rem != 0 {
            if 8 - rem > self.remaining_bits() {
                return Err(self.error(ErrorKind::UnexpectedEof));
            }
            self.pos += 8 - rem;
        }
        Ok(())
    }

    /// Read `n` whole octets at the current bit position; borrowed when octet-aligned.
    pub fn read_octets(&mut self, n: usize) -> Result<Cow<'a, [u8]>> {
        if n > self.remaining_bits() / 8 {
            return Err(self.error(ErrorKind::UnexpectedEof));
        }
        if self.pos.is_multiple_of(8) {
            let start = self.pos / 8;
            self.pos += n * 8;
            Ok(Cow::Borrowed(&self.data[start..start + n]))
        } else {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(self.read_bits(8)? as u8);
            }
            Ok(Cow::Owned(v))
        }
    }
}
