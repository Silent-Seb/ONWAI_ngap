//! Bit-level writer.

use crate::error::{AperError, ErrorKind};

/// Accumulates bits MSB-first. All APER encoders are methods on this type (see the other modules).
#[derive(Debug, Default, Clone)]
pub struct BitWriter {
    buf: Vec<u8>,
    nbits: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of bits written so far.
    pub fn bit_len(&self) -> usize {
        self.nbits
    }

    /// True if the next bit goes to the start of an octet.
    pub fn is_aligned(&self) -> bool {
        self.nbits.is_multiple_of(8)
    }

    /// An error positioned at the current write offset.
    pub fn error(&self, kind: ErrorKind) -> AperError {
        AperError::new(kind, self.nbits)
    }

    pub fn write_bit(&mut self, bit: bool) {
        self.write_bits(u64::from(bit), 1);
    }

    /// Write the low `n` bits of `value` (`n <= 64`), most significant first.
    pub fn write_bits(&mut self, value: u64, n: u32) {
        debug_assert!(n <= 64);
        let mut remaining = n;
        let mut v = if n < 64 {
            value & ((1u64 << n) - 1)
        } else {
            value
        };
        while remaining > 0 {
            let used = (self.nbits % 8) as u32;
            if used == 0 {
                self.buf.push(0);
            }
            let free = 8 - used;
            let take = free.min(remaining);
            let shift = remaining - take;
            let chunk = (v >> shift) as u8 & (((1u16 << take) - 1) as u8);
            *self.buf.last_mut().expect("a byte was pushed") |= chunk << (free - take);
            self.nbits += take as usize;
            remaining -= take;
            v &= (1u64 << shift) - 1;
        }
    }

    /// Pad with zero bits up to the next octet boundary.
    pub fn align(&mut self) {
        let rem = self.nbits % 8;
        if rem != 0 {
            self.nbits += 8 - rem;
        }
    }

    /// Write whole octets at the current bit position (not necessarily aligned).
    pub fn write_octets(&mut self, data: &[u8]) {
        if self.is_aligned() {
            self.buf.extend_from_slice(data);
            self.nbits += data.len() * 8;
        } else {
            for &b in data {
                self.write_bits(u64::from(b), 8);
            }
        }
    }

    /// The bytes written, the last one zero-padded. Empty if nothing was written.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// X.691 10.1: a *complete encoding* has at least one octet (an empty encoding becomes a single zero octet).
    pub fn into_complete_bytes(self) -> Vec<u8> {
        if self.buf.is_empty() {
            vec![0]
        } else {
            self.buf
        }
    }
}
