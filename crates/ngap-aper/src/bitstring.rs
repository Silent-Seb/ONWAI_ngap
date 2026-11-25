//! The BIT STRING value type.

use core::fmt;

use crate::error::{AperError, ErrorKind, Result};

/// A bit string: `bit_len` bits stored MSB-first in `ceil(bit_len / 8)` octets; unused trailing bits are zero.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct BitString {
    data: Vec<u8>,
    bit_len: usize,
}

impl BitString {
    /// Build from octets and a bit length. `data.len()` must be `ceil(bit_len / 8)`; unused trailing bits are cleared.
    pub fn new(mut data: Vec<u8>, bit_len: usize) -> Result<Self> {
        if data.len() != bit_len.div_ceil(8) {
            return Err(AperError::new(ErrorKind::InvalidBitString, 0));
        }
        let rem = bit_len % 8;
        if rem != 0 {
            let last = data.len() - 1;
            data[last] &= 0xFFu8 << (8 - rem);
        }
        Ok(Self { data, bit_len })
    }

    /// Build from individual bits.
    pub fn from_bits(bits: &[bool]) -> Self {
        let mut data = vec![0u8; bits.len().div_ceil(8)];
        for (i, &b) in bits.iter().enumerate() {
            if b {
                data[i / 8] |= 0x80 >> (i % 8);
            }
        }
        Self {
            data,
            bit_len: bits.len(),
        }
    }

    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    pub fn is_empty(&self) -> bool {
        self.bit_len == 0
    }

    /// The octets, with unused trailing bits zero.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Bit `i` (0 = most significant bit of the first octet); `None` if out of range.
    pub fn get(&self, i: usize) -> Option<bool> {
        (i < self.bit_len).then(|| self.data[i / 8] & (0x80 >> (i % 8)) != 0)
    }
}

impl fmt::Debug for BitString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitString<")?;
        for i in 0..self.bit_len {
            f.write_str(if self.get(i) == Some(true) { "1" } else { "0" })?;
        }
        write!(f, ">")
    }
}
