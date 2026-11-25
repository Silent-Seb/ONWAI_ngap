//! Helpers for CHOICE / ENUMERATED indices, SEQUENCE extension additions, open types and SEQUENCE OF.

use crate::error::{ErrorKind, Result};
use crate::size::{Size, Unit};
use crate::{BitReader, BitWriter};

/// Most elements of a SEQUENCE OF whose elements occupy zero bits that the decoder accepts.
const MAX_ZERO_SIZE_ITEMS: usize = 65535;

impl BitWriter {
    /// Index of a CHOICE alternative or ENUMERATED value. Root indices are `0..root_count`; an extension addition
    /// `k` (0-based) is passed as `root_count + k`. If `extensible`, the extension bit is written first.
    pub fn write_index(&mut self, index: u64, root_count: u64, extensible: bool) -> Result<()> {
        if root_count == 0 {
            return Err(self.error(ErrorKind::ValueOutOfRange));
        }
        let in_ext = index >= root_count;
        if extensible {
            self.write_bit(in_ext);
        } else if in_ext {
            return Err(self.error(ErrorKind::InvalidIndex(index)));
        }
        if in_ext {
            self.write_normally_small(index - root_count)
        } else {
            self.write_constrained_int(i128::from(index), 0, i128::from(root_count) - 1)
        }
    }

    /// Present extension additions of a SEQUENCE, after the root components (and after the extension bit was
    /// written as 1). `additions[i]` is the *complete encoding* of addition `i`, or `None` if absent. All
    /// additions known to the sender's version must be listed (the bitmap has one bit per addition).
    pub fn write_extension_additions(&mut self, additions: &[Option<Vec<u8>>]) -> Result<()> {
        if additions.is_empty() {
            return Err(self.error(ErrorKind::SizeOutOfRange));
        }
        self.write_normally_small_length(additions.len())?;
        for a in additions {
            self.write_bit(a.is_some());
        }
        for a in additions.iter().flatten() {
            self.write_open_type(a)?;
        }
        Ok(())
    }

    /// An open type: the complete encoding of a value, as an octet string with unconstrained length.
    pub fn write_open_type(&mut self, complete_encoding: &[u8]) -> Result<()> {
        if complete_encoding.is_empty() {
            return self.write_octet_string(&[0], Size::UNBOUNDED);
        }
        self.write_octet_string(complete_encoding, Size::UNBOUNDED)
    }

    /// SEQUENCE OF with the given SIZE constraint; `f` encodes one element.
    pub fn write_seq_of<T>(
        &mut self,
        items: &[T],
        size: Size,
        mut f: impl FnMut(&mut BitWriter, &T) -> Result<()>,
    ) -> Result<()> {
        self.write_counted(items.len(), size, Unit::Items, |w, start, count| {
            for item in &items[start..start + count] {
                f(w, item)?;
            }
            Ok(())
        })
    }
}

impl<'a> BitReader<'a> {
    /// Counterpart of [`BitWriter::write_index`]; returns `root_count + k` for extension addition `k`.
    /// The caller rejects indices it does not define.
    pub fn read_index(&mut self, root_count: u64, extensible: bool) -> Result<u64> {
        if root_count == 0 {
            return Err(self.error(ErrorKind::ValueOutOfRange));
        }
        if extensible && self.read_bit()? {
            let k = self.read_normally_small()?;
            root_count
                .checked_add(k)
                .ok_or_else(|| self.error(ErrorKind::IntegerOverflow))
        } else {
            Ok(self.read_constrained_int(0, i128::from(root_count) - 1)? as u64)
        }
    }

    /// Counterpart of [`BitWriter::write_extension_additions`]: one entry per addition in the sender's bitmap,
    /// each the complete encoding of a present addition (decode it with a new `BitReader`).
    pub fn read_extension_additions(&mut self) -> Result<Vec<Option<Vec<u8>>>> {
        let n = self.read_normally_small_length()?;
        if n > self.remaining_bits() {
            return Err(self.error(ErrorKind::UnexpectedEof));
        }
        let mut present = Vec::with_capacity(n);
        for _ in 0..n {
            present.push(self.read_bit()?);
        }
        let mut out = Vec::with_capacity(n);
        for p in present {
            out.push(if p {
                Some(self.read_open_type()?)
            } else {
                None
            });
        }
        Ok(out)
    }

    /// An open type: returns the octets of the complete encoding.
    ///
    /// The complete encoding of a value is at least one octet (X.691 11.2: an empty encoding is sent as a single
    /// zero octet), so a length of 0 is an error.
    pub fn read_open_type(&mut self) -> Result<Vec<u8>> {
        let content = self.read_octet_string(Size::UNBOUNDED)?;
        if content.is_empty() {
            return Err(self.error(ErrorKind::InvalidLength));
        }
        Ok(content)
    }

    /// SEQUENCE OF with the given SIZE constraint; `f` decodes one element.
    pub fn read_seq_of<T>(
        &mut self,
        size: Size,
        mut f: impl FnMut(&mut BitReader<'a>) -> Result<T>,
    ) -> Result<Vec<T>> {
        let mut out: Vec<T> = Vec::new();
        self.read_counted(size, Unit::Items, |r, count| {
            out.reserve(count.min(1024));
            for _ in 0..count {
                let before = r.bit_position();
                out.push(f(r)?);
                // Zero-bit elements (NULL, single-valued types) cost no input, so bound them to avoid a
                // CPU/memory amplification through chained fragment headers.
                if r.bit_position() == before && out.len() > MAX_ZERO_SIZE_ITEMS {
                    return Err(r.error(ErrorKind::SizeOutOfRange));
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
}
