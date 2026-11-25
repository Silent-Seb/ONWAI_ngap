//! BIT STRING, OCTET STRING and character string encodings (X.691 clauses 16, 17, 30).

use crate::bitstring::BitString;
use crate::error::{ErrorKind, Result};
use crate::size::{Size, Unit};
use crate::{BitReader, BitWriter};

/// Known-multiplier character string types NGAP uses. In ALIGNED PER both use 8 bits per character, so they are
/// encoded like an OCTET STRING of the character codes, after checking the permitted alphabet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharSet {
    /// `PrintableString`: A-Z a-z 0-9 space ' ( ) + , - . / : = ?
    Printable,
    /// `VisibleString`: the graphic characters 0x20..=0x7E.
    Visible,
}

impl CharSet {
    fn allows(self, b: u8) -> bool {
        match self {
            CharSet::Visible => (0x20..=0x7E).contains(&b),
            CharSet::Printable => {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b' ' | b'\''
                            | b'('
                            | b')'
                            | b'+'
                            | b','
                            | b'-'
                            | b'.'
                            | b'/'
                            | b':'
                            | b'='
                            | b'?'
                    )
            }
        }
    }
}

impl BitWriter {
    /// OCTET STRING with the given SIZE constraint.
    pub fn write_octet_string(&mut self, data: &[u8], size: Size) -> Result<()> {
        self.write_counted(data.len(), size, Unit::Octets, |w, start, count| {
            w.write_octets(&data[start..start + count]);
            Ok(())
        })
    }

    /// BIT STRING with the given SIZE constraint.
    pub fn write_bit_string(&mut self, bits: &BitString, size: Size) -> Result<()> {
        let data = bits.as_bytes();
        let total = bits.bit_len();
        self.write_counted(total, size, Unit::Bits, |w, start, count| {
            // fragments start on multiples of 16K bits, so `start` is octet-aligned in `data`
            let whole = count / 8;
            w.write_octets(&data[start / 8..start / 8 + whole]);
            let tail = (count % 8) as u32;
            if tail != 0 {
                w.write_bits(u64::from(data[start / 8 + whole] >> (8 - tail)), tail);
            }
            Ok(())
        })
    }

    /// PrintableString / VisibleString with the given SIZE constraint (counted in characters).
    pub fn write_char_string(&mut self, s: &str, size: Size, set: CharSet) -> Result<()> {
        if !s.bytes().all(|b| set.allows(b)) {
            return Err(self.error(ErrorKind::InvalidCharacter));
        }
        self.write_octet_string(s.as_bytes(), size)
    }

    /// UTF8String: its SIZE constraint is not PER-visible, so it is an octet string with an unconstrained length.
    pub fn write_utf8_string(&mut self, s: &str) -> Result<()> {
        self.write_octet_string(s.as_bytes(), Size::UNBOUNDED)
    }
}

impl<'a> BitReader<'a> {
    pub fn read_octet_string(&mut self, size: Size) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_counted(size, Unit::Octets, |r, count| {
            out.extend_from_slice(&r.read_octets(count)?);
            Ok(())
        })?;
        Ok(out)
    }

    pub fn read_bit_string(&mut self, size: Size) -> Result<BitString> {
        let mut out: Vec<u8> = Vec::new();
        let mut bits = 0usize;
        self.read_counted(size, Unit::Bits, |r, count| {
            // earlier fragments are multiples of 16K bits, so `out` is octet-aligned here
            let whole = count / 8;
            out.extend_from_slice(&r.read_octets(whole)?);
            let tail = (count % 8) as u32;
            if tail != 0 {
                out.push((r.read_bits(tail)? as u8) << (8 - tail));
            }
            bits += count;
            Ok(())
        })?;
        BitString::new(out, bits)
    }

    pub fn read_char_string(&mut self, size: Size, set: CharSet) -> Result<String> {
        let bytes = self.read_octet_string(size)?;
        if !bytes.iter().all(|&b| set.allows(b)) {
            return Err(self.error(ErrorKind::InvalidCharacter));
        }
        // all allowed characters are ASCII
        Ok(String::from_utf8(bytes).expect("ASCII"))
    }

    pub fn read_utf8_string(&mut self) -> Result<String> {
        let bytes = self.read_octet_string(Size::UNBOUNDED)?;
        String::from_utf8(bytes).map_err(|_| self.error(ErrorKind::InvalidUtf8))
    }
}
