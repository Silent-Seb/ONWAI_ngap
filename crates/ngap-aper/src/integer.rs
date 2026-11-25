//! INTEGER encodings (X.691 clauses 10.5 - 10.8, 11.5 - 11.6) and length determinants (10.9, 11.9).

use crate::error::{ErrorKind, Result};
use crate::{BitReader, BitWriter};

/// Fragment unit of a length determinant: 16K items.
pub(crate) const FRAGMENT: usize = 16384;

/// Number of bits needed to represent `v` (0 for 0).
fn bits_for(v: u128) -> u32 {
    128 - v.leading_zeros()
}

/// Number of octets needed to represent `v` (0 for 0).
fn octets_for(v: u128) -> usize {
    bits_for(v).div_ceil(8) as usize
}

/// A decoded unconstrained length determinant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LengthDet {
    /// The final (or only) chunk of `n` items.
    Final(usize),
    /// A fragment of `n` items (a multiple of 16K); another length determinant follows its items.
    Fragment(usize),
}

impl BitWriter {
    /// Constrained whole number `lo..=hi` (clause 11.5, ALIGNED variant). Range limits are `i128`.
    pub fn write_constrained_int(&mut self, v: i128, lo: i128, hi: i128) -> Result<()> {
        if lo > hi || v < lo || v > hi {
            return Err(self.error(ErrorKind::ValueOutOfRange));
        }
        let range = (hi - lo) as u128 + 1;
        let off = (v - lo) as u128;
        match range {
            1 => {}
            2..=255 => self.write_bits(off as u64, bits_for(range - 1)),
            256 => {
                self.align();
                self.write_bits(off as u64, 8);
            }
            257..=65536 => {
                self.align();
                self.write_bits(off as u64, 16);
            }
            _ => {
                // "indefinite length" case: number of octets as a constrained length, then the octets
                let max_octets = octets_for(range - 1);
                let n = octets_for(off).max(1);
                self.write_constrained_int((n - 1) as i128, 0, (max_octets - 1) as i128)?;
                self.align();
                self.write_octets(&off.to_be_bytes()[16 - n..]);
            }
        }
        Ok(())
    }

    /// INTEGER with an extensible constraint `(lo..hi, ...)`: extension bit, then the value as a constrained
    /// whole number if it is inside the root, else as an unconstrained integer.
    pub fn write_ext_constrained_int(&mut self, v: i128, lo: i128, hi: i128) -> Result<()> {
        let outside = v < lo || v > hi;
        self.write_bit(outside);
        if outside {
            self.write_unconstrained_int(v)
        } else {
            self.write_constrained_int(v, lo, hi)
        }
    }

    /// Unconstrained whole number: length determinant + minimal two's-complement octets (clause 10.8).
    pub fn write_unconstrained_int(&mut self, v: i128) -> Result<()> {
        let bytes = v.to_be_bytes();
        let mut start = 0;
        while start < 15 {
            let (a, b) = (bytes[start], bytes[start + 1]);
            if (a == 0x00 && b & 0x80 == 0) || (a == 0xFF && b & 0x80 != 0) {
                start += 1;
            } else {
                break;
            }
        }
        self.write_unconstrained_length(16 - start)?;
        self.write_octets(&bytes[start..]);
        Ok(())
    }

    /// Semi-constrained whole number `v >= lb`: length determinant + minimal unsigned octets (clause 10.7).
    pub fn write_semi_constrained_int(&mut self, v: i128, lb: i128) -> Result<()> {
        if v < lb {
            return Err(self.error(ErrorKind::ValueOutOfRange));
        }
        let off = (v - lb) as u128;
        let n = octets_for(off).max(1);
        self.write_unconstrained_length(n)?;
        self.write_octets(&off.to_be_bytes()[16 - n..]);
        Ok(())
    }

    /// Normally small non-negative whole number (clause 11.6): used for extension indices.
    pub fn write_normally_small(&mut self, n: u64) -> Result<()> {
        if n < 64 {
            self.write_bit(false);
            self.write_bits(n, 6);
            Ok(())
        } else {
            self.write_bit(true);
            self.write_semi_constrained_int(i128::from(n), 0)
        }
    }

    /// Normally small length `n >= 1` (clause 11.9.3.4): number of extension additions.
    pub(crate) fn write_normally_small_length(&mut self, n: usize) -> Result<()> {
        if n <= 64 {
            self.write_bit(false);
            self.write_bits((n - 1) as u64, 6);
            Ok(())
        } else {
            self.write_bit(true);
            self.write_unconstrained_length(n)
        }
    }

    /// Unconstrained length determinant for `n < 16384` (clause 10.9.3.5/6), octet-aligned.
    pub(crate) fn write_unconstrained_length(&mut self, n: usize) -> Result<()> {
        self.align();
        if n < 128 {
            self.write_bits(n as u64, 8);
        } else if n < FRAGMENT {
            self.write_bits(0x8000 | n as u64, 16);
        } else {
            return Err(self.error(ErrorKind::SizeOutOfRange));
        }
        Ok(())
    }
}

impl<'a> BitReader<'a> {
    /// Constrained whole number `lo..=hi`.
    pub fn read_constrained_int(&mut self, lo: i128, hi: i128) -> Result<i128> {
        if lo > hi {
            return Err(self.error(ErrorKind::ValueOutOfRange));
        }
        let range = (hi - lo) as u128 + 1;
        let off: u128 = match range {
            1 => 0,
            2..=255 => u128::from(self.read_bits(bits_for(range - 1))?),
            256 => {
                self.align()?;
                u128::from(self.read_bits(8)?)
            }
            257..=65536 => {
                self.align()?;
                u128::from(self.read_bits(16)?)
            }
            _ => {
                let max_octets = octets_for(range - 1);
                let n = self.read_constrained_int(0, (max_octets - 1) as i128)? as usize + 1;
                self.align()?;
                let mut v = 0u128;
                for &b in self.read_octets(n)?.iter() {
                    v = (v << 8) | u128::from(b);
                }
                v
            }
        };
        if off >= range {
            return Err(self.error(ErrorKind::ValueOutOfRange));
        }
        Ok(lo + off as i128)
    }

    /// Counterpart of [`BitWriter::write_ext_constrained_int`].
    pub fn read_ext_constrained_int(&mut self, lo: i128, hi: i128) -> Result<i128> {
        if self.read_bit()? {
            self.read_unconstrained_int()
        } else {
            self.read_constrained_int(lo, hi)
        }
    }

    pub fn read_unconstrained_int(&mut self) -> Result<i128> {
        let n = self.read_single_length()?;
        if n == 0 || n > 16 {
            return Err(self.error(if n == 0 {
                ErrorKind::InvalidLength
            } else {
                ErrorKind::IntegerOverflow
            }));
        }
        let bytes = self.read_octets(n)?;
        let mut v: i128 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in bytes.iter() {
            v = (v << 8) | i128::from(b);
        }
        Ok(v)
    }

    pub fn read_semi_constrained_int(&mut self, lb: i128) -> Result<i128> {
        let n = self.read_single_length()?;
        if n == 0 || n > 16 {
            return Err(self.error(if n == 0 {
                ErrorKind::InvalidLength
            } else {
                ErrorKind::IntegerOverflow
            }));
        }
        let mut v = 0u128;
        for &b in self.read_octets(n)?.iter() {
            v = (v << 8) | u128::from(b);
        }
        i128::try_from(v)
            .ok()
            .and_then(|o| lb.checked_add(o))
            .ok_or_else(|| self.error(ErrorKind::IntegerOverflow))
    }

    pub fn read_normally_small(&mut self) -> Result<u64> {
        if !self.read_bit()? {
            self.read_bits(6)
        } else {
            let v = self.read_semi_constrained_int(0)?;
            u64::try_from(v).map_err(|_| self.error(ErrorKind::IntegerOverflow))
        }
    }

    /// Counterpart of `write_normally_small_length`.
    pub(crate) fn read_normally_small_length(&mut self) -> Result<usize> {
        if !self.read_bit()? {
            Ok(self.read_bits(6)? as usize + 1)
        } else {
            self.read_single_length()
        }
    }

    /// An unconstrained length determinant that must not be a fragment.
    fn read_single_length(&mut self) -> Result<usize> {
        match self.read_length_det()? {
            LengthDet::Final(n) => Ok(n),
            LengthDet::Fragment(_) => Err(self.error(ErrorKind::InvalidLength)),
        }
    }

    /// Unconstrained length determinant (clause 10.9.3.5 - 10.9.3.8), octet-aligned.
    pub(crate) fn read_length_det(&mut self) -> Result<LengthDet> {
        self.align()?;
        let b0 = self.read_bits(8)? as usize;
        if b0 & 0x80 == 0 {
            Ok(LengthDet::Final(b0))
        } else if b0 & 0x40 == 0 {
            Ok(LengthDet::Final(
                ((b0 & 0x3F) << 8) | self.read_bits(8)? as usize,
            ))
        } else {
            let m = b0 & 0x3F;
            if (1..=4).contains(&m) {
                Ok(LengthDet::Fragment(m * FRAGMENT))
            } else {
                Err(self.error(ErrorKind::InvalidLength))
            }
        }
    }
}

/// The value constraint of an INTEGER type, as the generated code states it. Drives [`BitWriter::write_int`] /
/// [`BitReader::read_int`] so each generated type needs one line of code instead of the whole constraint logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntSpec {
    /// Lower bound of the root (`None`: unbounded).
    pub lb: Option<i128>,
    /// Upper bound of the root (`None`: unbounded).
    pub ub: Option<i128>,
    /// `(lb..ub, ...)`: the constraint has an extension marker.
    pub extensible: bool,
    /// The root as a union of ranges when it has gaps (`1..30|40|181`); empty means all of `lb..=ub`.
    pub ranges: &'static [(i128, i128)],
    /// Ranges defined after the extension marker; values outside the root are valid only inside these.
    pub additions: &'static [(i128, i128)],
}

impl IntSpec {
    /// No constraint at all.
    pub const UNCONSTRAINED: IntSpec = IntSpec {
        lb: None,
        ub: None,
        extensible: false,
        ranges: &[],
        additions: &[],
    };

    /// `(lb..ub)`.
    pub const fn range(lb: i128, ub: i128) -> IntSpec {
        IntSpec {
            lb: Some(lb),
            ub: Some(ub),
            extensible: false,
            ranges: &[],
            additions: &[],
        }
    }

    /// `(lb..MAX)`.
    pub const fn semi(lb: i128) -> IntSpec {
        IntSpec {
            lb: Some(lb),
            ub: None,
            extensible: false,
            ranges: &[],
            additions: &[],
        }
    }

    /// Add the extension marker.
    pub const fn extensible(self) -> IntSpec {
        IntSpec {
            extensible: true,
            ..self
        }
    }

    /// The root has gaps: only the listed ranges are valid.
    pub const fn with_ranges(self, ranges: &'static [(i128, i128)]) -> IntSpec {
        IntSpec { ranges, ..self }
    }

    /// Ranges defined after the extension marker.
    pub const fn with_additions(self, additions: &'static [(i128, i128)]) -> IntSpec {
        IntSpec { additions, ..self }
    }

    fn in_root(&self, v: i128) -> bool {
        if !self.ranges.is_empty() {
            return self.ranges.iter().any(|&(a, b)| (a..=b).contains(&v));
        }
        self.lb.is_none_or(|lb| v >= lb) && self.ub.is_none_or(|ub| v <= ub)
    }

    fn in_additions(&self, v: i128) -> bool {
        self.additions.iter().any(|&(a, b)| (a..=b).contains(&v))
    }
}

impl BitWriter {
    /// Encode an INTEGER with the constraint `spec`. A value outside the defined values is an error.
    pub fn write_int(&mut self, v: i128, spec: &IntSpec) -> Result<()> {
        if spec.extensible {
            if spec.in_root(v) {
                self.write_bit(false);
                self.write_root_int(v, spec)
            } else if spec.in_additions(v) {
                self.write_bit(true);
                self.write_unconstrained_int(v)
            } else {
                Err(self.error(ErrorKind::ValueOutOfRange))
            }
        } else if spec.in_root(v) {
            self.write_root_int(v, spec)
        } else {
            Err(self.error(ErrorKind::ValueOutOfRange))
        }
    }

    fn write_root_int(&mut self, v: i128, spec: &IntSpec) -> Result<()> {
        match (spec.lb, spec.ub) {
            (Some(lb), Some(ub)) => self.write_constrained_int(v, lb, ub),
            (Some(lb), None) => self.write_semi_constrained_int(v, lb),
            (None, _) => self.write_unconstrained_int(v),
        }
    }
}

impl<'a> BitReader<'a> {
    /// Decode an INTEGER with the constraint `spec`.
    pub fn read_int(&mut self, spec: &IntSpec) -> Result<i128> {
        let v = if spec.extensible && self.read_bit()? {
            let v = self.read_unconstrained_int()?;
            if !spec.in_additions(v) {
                return Err(self.error(ErrorKind::ValueOutOfRange));
            }
            return Ok(v);
        } else {
            match (spec.lb, spec.ub) {
                (Some(lb), Some(ub)) => self.read_constrained_int(lb, ub)?,
                (Some(lb), None) => self.read_semi_constrained_int(lb)?,
                (None, _) => self.read_unconstrained_int()?,
            }
        };
        if spec.in_root(v) {
            Ok(v)
        } else {
            Err(self.error(ErrorKind::ValueOutOfRange))
        }
    }

    /// [`read_int`](Self::read_int) converted to a Rust integer type (`ValueOutOfRange` if it does not fit).
    pub fn read_int_as<T: TryFrom<i128>>(&mut self, spec: &IntSpec) -> Result<T> {
        let v = self.read_int(spec)?;
        T::try_from(v).map_err(|_| self.error(ErrorKind::ValueOutOfRange))
    }
}
