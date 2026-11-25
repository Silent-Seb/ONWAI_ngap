//! SIZE constraints and the generic "counted field" engine shared by BIT STRING, OCTET STRING, restricted
//! character strings and SEQUENCE OF (X.691 clauses 10.9, 16, 17, 19, 30).

use crate::error::{ErrorKind, Result};
use crate::integer::{FRAGMENT, LengthDet};
use crate::{BitReader, BitWriter};

/// A SIZE constraint `(SIZE(lb..ub[, ...]))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub lb: u64,
    /// `None`: no upper bound.
    pub ub: Option<u64>,
    /// The constraint is extensible (`...`): lengths outside `lb..=ub` are allowed.
    pub ext: bool,
}

impl Size {
    /// No SIZE constraint.
    pub const UNBOUNDED: Size = Size {
        lb: 0,
        ub: None,
        ext: false,
    };

    /// `SIZE(n)`.
    pub const fn fixed(n: u64) -> Size {
        Size {
            lb: n,
            ub: Some(n),
            ext: false,
        }
    }

    /// `SIZE(lb..ub)`.
    pub const fn range(lb: u64, ub: u64) -> Size {
        Size {
            lb,
            ub: Some(ub),
            ext: false,
        }
    }

    /// Mark the constraint extensible: `SIZE(..., ...)`.
    pub const fn extensible(self) -> Size {
        Size { ext: true, ..self }
    }

    pub(crate) fn root_contains(&self, n: u64) -> bool {
        n >= self.lb && self.ub.is_none_or(|ub| n <= ub)
    }

    /// Upper bound below 64K: the length is a constrained whole number rather than an unconstrained determinant.
    fn bounded(&self) -> Option<u64> {
        self.ub.filter(|&ub| ub < 65536)
    }
}

/// What a counted field counts; decides alignment (X.691 16.x, 17.x, 19.x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unit {
    Octets,
    Bits,
    Items,
}

impl Unit {
    /// A fixed-size field is octet-aligned only when it is larger than 2 octets / 16 bits; items never are.
    fn fixed_is_aligned(self, n: u64) -> bool {
        match self {
            Unit::Octets => n > 2,
            Unit::Bits => n > 16,
            Unit::Items => false,
        }
    }

    /// Variable-size content is octet-aligned after its length (even when empty), except items.
    fn variable_is_aligned(self) -> bool {
        self != Unit::Items
    }
}

impl BitWriter {
    /// Write the length of a counted field and call `emit(writer, start, count)` once per fragment.
    pub(crate) fn write_counted<F>(
        &mut self,
        n: usize,
        size: Size,
        unit: Unit,
        mut emit: F,
    ) -> Result<()>
    where
        F: FnMut(&mut BitWriter, usize, usize) -> Result<()>,
    {
        // extension bit of an extensible size constraint: outside the root => treated as unconstrained
        let eff = if size.ext {
            let outside = !size.root_contains(n as u64);
            self.write_bit(outside);
            if outside {
                Size::UNBOUNDED
            } else {
                Size { ext: false, ..size }
            }
        } else if size.root_contains(n as u64) {
            size
        } else {
            return Err(self.error(ErrorKind::SizeOutOfRange));
        };

        if let Some(ub) = eff.bounded() {
            if eff.lb == ub {
                if n == 0 {
                    return Ok(());
                }
                if unit.fixed_is_aligned(ub) {
                    self.align();
                }
            } else {
                self.write_constrained_int(n as i128, i128::from(eff.lb), i128::from(ub))?;
                if unit.variable_is_aligned() {
                    self.align();
                }
            }
            return emit(self, 0, n);
        }

        // unconstrained length: 16K-multiple fragments, then a final length (possibly 0)
        let mut start = 0;
        loop {
            let remaining = n - start;
            if remaining >= FRAGMENT {
                let m = (remaining / FRAGMENT).min(4);
                self.align();
                self.write_bits(0xC0 | m as u64, 8);
                emit(self, start, m * FRAGMENT)?;
                start += m * FRAGMENT;
            } else {
                self.write_unconstrained_length(remaining)?;
                return emit(self, start, remaining);
            }
        }
    }
}

impl<'a> BitReader<'a> {
    /// Read the length of a counted field and call `consume(reader, count)` once per fragment; returns the total.
    pub(crate) fn read_counted<F>(
        &mut self,
        size: Size,
        unit: Unit,
        mut consume: F,
    ) -> Result<usize>
    where
        F: FnMut(&mut BitReader<'a>, usize) -> Result<()>,
    {
        let outside = size.ext && self.read_bit()?;
        let eff = if outside {
            Size::UNBOUNDED
        } else {
            Size { ext: false, ..size }
        };

        if let Some(ub) = eff.bounded() {
            let n = if eff.lb == ub {
                if ub == 0 {
                    return Ok(0);
                }
                if unit.fixed_is_aligned(ub) {
                    self.align()?;
                }
                ub as usize
            } else {
                let n = self.read_constrained_int(i128::from(eff.lb), i128::from(ub))? as usize;
                if unit.variable_is_aligned() {
                    self.align()?;
                }
                n
            };
            consume(self, n)?;
            return Ok(n);
        }

        let mut total = 0usize;
        loop {
            match self.read_length_det()? {
                LengthDet::Fragment(c) => {
                    consume(self, c)?;
                    total += c;
                }
                LengthDet::Final(c) => {
                    consume(self, c)?;
                    total += c;
                    break;
                }
            }
        }
        if !outside && !size.root_contains(total as u64) {
            return Err(self.error(ErrorKind::SizeOutOfRange));
        }
        Ok(total)
    }
}
