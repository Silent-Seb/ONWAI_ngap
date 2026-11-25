//! Error type shared by the encoder and decoder.

use core::fmt;

use crate::ie::Criticality;

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input ended before the value was complete.
    UnexpectedEof,
    /// An INTEGER is outside its (root) constraint, or an index is outside its range.
    ValueOutOfRange,
    /// A length / element count is outside its SIZE constraint.
    SizeOutOfRange,
    /// A length determinant is malformed (e.g. fragment multiplier 0 or > 4).
    InvalidLength,
    /// An ENUMERATED / CHOICE index that is not defined (including unknown extension additions).
    InvalidIndex(u64),
    /// A character outside the permitted alphabet of a restricted character string.
    InvalidCharacter,
    /// A UTF8String that is not valid UTF-8.
    InvalidUtf8,
    /// A malformed OBJECT IDENTIFIER.
    InvalidObjectIdentifier,
    /// A malformed bit string value (data length does not match the bit length).
    InvalidBitString,
    /// An integer does not fit the supported width (i128 / u64).
    IntegerOverflow,
    /// Whole octets are left over after decoding a complete encoding.
    TrailingData,
    /// A mandatory IE of an NGAP message is missing (abstract syntax error, X.413 10.3.5); carries the IE's
    /// criticality so the caller can pick the reaction.
    MissingIe { id: u32, criticality: Criticality },
    /// The same IE appears twice in a message (abstract syntax error, 10.3.6).
    DuplicateIe { id: u32 },
    /// The procedure code of a PDU is not defined (10.3.4.1); carries the criticality the sender gave it.
    UnknownProcedure { code: u16, criticality: Criticality },
}

/// An APER encoding or decoding error with the bit offset at which it was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AperError {
    pub kind: ErrorKind,
    /// Offset in bits from the start of the buffer being read or written.
    pub bit_offset: usize,
}

impl AperError {
    pub fn new(kind: ErrorKind, bit_offset: usize) -> Self {
        Self { kind, bit_offset }
    }
}

impl fmt::Display for AperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "APER error at bit {}: ", self.bit_offset)?;
        match &self.kind {
            ErrorKind::UnexpectedEof => f.write_str("unexpected end of input"),
            ErrorKind::ValueOutOfRange => f.write_str("value out of range"),
            ErrorKind::SizeOutOfRange => f.write_str("size out of range"),
            ErrorKind::InvalidLength => f.write_str("invalid length determinant"),
            ErrorKind::InvalidIndex(i) => write!(f, "undefined enumeration/choice index {i}"),
            ErrorKind::InvalidCharacter => f.write_str("character outside the permitted alphabet"),
            ErrorKind::InvalidUtf8 => f.write_str("invalid UTF-8"),
            ErrorKind::InvalidObjectIdentifier => f.write_str("invalid OBJECT IDENTIFIER"),
            ErrorKind::InvalidBitString => f.write_str("invalid bit string value"),
            ErrorKind::IntegerOverflow => f.write_str("integer too large"),
            ErrorKind::TrailingData => f.write_str("trailing data after the encoded value"),
            ErrorKind::MissingIe { id, criticality } => write!(
                f,
                "mandatory IE {id} is missing (criticality {criticality:?})"
            ),
            ErrorKind::DuplicateIe { id } => write!(f, "IE {id} appears more than once"),
            ErrorKind::UnknownProcedure { code, criticality } => write!(
                f,
                "unknown procedure code {code} (criticality {criticality:?})"
            ),
        }
    }
}

impl std::error::Error for AperError {}

/// `Result` with [`AperError`].
pub type Result<T> = core::result::Result<T, AperError>;
