//! Traits implemented by the generated types, and whole-value helpers.

use crate::error::{AperError, ErrorKind, Result};
use crate::{BitReader, BitWriter};

/// A type that can be written as APER.
pub trait AperEncode {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()>;
}

/// A type that can be read from APER.
pub trait AperDecode: Sized {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self>;
}

/// The *complete encoding* of a value (X.691 10.1): padded to octets, at least one octet.
pub fn to_vec<T: AperEncode>(value: &T) -> Result<Vec<u8>> {
    let mut w = BitWriter::new();
    value.aper_encode(&mut w)?;
    Ok(w.into_complete_bytes())
}

/// Decode a complete encoding. Padding bits of the last octet are ignored; any whole octet left over is an error.
pub fn from_slice<T: AperDecode>(data: &[u8]) -> Result<T> {
    let mut r = BitReader::new(data);
    let v = T::aper_decode(&mut r)?;
    if r.remaining_bits() >= 8 {
        return Err(AperError::new(ErrorKind::TrailingData, r.bit_position()));
    }
    Ok(v)
}
