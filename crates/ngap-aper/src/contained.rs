//! `OCTET STRING (CONTAINING T)`.

use core::fmt;
use core::marker::PhantomData;

use crate::error::Result;
use crate::size::Size;
use crate::traits::{AperDecode, AperEncode, from_slice, to_vec};
use crate::{BitReader, BitWriter};

/// An octet string that holds the complete APER encoding of a `T` (NGAP's N2 transfer containers).
///
/// The bytes are kept as received, so a node that only forwards the container never decodes or re-encodes it.
pub struct Contained<T> {
    raw: Vec<u8>,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Contained<T> {
    /// Wrap already-encoded bytes (not validated).
    pub fn from_raw(raw: Vec<u8>) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }
}

impl<T: AperEncode> Contained<T> {
    /// Encode `value` and wrap the result.
    pub fn encode_from(value: &T) -> Result<Self> {
        Ok(Self::from_raw(to_vec(value)?))
    }
}

impl<T: AperDecode> Contained<T> {
    /// Decode the contained value.
    pub fn decode(&self) -> Result<T> {
        from_slice(&self.raw)
    }
}

impl<T> AperEncode for Contained<T> {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        w.write_octet_string(&self.raw, Size::UNBOUNDED)
    }
}

impl<T> AperDecode for Contained<T> {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        Ok(Self::from_raw(r.read_octet_string(Size::UNBOUNDED)?))
    }
}

impl<T> Clone for Contained<T> {
    fn clone(&self) -> Self {
        Self::from_raw(self.raw.clone())
    }
}

impl<T> PartialEq for Contained<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<T> Eq for Contained<T> {}

impl<T> fmt::Debug for Contained<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Contained<{}>({} octets)",
            core::any::type_name::<T>(),
            self.raw.len()
        )
    }
}
