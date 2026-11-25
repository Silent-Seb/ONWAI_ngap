//! The 3GPP "protocol IE" machinery shared by all XxAP protocols: criticality, IE fields, IE containers, and the
//! procedure wrapper of the PDU. The generated `ngap-types` crate calls these; the layouts follow the
//! `NGAP-Containers` and `NGAP-PDU-Descriptions` modules of TS 38.413.

use crate::error::{ErrorKind, Result};
use crate::size::Size;
use crate::traits::{AperDecode, AperEncode, from_slice, to_vec};
use crate::{BitReader, BitWriter};

/// `Criticality ::= ENUMERATED { reject, ignore, notify }` (NGAP-CommonDataTypes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Criticality {
    Reject,
    Ignore,
    Notify,
}

impl AperEncode for Criticality {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        w.write_index(*self as u64, 3, false)
    }
}

impl AperDecode for Criticality {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        Ok(match r.read_index(3, false)? {
            0 => Criticality::Reject,
            1 => Criticality::Ignore,
            _ => Criticality::Notify,
        })
    }
}

/// One IE of a message as it is on the wire: `SEQUENCE { id ProtocolIE-ID, criticality, value OPEN TYPE }`.
///
/// Messages keep the IEs they do not know (unknown id) in this form, so nothing is lost when a message is
/// forwarded or re-encoded, and the receiver can apply the criticality rules of clause 10.3.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIe {
    pub id: u32,
    pub criticality: Criticality,
    /// The complete APER encoding of the IE's value.
    pub content: Vec<u8>,
}

impl RawIe {
    /// An IE holding `value`.
    pub fn new<T: AperEncode>(id: u32, criticality: Criticality, value: &T) -> Result<RawIe> {
        Ok(RawIe {
            id,
            criticality,
            content: to_vec(value)?,
        })
    }

    /// An IE whose value is written by `f`.
    pub fn with(
        id: u32,
        criticality: Criticality,
        f: impl FnOnce(&mut BitWriter) -> Result<()>,
    ) -> Result<RawIe> {
        let mut w = BitWriter::new();
        f(&mut w)?;
        Ok(RawIe {
            id,
            criticality,
            content: w.into_complete_bytes(),
        })
    }

    /// Decode the value as `T`.
    pub fn decode<T: AperDecode>(&self) -> Result<T> {
        from_slice(&self.content)
    }

    /// Decode the value with `f`; whole octets left over are an error.
    pub fn decode_with<T>(&self, f: impl FnOnce(&mut BitReader<'_>) -> Result<T>) -> Result<T> {
        let mut r = BitReader::new(&self.content);
        let v = f(&mut r)?;
        if r.remaining_bits() >= 8 {
            return Err(r.error(ErrorKind::TrailingData));
        }
        Ok(v)
    }
}

/// A single IE field (`ProtocolIE-SingleContainer`, the `choice-Extensions` alternative): id 0..65535, criticality,
/// open type.
impl AperEncode for RawIe {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        w.write_constrained_int(i128::from(self.id), 0, 65535)?;
        self.criticality.aper_encode(w)?;
        w.write_open_type(&self.content)
    }
}

impl AperDecode for RawIe {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        let id = r.read_constrained_int(0, 65535)? as u32;
        let criticality = Criticality::aper_decode(r)?;
        let content = r.read_open_type()?;
        Ok(RawIe {
            id,
            criticality,
            content,
        })
    }
}

/// `ProtocolIE-Container`: a list of IE fields with the given SIZE constraint.
pub fn write_container(w: &mut BitWriter, size: Size, ies: &[RawIe]) -> Result<()> {
    w.write_seq_of(ies, size, |w, ie| ie.aper_encode(w))
}

/// Counterpart of [`write_container`].
pub fn read_container(r: &mut BitReader<'_>, size: Size) -> Result<Vec<RawIe>> {
    r.read_seq_of(size, RawIe::aper_decode)
}

/// The ids of the IEs of an encoded message (`SEQUENCE { protocolIEs ProtocolIE-Container, ... }`), in the order
/// received. `extensible` says whether the message type has an extension marker.
pub fn wire_ie_ids(content: &[u8], extensible: bool, size: Size) -> Result<Vec<u32>> {
    let mut r = BitReader::new(content);
    if extensible {
        r.read_bit()?;
    }
    Ok(read_container(&mut r, size)?
        .into_iter()
        .map(|ie| ie.id)
        .collect())
}

/// Store `value` in an IE slot; a second occurrence of the same IE is an error (10.3.6).
pub fn set_once<T>(slot: &mut Option<T>, id: u32, value: T) -> Result<()> {
    if slot.is_some() {
        return Err(crate::AperError::new(ErrorKind::DuplicateIe { id }, 0));
    }
    *slot = Some(value);
    Ok(())
}

/// Unwrap a mandatory IE; absence is an error carrying the IE's criticality (10.3.5).
pub fn required<T>(slot: Option<T>, id: u32, criticality: Criticality) -> Result<T> {
    slot.ok_or_else(|| crate::AperError::new(ErrorKind::MissingIe { id, criticality }, 0))
}

/// The members of an extension container (`iE-Extensions`) that this version of the spec defines no type for.
/// Whatever arrives is kept as raw IEs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnknownIes {
    pub ies: Vec<RawIe>,
}

/// The procedure wrapper of the PDU: `SEQUENCE { procedureCode ProcedureCode (0..255), criticality, value OPEN TYPE }`.
pub fn write_procedure<T: AperEncode>(
    w: &mut BitWriter,
    code: u16,
    criticality: Criticality,
    message: &T,
) -> Result<()> {
    w.write_constrained_int(i128::from(code), 0, 255)?;
    criticality.aper_encode(w)?;
    w.write_open_type(&to_vec(message)?)
}

/// Counterpart of [`write_procedure`]: the procedure code, its criticality and the message's encoding.
pub fn read_procedure(r: &mut BitReader<'_>) -> Result<(u16, Criticality, Vec<u8>)> {
    let code = r.read_constrained_int(0, 255)? as u16;
    let criticality = Criticality::aper_decode(r)?;
    Ok((code, criticality, r.read_open_type()?))
}

/// Decode the message contained in a procedure wrapper.
pub fn decode_message<T: AperDecode>(content: &[u8]) -> Result<T> {
    from_slice(content)
}
