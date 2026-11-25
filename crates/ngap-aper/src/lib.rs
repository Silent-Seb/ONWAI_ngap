//! ASN.1 **ALIGNED PER** (ITU-T X.691) runtime for the NGAP codec.
//!
//! Hand-written; the generated `ngap-types` crate calls these primitives with the constraints of each ASN.1 type.
//!
//! * [`BitWriter`] / [`BitReader`]: bit-level I/O. Every encoder is a `write_*` method, every decoder a `read_*`
//!   method on these types.
//! * Integers: [`BitWriter::write_constrained_int`], `write_ext_constrained_int`, `write_unconstrained_int`,
//!   `write_semi_constrained_int`, `write_normally_small`.
//! * Strings: OCTET STRING, [`BitString`], PrintableString / VisibleString ([`CharSet`]), UTF8String, and
//!   [`ObjectIdentifier`], all with a [`Size`] constraint where applicable.
//! * Structure: CHOICE / ENUMERATED indices (`write_index`), SEQUENCE extension additions, open types,
//!   SEQUENCE OF (`write_seq_of`).
//! * [`ie`]: criticality, IE fields / containers and the procedure wrapper of the NGAP PDU.
//! * [`IntSpec`]: the constraint of an INTEGER type, for `write_int` / `read_int`.
//! * [`Contained`]: `OCTET STRING (CONTAINING T)` that can be forwarded without decoding.
//! * [`AperEncode`] / [`AperDecode`], [`to_vec`], [`from_slice`].
//!
//! Long fields use the X.691 16K fragmentation. Decoding never panics on malformed input; errors carry the bit
//! offset ([`AperError`]).

mod bitstring;
mod contained;
mod error;
pub mod ie;
mod integer;
mod oid;
mod reader;
mod seq;
mod size;
mod string;
mod traits;
mod writer;

pub use bitstring::BitString;
pub use contained::Contained;
pub use error::{AperError, ErrorKind, Result};
pub use integer::IntSpec;
pub use oid::ObjectIdentifier;
pub use reader::BitReader;
pub use size::Size;
pub use string::CharSet;
pub use traits::{AperDecode, AperEncode, from_slice, to_vec};
pub use writer::BitWriter;
