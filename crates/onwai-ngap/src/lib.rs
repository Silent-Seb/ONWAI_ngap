//! NGAP (3GPP TS 38.413 Rel-19) codec for the AMF side of N2.
//!
//! * [`decode_pdu`] turns the octets of an SCTP message into an [`NgapPdu`] and applies the **detectable** part of
//!   the error handling of clause 10: a failure is a [`DecodeError`] that says what the standard asks the receiver
//!   to do ([`DecodeError::reaction`]) and carries the data for the Error Indication / failure message
//!   ([`DecodeError::error_indication`], [`DecodeError::criticality_diagnostics`]).
//! * [`encode_pdu`] is the reverse.
//! * [`types`] holds every generated message and IE; [`Contained`] is `OCTET STRING (CONTAINING T)`, which is kept as
//!   raw octets so that N2 SM containers can be forwarded without being decoded.
//!
//! This crate is a codec: it sends nothing, keeps no state and does not know which procedures are ongoing.
//! Clause 10.4 (logical errors) and 10.6 (AP IDs) need that state and are left to the caller.
//!
//! ```
//! use onwai_ngap::{decode_pdu, encode_pdu, types::*};
//!
//! let request = NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(NgSetupRequest::new(
//!     GlobalRanNodeId::GlobalGnbId(GlobalGnbId::new(
//!         PlmnIdentity(vec![0x00, 0xf1, 0x10]),
//!         GnbId::GnbId(ngap_aper::BitString::new(vec![0, 0, 0x40], 22).unwrap()),
//!     )),
//!     SupportedTaList(vec![SupportedTaItem::new(
//!         Tac(vec![0, 0, 1]),
//!         BroadcastPlmnList(vec![BroadcastPlmnItem::new(
//!             PlmnIdentity(vec![0x00, 0xf1, 0x10]),
//!             SliceSupportList(vec![SliceSupportItem::new(SNssai::new(Sst(vec![1])))]),
//!         )]),
//!     )]),
//!     PagingDrx::V64,
//! )));
//! let bytes = encode_pdu(&request).unwrap();
//! let decoded = decode_pdu(&bytes).unwrap();
//! assert_eq!(decoded.pdu, request);
//! assert!(decoded.issues.is_empty());
//! ```

mod decode;
mod diagnostics;
mod encode;
mod info;

pub use decode::{DecodeOptions, Decoded, decode_pdu, decode_pdu_with};
pub use diagnostics::{
    AbstractSyntaxError, Construction, DecodeError, IeIssue, Reaction, UnknownProcedure,
};
pub use encode::encode_pdu;
pub use info::{Context, MessageType, PduInfo};
pub use ngap_aper::{AperError, Contained, ErrorKind, ie::Criticality};
pub use ngap_types as types;
pub use ngap_types::NgapPdu;
