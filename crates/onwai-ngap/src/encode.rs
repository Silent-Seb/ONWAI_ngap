use ngap_aper::AperError;
use ngap_types::NgapPdu;

/// The complete APER encoding of `pdu`: the payload of an SCTP message on N2.
///
/// Fails only if a value violates a constraint of the ASN.1 (e.g. a list that is too long); see
/// [`AperError::kind`].
pub fn encode_pdu(pdu: &NgapPdu) -> Result<Vec<u8>, AperError> {
    ngap_aper::to_vec(pdu)
}
