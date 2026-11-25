//! What identifies a PDU: the message type and the procedure.

use ngap_aper::ie::Criticality;
use ngap_types::{NgapPdu, TriggeringMessage};

/// The `NGAP-PDU` alternative: the "Type of Message" of clause 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    Initiating,
    Successful,
    Unsuccessful,
}

impl MessageType {
    /// The `TriggeringMessage` value of the Criticality Diagnostics IE.
    pub fn triggering_message(self) -> TriggeringMessage {
        match self {
            MessageType::Initiating => TriggeringMessage::InitiatingMessage,
            MessageType::Successful => TriggeringMessage::SuccessfulOutcome,
            MessageType::Unsuccessful => TriggeringMessage::UnsuccessfulOutcome,
        }
    }

    /// Initiating messages start a procedure; the other two are responses.
    pub fn is_response(self) -> bool {
        self != MessageType::Initiating
    }
}

/// The envelope of a PDU as received: which message, of which procedure, with which procedure criticality.
///
/// Known even when the body cannot be decoded, because it is read first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub message_type: MessageType,
    pub procedure_code: u16,
    /// The criticality the sender put on the procedure.
    pub procedure_criticality: Criticality,
}

/// Facts about a decoded [`NgapPdu`].
pub trait PduInfo {
    fn message_type(&self) -> MessageType;
    fn procedure_code(&self) -> u16;
    /// The procedure criticality the specification defines for this message.
    fn procedure_criticality(&self) -> Criticality;
    /// The ASN.1 name of the message type, e.g. `NGSetupRequest`.
    fn message_name(&self) -> &'static str;
    /// The IEs of the message that this version of the specification does not define, as received.
    fn unknown_ies(&self) -> &[ngap_aper::ie::RawIe];
}

impl PduInfo for NgapPdu {
    fn message_type(&self) -> MessageType {
        match self {
            NgapPdu::InitiatingMessage(_) => MessageType::Initiating,
            NgapPdu::SuccessfulOutcome(_) => MessageType::Successful,
            // `NgapPdu` is `#[non_exhaustive]` (the CHOICE is extensible), but a PDU with another alternative cannot
            // be decoded: the third alternative is the last one that exists.
            _ => MessageType::Unsuccessful,
        }
    }

    fn procedure_code(&self) -> u16 {
        NgapPdu::procedure_code(self)
    }

    fn procedure_criticality(&self) -> Criticality {
        NgapPdu::criticality(self)
    }

    fn message_name(&self) -> &'static str {
        NgapPdu::message_name(self)
    }

    fn unknown_ies(&self) -> &[ngap_aper::ie::RawIe] {
        NgapPdu::unknown_ies(self)
    }
}
