use ngap_aper::{
    AperError, BitReader, ErrorKind, from_slice,
    ie::{Criticality, RawIe, read_procedure, record_unknown_ies},
};
use ngap_types::{
    CriticalityDiagnostics, InitiatingMessage, NgapPdu, SuccessfulOutcome, TypeOfError,
    UnsuccessfulOutcome,
};

use crate::diagnostics::{
    AbstractSyntaxError, Construction, DecodeError, IeIssue, UnknownProcedure, diagnostics,
};
use crate::info::{Context, MessageType};

/// Knobs of [`decode_pdu_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeOptions {
    /// Treat known IEs that are not in the order of the specification as an abstract syntax error (10.3.6). The
    /// default is `true`, as the standard requires; switch it off to be liberal towards a sloppy peer.
    pub enforce_ie_order: bool,
}

impl DecodeOptions {
    /// Set [`DecodeOptions::enforce_ie_order`].
    pub fn enforce_ie_order(mut self, on: bool) -> Self {
        self.enforce_ie_order = on;
        self
    }
}

impl Default for DecodeOptions {
    fn default() -> Self {
        DecodeOptions {
            enforce_ie_order: true,
        }
    }
}

/// A PDU that decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub pdu: NgapPdu,
    pub context: Context,
    /// IEs that were not understood and are tolerated (10.3.4.2): those with criticality "Ignore" need nothing,
    /// those with "Notify" have to be reported to the sender ([`Decoded::criticality_diagnostics`]).
    pub issues: Vec<IeIssue>,
}

impl Decoded {
    /// `true` if clause 10.3.4.2 asks to tell the sender that an IE was ignored ("Ignore and Notify Sender").
    pub fn needs_report(&self) -> bool {
        self.issues
            .iter()
            .any(|i| i.criticality == Criticality::Notify)
    }

    /// The Criticality Diagnostics IE for the IEs that have to be reported, if there are any.
    pub fn criticality_diagnostics(&self) -> Option<CriticalityDiagnostics> {
        let reported: Vec<IeIssue> = self
            .issues
            .iter()
            .filter(|i| i.criticality == Criticality::Notify)
            .copied()
            .collect();
        (!reported.is_empty()).then(|| diagnostics(self.context, &reported))
    }
}

/// Decode the octets of one NGAP message with the default [`DecodeOptions`].
pub fn decode_pdu(bytes: &[u8]) -> Result<Decoded, DecodeError> {
    decode_pdu_with(bytes, &DecodeOptions::default())
}

/// Decode the octets of one NGAP message.
///
/// Reports the errors of clause 10 that are detectable from the message alone:
/// * 10.2 transfer syntax errors,
/// * 10.3.4.1 a procedure code that is not defined,
/// * 10.3.4.2 IEs that are not defined, at any depth: those of the message, of its list items and of extension
///   containers (they also stay in the `unknown_ies` / `ie_extensions` of the value they came from),
/// * 10.3.5 a missing mandatory IE (at any depth; the first one found is reported, and the typed message cannot
///   represent an absent mandatory IE, so this is an error whatever its criticality),
/// * 10.3.6 IEs in the wrong order (top level of the message) or occurring too often (at any depth).
///
/// Not detectable here: conditional IEs that are erroneously present, logical errors (10.4), AP ID handling.
pub fn decode_pdu_with(bytes: &[u8], options: &DecodeOptions) -> Result<Decoded, DecodeError> {
    let (context, content) = match peek(bytes) {
        Ok(v) => v,
        Err(error) => {
            return Err(DecodeError::TransferSyntax {
                error,
                context: None,
            });
        }
    };
    // the decoders note every IE they do not know, at any depth: those of the message and of its list items and
    // extension containers
    let (decoded, not_known) = record_unknown_ies(|| from_slice::<NgapPdu>(bytes));
    let pdu = match decoded {
        Ok(pdu) => pdu,
        Err(error) => return Err(classify(error, context)),
    };

    let mut rejected = Vec::new();
    let mut tolerated = Vec::new();
    for ie in &not_known {
        let issue = not_understood(ie);
        match ie.criticality {
            Criticality::Reject => rejected.push(issue),
            Criticality::Notify | Criticality::Ignore => tolerated.push(issue),
        }
    }
    let construction = if options.enforce_ie_order {
        first_out_of_order(&pdu, context, &content).map(|ie_id| Construction::WrongOrder { ie_id })
    } else {
        None
    };
    if !rejected.is_empty() || construction.is_some() {
        // the IEs to report: the rejected ones and those to be notified
        let mut issues = rejected;
        issues.extend(
            tolerated
                .into_iter()
                .filter(|i| i.criticality == Criticality::Notify),
        );
        return Err(DecodeError::AbstractSyntax(AbstractSyntaxError {
            context,
            issues,
            construction,
        }));
    }
    Ok(Decoded {
        pdu,
        context,
        issues: tolerated,
    })
}

fn not_understood(ie: &RawIe) -> IeIssue {
    IeIssue {
        ie_id: ie.id,
        criticality: ie.criticality,
        type_of_error: TypeOfError::NotUnderstood,
    }
}

/// Read the envelope: the alternative of `NGAP-PDU`, the procedure code and criticality, the open type with the
/// message.
fn peek(bytes: &[u8]) -> Result<(Context, Vec<u8>), AperError> {
    let mut r = BitReader::new(bytes);
    let message_type = match r.read_index(3, true)? {
        0 => MessageType::Initiating,
        1 => MessageType::Successful,
        2 => MessageType::Unsuccessful,
        i => return Err(r.error(ErrorKind::InvalidIndex(i))),
    };
    let (procedure_code, procedure_criticality, content) = read_procedure(&mut r)?;
    Ok((
        Context {
            message_type,
            procedure_code,
            procedure_criticality,
        },
        content,
    ))
}

/// Map a failure of the typed decoder to clause 10.
fn classify(error: AperError, context: Context) -> DecodeError {
    match error.kind {
        ErrorKind::UnknownProcedure { code, criticality } => {
            DecodeError::UnknownProcedure(UnknownProcedure {
                message_type: context.message_type,
                procedure_code: code,
                criticality,
            })
        }
        ErrorKind::MissingIe { id, criticality } => {
            DecodeError::AbstractSyntax(AbstractSyntaxError {
                context,
                issues: vec![IeIssue {
                    ie_id: id,
                    criticality,
                    type_of_error: TypeOfError::Missing,
                }],
                construction: None,
            })
        }
        ErrorKind::DuplicateIe { id } => DecodeError::AbstractSyntax(AbstractSyntaxError {
            context,
            issues: Vec::new(),
            construction: Some(Construction::TooManyOccurrences { ie_id: id }),
        }),
        _ => DecodeError::TransferSyntax {
            error,
            context: Some(context),
        },
    }
}

/// The first known IE that comes after one that the specification puts later; only IEs this version defines count
/// (10.3.6, last paragraph).
fn first_out_of_order(pdu: &NgapPdu, context: Context, content: &[u8]) -> Option<u32> {
    let known = pdu.ie_ids();
    let wire = match context.message_type {
        MessageType::Initiating => InitiatingMessage::wire_ie_ids(context.procedure_code, content),
        MessageType::Successful => SuccessfulOutcome::wire_ie_ids(context.procedure_code, content),
        MessageType::Unsuccessful => {
            UnsuccessfulOutcome::wire_ie_ids(context.procedure_code, content)
        }
    }?
    .ok()?;
    let mut last = None;
    for id in wire {
        if let Some(pos) = known.iter().position(|&k| k == id) {
            if last.is_some_and(|l| pos < l) {
                return Some(id);
            }
            last = Some(pos);
        }
    }
    None
}

impl Context {
    /// `true` if the PDU is a response (successful or unsuccessful outcome) rather than a procedure start.
    pub fn is_response(&self) -> bool {
        self.message_type.is_response()
    }
}
