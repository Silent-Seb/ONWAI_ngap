//! Clause 10 of TS 38.413 as data: what went wrong, and what the standard asks the receiver to do about it.

use core::fmt;

use ngap_aper::{AperError, ie::Criticality};
use ngap_types::{
    Cause, CauseProtocol, CriticalityDiagnostics, CriticalityDiagnosticsIeItem,
    CriticalityDiagnosticsIeList, ErrorIndication, ID_ERROR_INDICATION, ProcedureCode,
    ProtocolIeId, TypeOfError, UnsuccessfulOutcome,
};

use crate::info::{Context, MessageType};

/// One IE that was not understood or is missing: an entry of the Criticality Diagnostics IE (clause 9.3.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeIssue {
    pub ie_id: u32,
    /// The criticality of the IE: as received for an IE not understood, as the specification defines it for a
    /// missing one.
    pub criticality: Criticality,
    pub type_of_error: TypeOfError,
}

impl IeIssue {
    pub(crate) fn item(&self) -> Option<CriticalityDiagnosticsIeItem> {
        Some(CriticalityDiagnosticsIeItem::new(
            self.criticality,
            ProtocolIeId(u16::try_from(self.ie_id).ok()?),
            self.type_of_error,
        ))
    }
}

/// What clause 10.3.6 calls IEs "in wrong order or with too many occurrences".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Construction {
    /// Known IEs are not in the order of the specification (only IEs this version defines are considered).
    WrongOrder { ie_id: u32 },
    /// An IE that may occur once occurs more than once.
    TooManyOccurrences { ie_id: u32 },
}

/// An abstract syntax error (clause 10.3) in a message whose procedure is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractSyntaxError {
    pub context: Context,
    /// IEs not understood (10.3.4.2) or missing (10.3.5) that have to be reported. Not understood IEs with
    /// "Ignore" criticality are not listed: they need no report.
    pub issues: Vec<IeIssue>,
    /// Set for the errors of clause 10.3.6; these reject the procedure whatever the criticalities.
    pub construction: Option<Construction>,
}

/// A procedure code (10.3.4.1) this version of the specification does not define.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownProcedure {
    pub message_type: MessageType,
    pub procedure_code: u16,
    /// The criticality the sender put on the procedure.
    pub criticality: Criticality,
}

/// What the receiver has to do, according to clause 10. The codec does none of it; this is the instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// Drop the message, report nothing.
    Ignore,
    /// Initiate the Error Indication procedure ([`DecodeError::error_indication`] builds the message).
    ErrorIndication,
    /// Reject the procedure with the message the procedure uses for an unsuccessful outcome (e.g. NG Setup
    /// Failure), carrying [`DecodeError::cause`] and [`DecodeError::criticality_diagnostics`].
    UnsuccessfulOutcome,
    /// The faulty message is a response or an Error Indication (10.3.4.2, 10.5): nothing is sent; the procedure
    /// is considered unsuccessfully terminated and the node's local error handling takes over.
    LocalErrorHandling,
}

/// Why [`decode_pdu`](crate::decode_pdu) did not produce a PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Clause 10.2 (and 10.3.4.1A, a message type that cannot be read): the octets are not valid APER for the
    /// ASN.1. `context` is set when the envelope (message type and procedure) could still be read.
    TransferSyntax {
        error: AperError,
        context: Option<Context>,
    },
    /// Clause 10.3.4.1.
    UnknownProcedure(UnknownProcedure),
    /// Clauses 10.3.4.2, 10.3.5 and 10.3.6.
    AbstractSyntax(AbstractSyntaxError),
}

impl DecodeError {
    /// The envelope of the faulty PDU, if it could be read.
    pub fn context(&self) -> Option<Context> {
        match self {
            DecodeError::TransferSyntax { context, .. } => *context,
            DecodeError::UnknownProcedure(u) => Some(Context {
                message_type: u.message_type,
                procedure_code: u.procedure_code,
                procedure_criticality: u.criticality,
            }),
            DecodeError::AbstractSyntax(a) => Some(a.context),
        }
    }

    /// What clause 10 asks the receiver to do.
    pub fn reaction(&self) -> Reaction {
        let in_error_indication = self
            .context()
            .is_some_and(|c| c.procedure_code == u16::from(ID_ERROR_INDICATION));
        match self {
            // 10.5: an error in an Error Indication message never triggers another one
            _ if in_error_indication => Reaction::LocalErrorHandling,
            DecodeError::TransferSyntax { .. } => Reaction::ErrorIndication,
            DecodeError::UnknownProcedure(u) => match u.criticality {
                Criticality::Ignore => Reaction::Ignore,
                Criticality::Reject | Criticality::Notify => Reaction::ErrorIndication,
            },
            DecodeError::AbstractSyntax(a) => match a.context.message_type {
                MessageType::Initiating
                    if UnsuccessfulOutcome::PROCEDURE_CODES.contains(&a.context.procedure_code) =>
                {
                    Reaction::UnsuccessfulOutcome
                }
                MessageType::Initiating => Reaction::ErrorIndication,
                MessageType::Successful | MessageType::Unsuccessful => Reaction::LocalErrorHandling,
            },
        }
    }

    /// The cause value for the Error Indication or failure message.
    pub fn cause(&self) -> Cause {
        Cause::Protocol(match self {
            DecodeError::TransferSyntax { .. } => CauseProtocol::TransferSyntaxError,
            DecodeError::UnknownProcedure(u) => match u.criticality {
                Criticality::Reject => CauseProtocol::AbstractSyntaxErrorReject,
                Criticality::Notify | Criticality::Ignore => {
                    CauseProtocol::AbstractSyntaxErrorIgnoreAndNotify
                }
            },
            DecodeError::AbstractSyntax(a) => {
                if a.construction.is_some() {
                    CauseProtocol::AbstractSyntaxErrorFalselyConstructedMessage
                } else if a
                    .issues
                    .iter()
                    .any(|i| i.criticality == Criticality::Reject)
                {
                    CauseProtocol::AbstractSyntaxErrorReject
                } else {
                    CauseProtocol::AbstractSyntaxErrorIgnoreAndNotify
                }
            }
        })
    }

    /// The Criticality Diagnostics IE: procedure code, triggering message, procedure criticality (when the
    /// envelope was readable) and one entry per IE issue. `None` if there is nothing to say.
    pub fn criticality_diagnostics(&self) -> Option<CriticalityDiagnostics> {
        let context = self.context()?;
        let issues = match self {
            DecodeError::AbstractSyntax(a) => a.issues.as_slice(),
            _ => &[],
        };
        Some(diagnostics(context, issues))
    }

    /// The Error Indication message to send for this error (with [`Reaction::ErrorIndication`]), or `None` when
    /// clause 10 asks for no such message. The AP IDs are left for the caller to fill in.
    pub fn error_indication(&self) -> Option<ErrorIndication> {
        match self.reaction() {
            Reaction::Ignore | Reaction::LocalErrorHandling => None,
            Reaction::ErrorIndication | Reaction::UnsuccessfulOutcome => {
                let mut m = ErrorIndication::new();
                m.cause = Some(self.cause());
                m.criticality_diagnostics = self.criticality_diagnostics();
                Some(m)
            }
        }
    }
}

/// A Criticality Diagnostics IE for `context` listing `issues`.
pub(crate) fn diagnostics(context: Context, issues: &[IeIssue]) -> CriticalityDiagnostics {
    let mut d = CriticalityDiagnostics::new();
    d.procedure_code = u8::try_from(context.procedure_code).ok().map(ProcedureCode);
    d.triggering_message = Some(context.message_type.triggering_message());
    d.procedure_criticality = Some(context.procedure_criticality);
    let items: Vec<_> = issues.iter().filter_map(IeIssue::item).collect();
    if !items.is_empty() {
        d.ies_criticality_diagnostics = Some(CriticalityDiagnosticsIeList(items));
    }
    d
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TransferSyntax { error, .. } => {
                write!(f, "transfer syntax error: {error}")
            }
            DecodeError::UnknownProcedure(u) => write!(
                f,
                "procedure code {} is not comprehended (criticality {:?})",
                u.procedure_code, u.criticality
            ),
            DecodeError::AbstractSyntax(a) => {
                write!(
                    f,
                    "abstract syntax error in procedure {}",
                    a.context.procedure_code
                )?;
                match a.construction {
                    Some(Construction::WrongOrder { ie_id }) => {
                        write!(f, ": IE {ie_id} is out of order")?
                    }
                    Some(Construction::TooManyOccurrences { ie_id }) => {
                        write!(f, ": IE {ie_id} occurs more than once")?
                    }
                    None => {}
                }
                for i in &a.issues {
                    write!(
                        f,
                        ": IE {} {} (criticality {:?})",
                        i.ie_id,
                        match i.type_of_error {
                            TypeOfError::Missing => "is missing",
                            _ => "is not comprehended",
                        },
                        i.criticality
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecodeError::TransferSyntax { error, .. } => Some(error),
            _ => None,
        }
    }
}
