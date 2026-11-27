//! Clause 10 behaviour of `decode_pdu`, on PDUs built by hand so that every defect is under control.

use ngap_aper::{
    BitString, BitWriter, Size,
    ie::{RawIe, read_container, write_container, write_procedure},
};
use onwai_ngap::{
    Construction, Criticality, DecodeError, DecodeOptions, MessageType, Reaction, decode_pdu,
    decode_pdu_with, encode_pdu, types::*,
};

const NG_SETUP: u16 = 21;
const ERROR_INDICATION: u16 = 9;

/// A valid NG Setup Request and its IEs as they are on the wire (ids 27, 82, 21, ...).
fn setup_request() -> (NgapPdu, Vec<RawIe>) {
    let request = NgSetupRequest::new(
        GlobalRanNodeId::GlobalGnbId(GlobalGnbId::new(
            PlmnIdentity(vec![0x00, 0xf1, 0x10]),
            GnbId::GnbId(BitString::new(vec![0, 0, 0x40], 22).unwrap()),
        )),
        SupportedTaList(vec![SupportedTaItem::new(
            Tac(vec![0, 0, 1]),
            BroadcastPlmnList(vec![BroadcastPlmnItem::new(
                PlmnIdentity(vec![0x00, 0xf1, 0x10]),
                SliceSupportList(vec![SliceSupportItem::new(SNssai::new(Sst(vec![1])))]),
            )]),
        )]),
        PagingDrx::V64,
    );
    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(request));
    let bytes = encode_pdu(&pdu).unwrap();
    // skip: PDU choice (3 bits incl. extension), procedure wrapper; then the message
    let (_, content) = envelope(&bytes);
    (pdu, ies_of(&content))
}

/// The IEs of an encoded message.
fn ies_of(content: &[u8]) -> Vec<RawIe> {
    let mut r = ngap_aper::BitReader::new(content);
    r.read_bit().unwrap(); // the message's extension marker
    read_container(&mut r, Size::range(0, 65535)).unwrap()
}

fn envelope(bytes: &[u8]) -> (u64, Vec<u8>) {
    let mut r = ngap_aper::BitReader::new(bytes);
    let alt = r.read_index(3, true).unwrap();
    let (_, _, content) = ngap_aper::ie::read_procedure(&mut r).unwrap();
    (alt, content)
}

/// `NGAP-PDU` with the given alternative and procedure, holding a message made of exactly `ies`.
fn pdu_bytes(alternative: u64, code: u16, criticality: Criticality, ies: &[RawIe]) -> Vec<u8> {
    struct Message<'a>(&'a [RawIe]);
    impl ngap_aper::AperEncode for Message<'_> {
        fn aper_encode(&self, w: &mut BitWriter) -> ngap_aper::Result<()> {
            w.write_bit(false);
            write_container(w, Size::range(0, 65535), self.0)
        }
    }
    let mut w = BitWriter::new();
    w.write_index(alternative, 3, true).unwrap();
    write_procedure(&mut w, code, criticality, &Message(ies)).unwrap();
    w.into_complete_bytes()
}

fn setup_with(ies: &[RawIe]) -> Vec<u8> {
    pdu_bytes(0, NG_SETUP, Criticality::Reject, ies)
}

fn unknown(id: u32, criticality: Criticality) -> RawIe {
    RawIe {
        id,
        criticality,
        content: vec![0x00],
    }
}

fn abstract_error(e: DecodeError) -> onwai_ngap::AbstractSyntaxError {
    match e {
        DecodeError::AbstractSyntax(a) => a,
        other => panic!("expected an abstract syntax error, got {other:?}"),
    }
}

#[test]
fn a_valid_pdu_decodes_without_issues() {
    let (pdu, ies) = setup_request();
    let decoded = decode_pdu(&setup_with(&ies)).unwrap();
    assert_eq!(decoded.pdu, pdu);
    assert!(decoded.issues.is_empty());
    assert!(!decoded.needs_report());
    assert_eq!(decoded.criticality_diagnostics(), None);
    assert_eq!(decoded.context.message_type, MessageType::Initiating);
    assert_eq!(decoded.context.procedure_code, NG_SETUP);
}

#[test]
fn unknown_ie_ignore_is_tolerated_silently() {
    let (_, mut ies) = setup_request();
    ies.push(unknown(60000, Criticality::Ignore));
    let decoded = decode_pdu(&setup_with(&ies)).unwrap();
    assert!(!decoded.needs_report());
    assert_eq!(decoded.issues.len(), 1);
    assert_eq!(decoded.issues[0].ie_id, 60000);
    assert_eq!(decoded.criticality_diagnostics(), None);
}

#[test]
fn unknown_ie_notify_is_tolerated_and_must_be_reported() {
    let (_, mut ies) = setup_request();
    ies.push(unknown(60001, Criticality::Notify));
    let decoded = decode_pdu(&setup_with(&ies)).unwrap();
    assert!(decoded.needs_report());
    let d = decoded.criticality_diagnostics().unwrap();
    assert_eq!(d.procedure_code, Some(ProcedureCode(21)));
    assert_eq!(
        d.triggering_message,
        Some(TriggeringMessage::InitiatingMessage)
    );
    let items = d.ies_criticality_diagnostics.unwrap().0;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].ie_id, ProtocolIeId(60001));
    assert_eq!(items[0].type_of_error, TypeOfError::NotUnderstood);
    assert_eq!(items[0].ie_criticality, Criticality::Notify);
}

#[test]
fn unknown_ie_reject_rejects_the_procedure_with_its_failure_message() {
    let (_, mut ies) = setup_request();
    ies.push(unknown(60002, Criticality::Reject));
    ies.push(unknown(60003, Criticality::Notify));
    ies.push(unknown(60004, Criticality::Ignore));
    let e = decode_pdu(&setup_with(&ies)).unwrap_err();
    assert_eq!(e.reaction(), Reaction::UnsuccessfulOutcome); // NG Setup has NG Setup Failure
    assert_eq!(
        e.cause(),
        Cause::Protocol(CauseProtocol::AbstractSyntaxErrorReject)
    );
    let a = abstract_error(e);
    // the rejected and the notify IE are reported, the ignore IE is not
    let ids: Vec<u32> = a.issues.iter().map(|i| i.ie_id).collect();
    assert_eq!(ids, [60002, 60003]);
    assert_eq!(a.construction, None);
}

#[test]
fn a_reject_ie_in_a_procedure_without_failure_message_uses_error_indication() {
    // Downlink NAS Transport (code 4) is class 2: no failure message
    let message = NgapPdu::InitiatingMessage(InitiatingMessage::DownlinkNasTransport(
        DownlinkNasTransport::new(AmfUeNgapId(1), RanUeNgapId(2), NasPdu(vec![0x7e, 0, 0x42])),
    ));
    let (_, content) = envelope(&encode_pdu(&message).unwrap());
    let mut ies = ies_of(&content);
    ies.push(unknown(60000, Criticality::Reject));
    let bytes = pdu_bytes(0, 4, Criticality::Ignore, &ies);
    // without the extra IE it is the message we built
    assert_eq!(
        decode_pdu(&pdu_bytes(0, 4, Criticality::Ignore, &ies[..3]))
            .unwrap()
            .pdu,
        message
    );

    let e = decode_pdu(&bytes).unwrap_err();
    assert!(matches!(e, DecodeError::AbstractSyntax(_)));
    assert_eq!(e.reaction(), Reaction::ErrorIndication);
    let ei = e.error_indication().unwrap();
    assert_eq!(
        ei.cause,
        Some(Cause::Protocol(CauseProtocol::AbstractSyntaxErrorReject))
    );
    let d = ei.criticality_diagnostics.unwrap();
    assert_eq!(d.procedure_code, Some(ProcedureCode(4)));
    assert_eq!(d.procedure_criticality, Some(Criticality::Ignore));
    assert_eq!(
        d.ies_criticality_diagnostics.unwrap().0[0].ie_id,
        ProtocolIeId(60000)
    );
}

#[test]
fn a_missing_mandatory_ie_is_reported_with_its_criticality() {
    let (_, ies) = setup_request();
    let without: Vec<RawIe> = ies.into_iter().filter(|ie| ie.id != 27).collect(); // GlobalRANNodeID
    let e = decode_pdu(&setup_with(&without)).unwrap_err();
    assert_eq!(e.reaction(), Reaction::UnsuccessfulOutcome);
    let a = abstract_error(e.clone());
    assert_eq!(a.issues.len(), 1);
    assert_eq!(a.issues[0].ie_id, 27);
    assert_eq!(a.issues[0].criticality, Criticality::Reject);
    assert_eq!(a.issues[0].type_of_error, TypeOfError::Missing);
    let d = e.criticality_diagnostics().unwrap();
    let items = d.ies_criticality_diagnostics.unwrap().0;
    assert_eq!(items[0].type_of_error, TypeOfError::Missing);
}

#[test]
fn ies_in_the_wrong_order_are_a_falsely_constructed_message() {
    let (_, mut ies) = setup_request();
    ies.reverse();
    let e = decode_pdu(&setup_with(&ies)).unwrap_err();
    assert_eq!(
        e.cause(),
        Cause::Protocol(CauseProtocol::AbstractSyntaxErrorFalselyConstructedMessage)
    );
    assert_eq!(e.reaction(), Reaction::UnsuccessfulOutcome);
    let a = abstract_error(e);
    assert!(matches!(
        a.construction,
        Some(Construction::WrongOrder { .. })
    ));
    // a liberal receiver accepts it
    let lenient = DecodeOptions::default().enforce_ie_order(false);
    assert!(decode_pdu_with(&setup_with(&ies), &lenient).is_ok());
}

#[test]
fn unknown_ies_do_not_count_for_the_order() {
    let (_, mut ies) = setup_request();
    ies.insert(0, unknown(60000, Criticality::Ignore));
    ies.insert(2, unknown(60001, Criticality::Ignore));
    assert!(decode_pdu(&setup_with(&ies)).is_ok());
}

#[test]
fn a_duplicate_ie_is_too_many_occurrences() {
    let (_, mut ies) = setup_request();
    ies.push(ies[0].clone());
    let e = decode_pdu(&setup_with(&ies)).unwrap_err();
    let a = abstract_error(e);
    assert_eq!(
        a.construction,
        Some(Construction::TooManyOccurrences { ie_id: 27 })
    );
}

#[test]
fn an_unknown_procedure_follows_its_criticality() {
    for (crit, reaction, cause) in [
        (
            Criticality::Reject,
            Reaction::ErrorIndication,
            CauseProtocol::AbstractSyntaxErrorReject,
        ),
        (
            Criticality::Notify,
            Reaction::ErrorIndication,
            CauseProtocol::AbstractSyntaxErrorIgnoreAndNotify,
        ),
        (
            Criticality::Ignore,
            Reaction::Ignore,
            CauseProtocol::AbstractSyntaxErrorIgnoreAndNotify,
        ),
    ] {
        let e = decode_pdu(&pdu_bytes(0, 200, crit, &[])).unwrap_err();
        let DecodeError::UnknownProcedure(u) = &e else {
            panic!("{e:?}")
        };
        assert_eq!((u.procedure_code, u.criticality), (200, crit));
        assert_eq!(e.reaction(), reaction);
        assert_eq!(e.cause(), Cause::Protocol(cause));
        if reaction == Reaction::Ignore {
            assert_eq!(e.error_indication(), None);
        } else {
            let d = e
                .error_indication()
                .unwrap()
                .criticality_diagnostics
                .unwrap();
            assert_eq!(d.procedure_code, Some(ProcedureCode(200)));
            assert_eq!(d.procedure_criticality, Some(crit));
            assert_eq!(
                d.triggering_message,
                Some(TriggeringMessage::InitiatingMessage)
            );
            assert_eq!(d.ies_criticality_diagnostics, None);
        }
    }
}

#[test]
fn a_procedure_code_that_exists_only_as_initiating_is_unknown_as_response() {
    // NG Setup (21) as a *successful outcome* is fine, but a class 2 procedure (Downlink NAS Transport, 4) has none
    let e = decode_pdu(&pdu_bytes(1, 4, Criticality::Ignore, &[])).unwrap_err();
    assert!(matches!(e, DecodeError::UnknownProcedure(_)));
}

#[test]
fn transfer_syntax_errors() {
    let (_, ies) = setup_request();
    let good = setup_with(&ies);
    // truncated at every length
    for n in 0..good.len() {
        let e = decode_pdu(&good[..n]).unwrap_err();
        assert!(
            matches!(e, DecodeError::TransferSyntax { .. }),
            "prefix {n}: {e:?}"
        );
        assert_eq!(e.reaction(), Reaction::ErrorIndication);
        assert_eq!(
            e.cause(),
            Cause::Protocol(CauseProtocol::TransferSyntaxError)
        );
    }
    // once the envelope is readable, the error says which procedure it was
    let e = decode_pdu(&good[..good.len() - 1]).unwrap_err();
    assert!(e.context().is_none() || e.context().unwrap().procedure_code == NG_SETUP);
    // trailing octets
    let mut longer = good.clone();
    longer.extend_from_slice(&[0, 0]);
    assert!(matches!(
        decode_pdu(&longer).unwrap_err(),
        DecodeError::TransferSyntax { .. }
    ));
    // a PDU type that does not exist
    let e = decode_pdu(&[0xe0, 0x00]).unwrap_err();
    assert!(matches!(
        e,
        DecodeError::TransferSyntax { context: None, .. }
    ));
}

#[test]
fn errors_in_an_error_indication_never_trigger_another() {
    let e = decode_pdu(&pdu_bytes(
        0,
        ERROR_INDICATION,
        Criticality::Ignore,
        &[unknown(60000, Criticality::Reject)],
    ))
    .unwrap_err();
    assert_eq!(e.reaction(), Reaction::LocalErrorHandling);
    assert_eq!(e.error_indication(), None);
    // an IE whose value cannot be decoded, inside an envelope that can be read
    let broken = RawIe {
        id: 15, // Cause
        criticality: Criticality::Ignore,
        content: vec![],
    };
    let e = decode_pdu(&pdu_bytes(
        0,
        ERROR_INDICATION,
        Criticality::Ignore,
        &[broken],
    ))
    .unwrap_err();
    assert!(
        matches!(
            e,
            DecodeError::TransferSyntax {
                context: Some(_),
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(e.reaction(), Reaction::LocalErrorHandling);
}

#[test]
fn errors_in_a_response_go_to_local_error_handling() {
    // NG Setup Response (successful outcome) without its mandatory IEs
    let e = decode_pdu(&pdu_bytes(1, NG_SETUP, Criticality::Reject, &[])).unwrap_err();
    assert!(matches!(e, DecodeError::AbstractSyntax(_)));
    assert_eq!(e.reaction(), Reaction::LocalErrorHandling);
    assert_eq!(e.error_indication(), None);
}

#[test]
fn the_error_indication_built_from_an_error_round_trips() {
    let (_, mut ies) = setup_request();
    ies.push(unknown(60002, Criticality::Reject));
    let e = decode_pdu(&setup_with(&ies)).unwrap_err();
    let ei = e.error_indication().unwrap();
    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage::ErrorIndication(ei));
    let bytes = encode_pdu(&pdu).unwrap();
    let back = decode_pdu(&bytes).unwrap();
    assert_eq!(back.pdu, pdu);
    assert_eq!(back.context.procedure_code, ERROR_INDICATION);
}

#[test]
fn display_names_the_problem() {
    let (_, mut ies) = setup_request();
    ies.push(unknown(60002, Criticality::Reject));
    let text = decode_pdu(&setup_with(&ies)).unwrap_err().to_string();
    assert!(text.contains("60002"), "{text}");
    assert!(text.contains("not comprehended"), "{text}");
}

/// The NG Setup Request with `ies` as the extension IEs of its Global RAN Node ID (a nested container).
fn setup_with_nested(ies: Vec<RawIe>) -> Vec<u8> {
    let (mut pdu, _) = setup_request();
    let NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(m)) = &mut pdu else {
        unreachable!()
    };
    let GlobalRanNodeId::GlobalGnbId(g) = &mut m.global_ran_node_id else {
        unreachable!()
    };
    g.ie_extensions = Some(ngap_aper::ie::UnknownIes { ies });
    encode_pdu(&pdu).unwrap()
}

#[test]
fn a_nested_unknown_reject_ie_rejects_the_procedure() {
    let bytes = setup_with_nested(vec![unknown(60001, Criticality::Reject)]);
    let a = abstract_error(decode_pdu(&bytes).unwrap_err());
    assert_eq!(a.context.procedure_code, NG_SETUP);
    assert_eq!(a.issues.len(), 1);
    assert_eq!(a.issues[0].ie_id, 60001);
    assert_eq!(a.issues[0].criticality, Criticality::Reject);
}

#[test]
fn a_nested_unknown_ignore_ie_is_tolerated_and_listed() {
    let bytes = setup_with_nested(vec![unknown(60002, Criticality::Ignore)]);
    let decoded = decode_pdu(&bytes).unwrap();
    assert_eq!(decoded.issues.len(), 1);
    assert_eq!(decoded.issues[0].ie_id, 60002);
    assert!(!decoded.needs_report());
}

#[test]
fn a_nested_unknown_notify_ie_must_be_reported() {
    let bytes = setup_with_nested(vec![unknown(60003, Criticality::Notify)]);
    let decoded = decode_pdu(&bytes).unwrap();
    assert!(decoded.needs_report());
    let d = decoded.criticality_diagnostics().unwrap();
    assert_eq!(d.ies_criticality_diagnostics.unwrap().0.len(), 1);
}

#[test]
fn top_level_and_nested_unknown_ies_are_both_found_and_repeats_are_listed_once() {
    let (_, mut ies) = setup_request();
    ies.push(unknown(60000, Criticality::Notify));
    // the nested container sits inside the Global RAN Node ID IE: build the PDU from the typed value instead
    let bytes = setup_with_nested(vec![
        unknown(60004, Criticality::Notify),
        unknown(60004, Criticality::Notify),
    ]);
    let decoded = decode_pdu(&bytes).unwrap();
    assert_eq!(decoded.issues.len(), 2, "both occurrences are found");
    let d = decoded.criticality_diagnostics().unwrap();
    assert_eq!(
        d.ies_criticality_diagnostics.unwrap().0.len(),
        1,
        "but the sender is told once"
    );
    // a top-level one next to it
    let again = decode_pdu(&setup_with(&ies)).unwrap();
    assert_eq!(again.issues.len(), 1);
}
