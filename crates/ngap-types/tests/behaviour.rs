//! Behaviour of the generated codec beyond the golden vectors: unknown and misplaced IEs, missing and duplicate
//! IEs, unknown procedures, typed extension members, value checks and robustness against bad input.

use ngap_aper::ie::{self, RawIe};
use ngap_aper::{
    AperDecode, AperEncode, BitReader, BitString, BitWriter, ErrorKind, Size, from_slice, to_vec,
};
use ngap_types::*;

fn plmn() -> PlmnIdentity {
    PlmnIdentity(vec![0x00, 0xf1, 0x10])
}

fn setup_failure() -> NgSetupFailure {
    let mut m = NgSetupFailure::new(Cause::Misc(CauseMisc::Unspecified));
    m.time_to_wait = Some(TimeToWait::V10s);
    m
}

fn pdu_of(m: NgSetupFailure) -> NgapPdu {
    NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome::NgSetupFailure(m))
}

/// A PDU `unsuccessfulOutcome` / procedure 21 around a message whose IEs are exactly `ies` (in that order).
fn failure_pdu_with(ies: &[RawIe]) -> Vec<u8> {
    let mut msg = BitWriter::new();
    msg.write_bit(false); // the message SEQUENCE's extension marker
    ie::write_container(&mut msg, Size::range(0, 65535), ies).unwrap();
    let mut w = BitWriter::new();
    w.write_index(2, 3, true).unwrap(); // NGAP-PDU: unsuccessfulOutcome
    w.write_constrained_int(21, 0, 255).unwrap(); // procedure code
    ie::Criticality::Reject.aper_encode(&mut w).unwrap();
    w.write_open_type(&msg.into_complete_bytes()).unwrap();
    w.into_complete_bytes()
}

fn ie_cause() -> RawIe {
    RawIe::new(
        15,
        ie::Criticality::Ignore,
        &Cause::Misc(CauseMisc::Unspecified),
    )
    .unwrap()
}

fn ie_wait() -> RawIe {
    RawIe::new(107, ie::Criticality::Ignore, &TimeToWait::V10s).unwrap()
}

#[test]
fn unknown_ies_are_kept_and_survive_a_round_trip() {
    let mut m = setup_failure();
    m.unknown_ies.push(RawIe {
        id: 4242,
        criticality: ie::Criticality::Notify,
        content: vec![0xAB, 0xCD],
    });
    let bytes = to_vec(&pdu_of(m.clone())).unwrap();
    let NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome::NgSetupFailure(back)) =
        from_slice::<NgapPdu>(&bytes).unwrap()
    else {
        panic!()
    };
    assert_eq!(back, m);
    assert_eq!(back.unknown_ies[0].id, 4242);
    assert_eq!(back.unknown_ies[0].criticality, ie::Criticality::Notify);
}

#[test]
fn ies_may_arrive_in_any_order() {
    let in_spec_order = to_vec(&pdu_of(setup_failure())).unwrap();
    let reversed = failure_pdu_with(&[ie_wait(), ie_cause()]);
    assert_eq!(
        from_slice::<NgapPdu>(&reversed).unwrap(),
        from_slice::<NgapPdu>(&in_spec_order).unwrap()
    );
    // ... and the encoder always writes the spec order
    assert_ne!(reversed, in_spec_order);
    let NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome::NgSetupFailure(m)) =
        from_slice::<NgapPdu>(&reversed).unwrap()
    else {
        panic!()
    };
    assert_eq!(to_vec(&pdu_of(m)).unwrap(), in_spec_order);
}

#[test]
fn a_missing_mandatory_ie_reports_its_id_and_criticality() {
    let e = from_slice::<NgapPdu>(&failure_pdu_with(&[ie_wait()])).unwrap_err();
    assert_eq!(
        e.kind,
        ErrorKind::MissingIe {
            id: 15,
            criticality: ie::Criticality::Ignore
        }
    );
    let e = from_slice::<NgapPdu>(&failure_pdu_with(&[])).unwrap_err();
    assert_eq!(
        e.kind,
        ErrorKind::MissingIe {
            id: 15,
            criticality: ie::Criticality::Ignore
        }
    );
}

#[test]
fn a_repeated_ie_is_an_error() {
    let e = from_slice::<NgapPdu>(&failure_pdu_with(&[ie_cause(), ie_cause()])).unwrap_err();
    assert_eq!(e.kind, ErrorKind::DuplicateIe { id: 15 });
}

#[test]
fn an_ie_with_a_bad_value_is_a_decode_error() {
    // IE 15 (Cause) holding a CHOICE index that does not exist, and IE 107 holding a 3-bit field with trailing octets
    let bad_cause = RawIe {
        id: 15,
        criticality: ie::Criticality::Ignore,
        content: vec![0xE0],
    };
    assert!(from_slice::<NgapPdu>(&failure_pdu_with(&[bad_cause])).is_err());
    let trailing = RawIe {
        id: 15,
        criticality: ie::Criticality::Ignore,
        content: [
            to_vec(&Cause::Misc(CauseMisc::Unspecified)).unwrap(),
            vec![0],
        ]
        .concat(),
    };
    assert_eq!(
        from_slice::<NgapPdu>(&failure_pdu_with(&[trailing]))
            .unwrap_err()
            .kind,
        ErrorKind::TrailingData
    );
}

#[test]
fn an_unknown_procedure_code_reports_code_and_criticality() {
    let mut w = BitWriter::new();
    w.write_index(0, 3, true).unwrap(); // initiatingMessage
    ie::write_procedure(&mut w, 250, ie::Criticality::Notify, &setup_failure()).unwrap();
    let e = from_slice::<NgapPdu>(&w.into_complete_bytes()).unwrap_err();
    assert_eq!(
        e.kind,
        ErrorKind::UnknownProcedure {
            code: 250,
            criticality: ie::Criticality::Notify
        }
    );
    // a procedure that exists, but with the wrong direction: NG Setup has no initiating `NgSetupFailure`
    let mut w = BitWriter::new();
    w.write_index(0, 3, true).unwrap();
    ie::write_procedure(&mut w, 21, ie::Criticality::Reject, &setup_failure()).unwrap();
    assert!(
        from_slice::<NgapPdu>(&w.into_complete_bytes()).is_err(),
        "NgSetupFailure is not an initiating message"
    );
}

#[test]
fn an_unknown_choice_index_of_the_pdu_is_an_error() {
    let mut w = BitWriter::new();
    w.write_index(3, 3, true).unwrap(); // first extension alternative of NGAP-PDU
    w.write_open_type(&[0]).unwrap();
    assert_eq!(
        from_slice::<NgapPdu>(&w.into_complete_bytes())
            .unwrap_err()
            .kind,
        ErrorKind::InvalidIndex(3)
    );
}

#[test]
fn typed_extension_members_round_trip_next_to_unknown_ones() {
    let mut item = SupportedTaItem::new(Tac(vec![0, 0, 1]), BroadcastPlmnList(vec![]));
    item.broadcast_plmn_list = BroadcastPlmnList(vec![BroadcastPlmnItem::new(
        plmn(),
        SliceSupportList(vec![SliceSupportItem::new(SNssai::new(Sst(vec![1])))]),
    )]);
    let ext = SupportedTaItemExtIes {
        configured_tac_indication: Some(ConfiguredTacIndication::True),
        unknown_ies: vec![RawIe {
            id: 60000,
            criticality: ie::Criticality::Ignore,
            content: vec![1],
        }],
        ..SupportedTaItemExtIes::default()
    };
    item.ie_extensions = Some(ext);
    let bytes = to_vec(&item).unwrap();
    let back = from_slice::<SupportedTaItem>(&bytes).unwrap();
    assert_eq!(back, item);
    let ext = back.ie_extensions.unwrap();
    assert_eq!(
        ext.configured_tac_indication,
        Some(ConfiguredTacIndication::True)
    );
    assert_eq!(ext.unknown_ies.len(), 1);
}

#[test]
fn an_empty_extension_container_cannot_be_encoded() {
    // the container has SIZE(1..65535): `Some` of nothing is not a valid value
    let mut item = SupportedTaItem::new(
        Tac(vec![0, 0, 1]),
        BroadcastPlmnList(vec![BroadcastPlmnItem::new(
            plmn(),
            SliceSupportList(vec![SliceSupportItem::new(SNssai::new(Sst(vec![1])))]),
        )]),
    );
    item.ie_extensions = Some(SupportedTaItemExtIes::default());
    assert_eq!(to_vec(&item).unwrap_err().kind, ErrorKind::SizeOutOfRange);
}

#[test]
fn a_single_ie_field_keeps_unknown_alternatives() {
    // `choice-Extensions` of GlobalRANNodeID: ProtocolIE-SingleContainer with typed rows and an Unknown fallback
    let unknown = GlobalRanNodeId::ChoiceExtensions(GlobalRanNodeIdExtIes::Unknown(RawIe {
        id: 31000,
        criticality: ie::Criticality::Reject,
        content: vec![9, 9],
    }));
    let bytes = to_vec(&unknown).unwrap();
    assert_eq!(from_slice::<GlobalRanNodeId>(&bytes).unwrap(), unknown);
}

#[test]
fn values_outside_the_defined_range_are_rejected_on_encode() {
    // AMF-UE-NGAP-ID is INTEGER (0..1099511627775): 40 bits
    assert_eq!(
        to_vec(&AmfUeNgapId(1 << 40)).unwrap_err().kind,
        ErrorKind::ValueOutOfRange
    );
    assert!(to_vec(&AmfUeNgapId((1 << 40) - 1)).is_ok());
    // RANNodeName is PrintableString (SIZE(1..150, ...)): the printable alphabet is enforced. (The SIZE constraint is
    // extensible, so lengths outside 1..150 use the extension form instead of being rejected.)
    assert_eq!(
        to_vec(&RanNodeName("a_b".into())).unwrap_err().kind,
        ErrorKind::InvalidCharacter
    );
    // fixed-size strings must have exactly their size
    assert_eq!(
        to_vec(&PlmnIdentity(vec![0, 1])).unwrap_err().kind,
        ErrorKind::SizeOutOfRange
    );
    assert_eq!(
        to_vec(&AmfSetId(BitString::new(vec![0, 0], 16).unwrap()))
            .unwrap_err()
            .kind,
        ErrorKind::SizeOutOfRange
    );
}

#[test]
fn an_unknown_enumeration_extension_is_an_error() {
    // CauseRadioNetwork has extension additions; index 200 of the extension range is not defined
    let mut w = BitWriter::new();
    w.write_index(66 + 200, 66, true)
        .unwrap_or_else(|e| panic!("{e}"));
    let bytes = w.into_complete_bytes();
    let e = CauseRadioNetwork::aper_decode(&mut BitReader::new(&bytes)).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::InvalidIndex(_)), "{e}");
}

#[test]
fn trailing_octets_after_a_pdu_are_an_error() {
    let mut bytes = to_vec(&pdu_of(setup_failure())).unwrap();
    bytes.push(0);
    assert_eq!(
        from_slice::<NgapPdu>(&bytes).unwrap_err().kind,
        ErrorKind::TrailingData
    );
}

#[test]
fn no_prefix_of_a_valid_pdu_makes_the_decoder_panic() {
    for line in include_str!("vectors.txt").lines() {
        let (name, hex) = line.split_once(" | ").unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        for cut in 0..bytes.len() {
            let r = from_slice::<NgapPdu>(&bytes[..cut]);
            assert!(
                r.is_err(),
                "{name}: the prefix of {cut}/{} octets decoded",
                bytes.len()
            );
        }
        // single-bit corruption must give an error or a value, never a panic
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut b = bytes.clone();
                b[i] ^= 1 << bit;
                let _ = from_slice::<NgapPdu>(&b);
            }
        }
    }
}
