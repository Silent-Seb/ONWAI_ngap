//! Checks added by a review of the repository against the specification and against real data:
//! * the N2 SM containers of the captured PDU Session Resource Setup (nested APER, encoded by another implementation);
//! * `PrivateMessage` (no sampled vectors exist for it);
//! * what happens when a mandatory IE with criticality "ignore" is missing (clause 10.3.5).

use ngap_aper::{
    BitWriter, Size,
    ie::{RawIe, read_container, write_container, write_procedure},
};
use onwai_ngap::{Criticality, DecodeError, Reaction, decode_pdu, encode_pdu, types::*};

fn capture() -> Vec<Vec<u8>> {
    include_str!("captures/attach.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(" | "))
        .map(|(_, hex)| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

#[test]
fn the_captured_n2_sm_containers_decode_and_re_encode_to_the_same_octets() {
    let all = capture();

    let NgapPdu::InitiatingMessage(InitiatingMessage::PduSessionResourceSetupRequest(request)) =
        decode_pdu(&all[12]).unwrap().pdu
    else {
        panic!("frame 95 is a PDU Session Resource Setup Request")
    };
    assert!(!request.pdu_session_resource_setup_list_su_req.0.is_empty());
    for item in &request.pdu_session_resource_setup_list_su_req.0 {
        let container = &item.pdu_session_resource_setup_request_transfer;
        let transfer = container.decode().expect("the SMF's transfer decodes");
        let again = rt_encode(&transfer);
        assert_eq!(
            again,
            container.raw(),
            "request transfer re-encodes identically"
        );
    }

    let NgapPdu::SuccessfulOutcome(SuccessfulOutcome::PduSessionResourceSetupResponse(response)) =
        decode_pdu(&all[13]).unwrap().pdu
    else {
        panic!("frame 97 is a PDU Session Resource Setup Response")
    };
    let list = response
        .pdu_session_resource_setup_list_su_res
        .expect("one session was set up");
    assert!(!list.0.is_empty());
    for item in &list.0 {
        let container = &item.pdu_session_resource_setup_response_transfer;
        let transfer = container.decode().expect("the gNB's transfer decodes");
        assert_eq!(rt_encode(&transfer), container.raw());
    }
}

fn rt_encode<T: ngap_aper::AperEncode>(value: &T) -> Vec<u8> {
    ngap_aper::to_vec(value).expect("encodes")
}

#[test]
fn a_private_message_with_local_and_global_ids_round_trips() {
    let message = PrivateMessage {
        private_ies: vec![
            PrivateIe {
                id: PrivateIeId::Local(7),
                criticality: Criticality::Ignore,
                content: vec![0x01, 0x02],
            },
            PrivateIe {
                id: PrivateIeId::Global(
                    ngap_aper::ObjectIdentifier::new(vec![1, 3, 6, 1, 4, 1, 99999]).unwrap(),
                ),
                criticality: Criticality::Reject,
                content: vec![0xff],
            },
        ],
    };
    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage::PrivateMessage(message));
    let wire = encode_pdu(&pdu).expect("a private message encodes");
    let decoded = decode_pdu(&wire).expect("and decodes: it is a defined procedure");
    assert_eq!(decoded.pdu, pdu);
    assert_eq!(encode_pdu(&decoded.pdu).unwrap(), wire);
}

/// 10.3.5: a message that misses an IE with criticality "Ignore" is processed with the other IEs.
/// `DefaultPagingDRX` (id 21) of the NG Setup Request is `Ignore, Mandatory`.
///
/// KNOWN GAP (see CLAUDE.md, "Deferred work", item 3): the typed message cannot hold an absent mandatory IE, so the
/// facade returns an abstract syntax error whatever the criticality, and `reaction()` then asks for an NG Setup Failure.
/// 125 of the 350 mandatory IEs are `Ignore` (both UE NGAP IDs among them). Run with `--ignored` to see it fail.
#[test]
#[ignore = "known deviation from clause 10.3.5: a missing mandatory IE is always an error"]
fn a_missing_mandatory_ie_with_criticality_ignore_must_not_reject_the_message() {
    let all = capture();
    let bytes = &all[0];
    // rebuild the NG Setup Request without IE 21
    let mut r = ngap_aper::BitReader::new(bytes);
    let alt = r.read_index(3, true).unwrap();
    let (code, crit, content) = ngap_aper::ie::read_procedure(&mut r).unwrap();
    let mut c = ngap_aper::BitReader::new(&content);
    c.read_bit().unwrap();
    let ies: Vec<RawIe> = read_container(&mut c, Size::range(0, 65535)).unwrap();
    let kept: Vec<RawIe> = ies.into_iter().filter(|ie| ie.id != 21).collect();

    struct Message<'a>(&'a [RawIe]);
    impl ngap_aper::AperEncode for Message<'_> {
        fn aper_encode(&self, w: &mut BitWriter) -> ngap_aper::Result<()> {
            w.write_bit(false);
            write_container(w, Size::range(0, 65535), self.0)
        }
    }
    let mut w = BitWriter::new();
    w.write_index(alt, 3, true).unwrap();
    write_procedure(&mut w, code, crit, &Message(&kept)).unwrap();
    let without = w.into_complete_bytes();

    match decode_pdu(&without) {
        Ok(_) => {} // what the specification asks for
        Err(DecodeError::AbstractSyntax(a)) => {
            // the codec cannot represent the absent IE; at the very least it must not tell the caller to reject
            // the procedure on account of an IE whose criticality is "Ignore"
            let missing_is_ignore = a
                .issues
                .iter()
                .all(|i| i.criticality == Criticality::Ignore);
            assert!(missing_is_ignore, "unexpected issues {:?}", a.issues);
            let e = DecodeError::AbstractSyntax(a);
            assert_ne!(
                e.reaction(),
                Reaction::UnsuccessfulOutcome,
                "rejects an NG Setup Request over a missing IE that clause 10.3.5 says to ignore"
            );
        }
        Err(other) => panic!("unexpected error {other:?}"),
    }
}
