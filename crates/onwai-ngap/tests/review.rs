//! Checks added by a review of the repository against the specification and against real data:
//! * the N2 SM containers of the captured PDU Session Resource Setup (nested APER, encoded by another implementation);
//! * `PrivateMessage` (no sampled vectors exist for it);
//! * a mandatory IE with criticality "ignore" that is missing is tolerated (clause 10.3.5), one with "reject" is not.

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
/// `DefaultPagingDRX` (id 21) of the NG Setup Request is `Ignore, Mandatory`: it decodes with the field `None`.
#[test]
fn a_missing_mandatory_ie_with_criticality_ignore_is_tolerated() {
    let all = capture();
    let without = without_ie(&all[0], 21);

    let decoded = decode_pdu(&without).expect("clause 10.3.5: ignore the missing IE and continue");
    assert!(
        decoded.issues.is_empty(),
        "\"Ignore\" is tolerated silently"
    );
    assert!(!decoded.needs_report());
    let NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(r)) = &decoded.pdu else {
        panic!("not an NG Setup Request")
    };
    assert_eq!(r.default_paging_drx, None);
    assert!(r.ran_node_name.is_some(), "the other IEs are kept");

    // the absent IE stays absent on the wire: decode -> encode reproduces the received octets
    assert_eq!(encode_pdu(&decoded.pdu).unwrap(), without);
}

/// A mandatory IE with criticality "Reject" that is missing still rejects the procedure.
#[test]
fn a_missing_mandatory_ie_with_criticality_reject_still_rejects() {
    let all = capture();
    let without = without_ie(&all[0], 27); // GlobalRANNodeID: Reject, Mandatory
    let Err(DecodeError::AbstractSyntax(a)) = decode_pdu(&without) else {
        panic!("expected an abstract syntax error")
    };
    assert_eq!(a.issues.len(), 1);
    assert_eq!(a.issues[0].ie_id, 27);
    assert_eq!(a.issues[0].criticality, Criticality::Reject);
    assert_eq!(
        DecodeError::AbstractSyntax(a).reaction(),
        Reaction::UnsuccessfulOutcome
    );
}

/// The PDU `bytes` rebuilt without the IE `id`.
fn without_ie(bytes: &[u8], id: u32) -> Vec<u8> {
    let mut r = ngap_aper::BitReader::new(bytes);
    let alt = r.read_index(3, true).unwrap();
    let (code, crit, content) = ngap_aper::ie::read_procedure(&mut r).unwrap();
    let mut c = ngap_aper::BitReader::new(&content);
    c.read_bit().unwrap();
    let ies: Vec<RawIe> = read_container(&mut c, Size::range(0, 65535)).unwrap();
    assert!(ies.iter().any(|ie| ie.id == id), "the PDU has IE {id}");
    let kept: Vec<RawIe> = ies.into_iter().filter(|ie| ie.id != id).collect();

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
    w.into_complete_bytes()
}
